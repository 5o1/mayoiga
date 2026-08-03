package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func requestConnectionCLI(profilePath string, options options) error {
	if options.targetNode == "" || options.service == "" {
		return errors.New("--target-node and --service are required")
	}
	p, err := loadProfile(profilePath)
	if err != nil {
		return err
	}
	idempotency := strings.TrimSpace(options.idempotencyKey)
	if idempotency == "" {
		idempotency, err = randomToken()
		if err != nil {
			return err
		}
	}
	connection, err := createConnectionRequest(
		context.Background(), p, options.targetNode, options.service, "", idempotency,
	)
	if err != nil {
		return err
	}
	fmt.Printf("REQUEST_ID=%s\nIDEMPOTENCY_KEY=%s\nSTATE=%s\nEXPIRES=%s\n",
		connection.ID, idempotency, connection.State, connection.ExpiresAt.Format(time.RFC3339))
	return nil
}

func createConnectionRequest(ctx context.Context, p profile, targetNode, service, returnRelay, idempotency string) (connectionRequest, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/connections/request", createConnectionInput{
		IdempotencyKey: idempotency, TargetNode: targetNode, Service: service, ReturnRelay: returnRelay,
	})
	if err != nil {
		return connectionRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return connectionRequest{}, coordinatorResponseError(response)
	}
	var connection connectionRequest
	return connection, json.NewDecoder(response.Body).Decode(&connection)
}

func decideConnectionRequest(ctx context.Context, p profile, requestID, decision, reason string) (connectionRequest, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/connections/"+decision, connectionIDInput{
		RequestID: requestID, Reason: reason,
	})
	if err != nil {
		return connectionRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return connectionRequest{}, coordinatorResponseError(response)
	}
	var connection connectionRequest
	return connection, json.NewDecoder(response.Body).Decode(&connection)
}

func connectionStatusCLI(profilePath, requestID string, wait bool) error {
	if requestID == "" {
		return errors.New("--request-id is required")
	}
	p, err := loadProfile(profilePath)
	if err != nil {
		return err
	}
	connection, err := getConnectionStatus(context.Background(), p, requestID, "", false)
	if err != nil {
		return err
	}
	for wait && !connectionTerminal(connection.State) {
		connection, err = getConnectionStatus(context.Background(), p, requestID, connection.State, true)
		if err != nil {
			return err
		}
	}
	printConnection(connection)
	return nil
}

func getConnectionStatus(ctx context.Context, p profile, requestID, knownState string, wait bool) (connectionRequest, error) {
	endpoint := "/v1/connections/status"
	if wait {
		endpoint += "/wait"
	}
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, endpoint, connectionStatusWaitInput{
		RequestID: requestID, KnownState: knownState, WaitSeconds: int(connectionWaitMaximum / time.Second),
	})
	if err != nil {
		return connectionRequest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return connectionRequest{}, coordinatorResponseError(response)
	}
	var connection connectionRequest
	return connection, json.NewDecoder(response.Body).Decode(&connection)
}

func decideConnectionCLI(profilePath, requestID, decision, reason string) error {
	if requestID == "" {
		return errors.New("--request-id is required")
	}
	p, err := loadProfile(profilePath)
	if err != nil {
		return err
	}
	connection, err := decideConnectionRequest(context.Background(), p, requestID, decision, reason)
	if err != nil {
		return err
	}
	if connection.TargetNode == p.Node.ID {
		_ = removeInboxRequest(profilePath, requestID)
	}
	printConnection(connection)
	return nil
}

func printConnectionInbox(profilePath string) error {
	inbox, err := loadInbox(profilePath)
	if err != nil {
		return err
	}
	if len(inbox.Events) == 0 {
		fmt.Println("no pending connection requests")
		return nil
	}
	fmt.Println("REQUEST_ID\tSOURCE\tSERVICE\tSTATE\tEXPIRES")
	for _, connection := range inbox.Events {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", connection.ID, connection.SourceNode, connection.Service,
			connection.State, connection.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func removeInboxRequest(profilePath, requestID string) error {
	inboxFileMu.Lock()
	defer inboxFileMu.Unlock()
	inbox, err := loadInbox(profilePath)
	if err != nil {
		return err
	}
	filtered := inbox.Events[:0]
	for _, connection := range inbox.Events {
		if connection.ID != requestID {
			filtered = append(filtered, connection)
		}
	}
	inbox.Events = filtered
	body, err := json.MarshalIndent(inbox, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(profilePath), "connection-inbox.json")
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(body, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func printConnection(connection connectionRequest) {
	fmt.Printf("REQUEST_ID=%s\nSOURCE=%s\nTARGET=%s\nSERVICE=%s\nSTATE=%s\nSTATUS_CODE=%d\nREASON=%s\nEXPIRES=%s\n",
		connection.ID, connection.SourceNode, connection.TargetNode, connection.Service,
		connection.State, connection.StatusCode, connection.Reason, connection.ExpiresAt.Format(time.RFC3339))
}
