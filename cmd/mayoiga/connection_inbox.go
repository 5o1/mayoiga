package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type cachedInbox struct {
	Cursor uint64              `json:"cursor"`
	Events []connectionRequest `json:"events"`
}

var inboxFileMu sync.Mutex

func saveInbox(profilePath string, inbox cachedInbox) error {
	inboxFileMu.Lock()
	defer inboxFileMu.Unlock()
	path := filepath.Join(filepath.Dir(profilePath), "connection-inbox.json")
	existing, _ := loadInbox(profilePath)
	byID := make(map[string]connectionRequest)
	for _, event := range existing.Events {
		if !connectionTerminal(event.State) {
			byID[event.ID] = event
		}
	}
	for _, event := range inbox.Events {
		byID[event.ID] = event
	}
	inbox.Events = inbox.Events[:0]
	for _, event := range byID {
		inbox.Events = append(inbox.Events, event)
	}
	sort.Slice(inbox.Events, func(i, j int) bool { return inbox.Events[i].Cursor < inbox.Events[j].Cursor })
	if existing.Cursor > inbox.Cursor {
		inbox.Cursor = existing.Cursor
	}
	body, err := json.MarshalIndent(inbox, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(body, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadInbox(profilePath string) (cachedInbox, error) {
	path := filepath.Join(filepath.Dir(profilePath), "connection-inbox.json")
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cachedInbox{}, nil
	}
	var inbox cachedInbox
	if err != nil {
		return inbox, err
	}
	return inbox, json.Unmarshal(body, &inbox)
}

func signedCoordinatorRequest(ctx context.Context, p profile, method, endpoint string, input any) (*http.Response, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, p.Coordinator.URL+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if p.Coordinator.Credential == nil {
		return nil, errors.New("node has no approved coordinator credential")
	}
	if err := signRequest(request, body, p.Node.ID, p.Coordinator.Credential.PrivateKey); err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	client, err := coordinatorNodeHTTPClient(p)
	if err != nil {
		return nil, err
	}
	if strings.Contains(endpoint, "/wait") {
		client.Timeout = connectionWaitMaximum + 10*time.Second
	}
	return client.Do(request)
}

func waitInbox(ctx context.Context, path string, p profile) (inboxWaitResponse, error) {
	inbox, err := loadInbox(path)
	if err != nil {
		return inboxWaitResponse{}, err
	}
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/connections/inbox/wait", inboxWaitInput{
		AfterCursor: inbox.Cursor, WaitSeconds: int(connectionWaitMaximum / time.Second), MaxEvents: maxInboxEvents,
	})
	if err != nil {
		return inboxWaitResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return inboxWaitResponse{}, coordinatorResponseError(response)
	}
	var output inboxWaitResponse
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		return output, err
	}
	if len(output.Events) > 0 {
		if err := saveInbox(path, cachedInbox{Cursor: output.Cursor, Events: output.Events}); err != nil {
			return output, err
		}
		ack, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/connections/inbox/ack", inboxAckInput{Cursor: output.Cursor})
		if err != nil {
			return output, err
		}
		if ack.StatusCode != http.StatusOK {
			err := coordinatorResponseError(ack)
			ack.Body.Close()
			return output, err
		}
		ack.Body.Close()
	} else if err := saveInbox(path, cachedInbox{Cursor: output.Cursor}); err != nil {
		return output, err
	}
	return output, nil
}
