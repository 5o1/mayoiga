package app

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"time"
)

func dialRelay(local profile, relay discoveredNode, targetNode, service string) (net.Conn, error) {
	return dialSignedRelay(local, relay, "service", targetNode, service, "")
}

func dialReverseRelay(local profile, relay discoveredNode, requestID, service string) (net.Conn, error) {
	return dialSignedRelay(local, relay, "reverse", local.Node.ID, service, requestID)
}

func dialSignedRelay(local profile, relay discoveredNode, mode, targetNode, service, requestID string) (net.Conn, error) {
	if relay.Relay == nil || local.Coordinator.Credential == nil {
		return nil, errors.New("relay or node credential is unavailable")
	}
	config, err := pinnedTLSConfig(relay.Relay.PinnedSHA256)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", relay.Relay.Endpoint, config)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		connection.Close()
		return nil, err
	}
	handshake := relayHandshake{
		Version: relayHandshakeVersion, Mode: mode, Network: local.VirtualNetwork, SourceNode: local.Node.ID,
		RelayNode: relay.ID, TargetNode: targetNode, Service: service, RequestID: requestID,
		Timestamp: time.Now().Unix(), Nonce: nonce,
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(local.Coordinator.Credential.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		connection.Close()
		return nil, errors.New("invalid local node credential")
	}
	handshake.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(privateKey), relayHandshakeMessage(handshake)))
	body, _ := json.Marshal(handshake)
	if _, err := connection.Write(append(body, '\n')); err != nil {
		connection.Close()
		return nil, err
	}
	_ = connection.SetReadDeadline(time.Now().Add(relayDialTimeout))
	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	if err != nil || response != "OK\n" {
		connection.Close()
		if err == nil {
			err = relayResponseError(response)
		}
		return nil, err
	}
	_ = connection.SetReadDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func dialCoordinatorViaRelay(ctx context.Context, network, nodeID string, subnode subnodeConfig) (net.Conn, error) {
	config, err := pinnedTLSConfig(subnode.RelayPinnedSHA256)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", subnode.RelayEndpoint, config)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	body, _ := json.Marshal(relayHandshake{
		Version: relayHandshakeVersion, Mode: "coordinator", Network: network, SourceNode: nodeID,
		RelayNode: subnode.RelayNodeID, RelayToken: subnode.RelayToken,
	})
	if _, err := connection.Write(append(body, '\n')); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	if err != nil || response != "OK\n" {
		connection.Close()
		if err == nil {
			err = relayResponseError(response)
		}
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, nil
}
