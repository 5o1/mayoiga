package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	connectionRequestLifetime = 2 * time.Minute
	connectionOfferLease      = 15 * time.Second
	connectionWaitMaximum     = 25 * time.Second
	maxConnectionRequests     = 10000
	maxConnectionsPerTarget   = 128
	maxInboxEvents            = 32
	maxConnectionReason       = 512
)

type connectionRequest struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	SourceNode     string    `json:"source_node"`
	TargetNode     string    `json:"target_node"`
	Service        string    `json:"service"`
	ReturnRelay    string    `json:"return_relay,omitempty"`
	State          string    `json:"state"`
	StatusCode     int       `json:"status_code"`
	Reason         string    `json:"reason,omitempty"`
	Cursor         uint64    `json:"cursor"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	OfferLeaseEnds time.Time `json:"offer_lease_ends,omitempty"`
}

type createConnectionInput struct {
	IdempotencyKey string `json:"idempotency_key"`
	TargetNode     string `json:"target_node"`
	Service        string `json:"service"`
	ReturnRelay    string `json:"return_relay,omitempty"`
}

type connectionIDInput struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason,omitempty"`
}

type inboxWaitInput struct {
	AfterCursor uint64 `json:"after_cursor"`
	WaitSeconds int    `json:"wait_seconds"`
	MaxEvents   int    `json:"max_events"`
}

type inboxWaitResponse struct {
	Cursor uint64              `json:"cursor"`
	Events []connectionRequest `json:"events"`
}

type inboxAckInput struct {
	Cursor uint64 `json:"cursor"`
}

type connectionStatusWaitInput struct {
	RequestID   string `json:"request_id"`
	KnownState  string `json:"known_state"`
	WaitSeconds int    `json:"wait_seconds"`
}

func (r *registry) serveConnections(w http.ResponseWriter, req *http.Request) bool {
	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/request":
		r.createConnection(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/inbox/wait":
		r.waitConnectionInbox(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/inbox/ack":
		r.ackConnectionInbox(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/accept":
		r.decideConnection(w, req, "accepted", 200)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/reject":
		r.decideConnection(w, req, "rejected", 403)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/cancel":
		r.cancelConnection(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/status":
		r.connectionStatus(w, req, false)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/connections/status/wait":
		r.connectionStatus(w, req, true)
	default:
		return false
	}
	return true
}

func (r *registry) authenticatedConnectionBody(w http.ResponseWriter, req *http.Request) ([]byte, string, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return nil, "", false
	}
	nodeID := req.Header.Get("X-Mayoiga-Node")
	r.mu.Lock()
	authorized, exists := r.state.Authorized[nodeID]
	if !exists || !r.verifySignatureLocked(req, body, authorized.PublicKey) {
		r.mu.Unlock()
		http.Error(w, "invalid node signature", http.StatusUnauthorized)
		return nil, "", false
	}
	if !r.allowRequestLocked("connection-node:"+nodeID, publicRequestsPerMinute*5, time.Now().UTC()) {
		r.mu.Unlock()
		http.Error(w, "node rate limit exceeded", http.StatusTooManyRequests)
		return nil, "", false
	}
	r.mu.Unlock()
	return body, nodeID, true
}

func (r *registry) createConnection(w http.ResponseWriter, req *http.Request) {
	body, sourceNode, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input createConnectionInput
	if json.Unmarshal(body, &input) != nil || input.TargetNode == "" || input.Service == "" ||
		input.IdempotencyKey == "" || len(input.IdempotencyKey) > 128 {
		http.Error(w, "idempotency_key, target_node, and service are required", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	r.mu.Lock()
	if r.cleanupLocked(now) {
		if err := r.persistLocked(); err != nil {
			r.mu.Unlock()
			http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
			return
		}
	}
	idempotencyIndex := sourceNode + "\x00" + input.IdempotencyKey
	if existingID := r.state.ConnectionIdempotency[idempotencyIndex]; existingID != "" {
		existing, exists := r.state.Connections[existingID]
		r.mu.Unlock()
		if !exists {
			http.Error(w, "idempotency index is inconsistent", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, existing)
		return
	}
	source, sourceExists := r.state.Nodes[sourceNode]
	target, targetExists := r.state.Nodes[input.TargetNode]
	if !sourceExists || !targetExists || source.VirtualNetwork != target.VirtualNetwork {
		r.mu.Unlock()
		http.Error(w, "source or target node is not active", http.StatusNotFound)
		return
	}
	if input.ReturnRelay != "" {
		relay, relayExists := r.state.Nodes[input.ReturnRelay]
		if !relayExists || relay.Role != "relay" || relay.Relay == nil ||
			relay.VirtualNetwork != source.VirtualNetwork || relay.Segment != source.Segment {
			r.mu.Unlock()
			http.Error(w, "return relay is not active in the source segment", http.StatusBadRequest)
			return
		}
	}
	serviceExists := false
	for _, service := range target.Services {
		if service.Name == input.Service {
			serviceExists = true
			break
		}
	}
	if !serviceExists {
		r.mu.Unlock()
		http.Error(w, "target service is not published", http.StatusNotFound)
		return
	}
	if len(r.state.Connections) >= r.connectionMax {
		r.mu.Unlock()
		http.Error(w, "connection request capacity reached", http.StatusServiceUnavailable)
		return
	}
	targetPending := 0
	for _, connection := range r.state.Connections {
		if connection.TargetNode == input.TargetNode && !connectionTerminal(connection.State) {
			targetPending++
		}
	}
	if targetPending >= maxConnectionsPerTarget {
		r.mu.Unlock()
		http.Error(w, "target connection queue is full", http.StatusTooManyRequests)
		return
	}
	id, err := randomToken()
	if err != nil {
		r.mu.Unlock()
		http.Error(w, "secure random source unavailable", http.StatusInternalServerError)
		return
	}
	r.state.ConnectionCursors[input.TargetNode]++
	connection := connectionRequest{
		ID: id, IdempotencyKey: input.IdempotencyKey, SourceNode: sourceNode,
		TargetNode: input.TargetNode, Service: input.Service, ReturnRelay: input.ReturnRelay,
		State: "queued", StatusCode: 100,
		Cursor: r.state.ConnectionCursors[input.TargetNode], CreatedAt: now, UpdatedAt: now,
		ExpiresAt: now.Add(r.connectionTTL),
	}
	r.state.Connections[id] = connection
	r.state.ConnectionIdempotency[idempotencyIndex] = id
	r.appendAuditLocked(auditEvent{Action: "connection_requested", NodeID: sourceNode, RequestID: id})
	err = r.persistLocked()
	r.notifyTargetLocked(input.TargetNode)
	r.notifyRequestLocked(id)
	r.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist connection request", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, connection)
}

func (r *registry) waitConnectionInbox(w http.ResponseWriter, req *http.Request) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input inboxWaitInput
	if json.Unmarshal(body, &input) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	wait := r.boundedConnectionWait(input.WaitSeconds)
	maxEvents := input.MaxEvents
	if maxEvents <= 0 || maxEvents > maxInboxEvents {
		maxEvents = maxInboxEvents
	}
	r.mu.Lock()
	if r.inboxWaiters[nodeID] {
		r.mu.Unlock()
		http.Error(w, "an inbox wait is already active for this node", http.StatusConflict)
		return
	}
	r.inboxWaiters[nodeID] = true
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inboxWaiters, nodeID)
		r.mu.Unlock()
	}()
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		now := time.Now().UTC()
		r.mu.Lock()
		cleanupChanged := r.cleanupLocked(now)
		events := r.pendingEventsLocked(nodeID, input.AfterCursor, maxEvents)
		if len(events) > 0 {
			for i := range events {
				connection := events[i]
				connection.State, connection.StatusCode = "offered", 102
				connection.UpdatedAt, connection.OfferLeaseEnds = now, now.Add(r.connectionLease)
				r.state.Connections[connection.ID] = connection
				events[i] = connection
				r.notifyRequestLocked(connection.ID)
			}
			persistErr := r.persistLocked()
			cursor := events[len(events)-1].Cursor
			r.mu.Unlock()
			if persistErr != nil {
				http.Error(w, "failed to persist inbox delivery", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, inboxWaitResponse{Cursor: cursor, Events: events})
			return
		}
		signal := r.targetSignalLocked(nodeID)
		cursor := r.state.ConnectionCursors[nodeID]
		if cleanupChanged {
			if err := r.persistLocked(); err != nil {
				r.mu.Unlock()
				http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
				return
			}
		}
		r.mu.Unlock()
		select {
		case <-req.Context().Done():
			return
		case <-deadline.C:
			writeJSON(w, http.StatusOK, inboxWaitResponse{Cursor: cursor, Events: []connectionRequest{}})
			return
		case <-signal:
		}
	}
}

func (r *registry) pendingEventsLocked(nodeID string, after uint64, limit int) []connectionRequest {
	events := make([]connectionRequest, 0)
	for _, connection := range r.state.Connections {
		if connection.TargetNode == nodeID && connection.State == "queued" && connection.Cursor > after {
			events = append(events, connection)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Cursor < events[j].Cursor })
	if len(events) > limit {
		events = events[:limit]
	}
	return events
}

func (r *registry) ackConnectionInbox(w http.ResponseWriter, req *http.Request) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input inboxAckInput
	if json.Unmarshal(body, &input) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	if input.Cursor > r.state.ConnectionCursors[nodeID] {
		r.mu.Unlock()
		http.Error(w, "cursor is ahead of server state", http.StatusConflict)
		return
	}
	if input.Cursor > r.state.ConnectionAcks[nodeID] {
		r.state.ConnectionAcks[nodeID] = input.Cursor
		if err := r.persistLocked(); err != nil {
			r.mu.Unlock()
			http.Error(w, "failed to persist inbox acknowledgement", http.StatusInternalServerError)
			return
		}
	}
	acknowledged := r.state.ConnectionAcks[nodeID]
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"status": "acknowledged", "cursor": acknowledged})
}

func (r *registry) decideConnection(w http.ResponseWriter, req *http.Request, state string, statusCode int) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input connectionIDInput
	if json.Unmarshal(body, &input) != nil || input.RequestID == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(input.Reason)) > maxConnectionReason {
		http.Error(w, "connection reason is too long", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	r.mu.Lock()
	if r.cleanupLocked(now) {
		if err := r.persistLocked(); err != nil {
			r.mu.Unlock()
			http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
			return
		}
	}
	connection, exists := r.state.Connections[input.RequestID]
	if !exists {
		r.mu.Unlock()
		http.Error(w, "connection request not found", http.StatusNotFound)
		return
	}
	if connection.TargetNode != nodeID {
		r.mu.Unlock()
		http.Error(w, "only the target node can decide this request", http.StatusForbidden)
		return
	}
	if connection.State == state {
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, connection)
		return
	}
	if connectionTerminal(connection.State) || (connection.State != "queued" && connection.State != "offered") {
		r.mu.Unlock()
		http.Error(w, "connection request cannot be decided in its current state", http.StatusConflict)
		return
	}
	connection.State, connection.StatusCode, connection.Reason = state, statusCode, strings.TrimSpace(input.Reason)
	connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
	r.state.Connections[connection.ID] = connection
	r.appendAuditLocked(auditEvent{Action: "connection_" + state, NodeID: nodeID, RequestID: connection.ID})
	err := r.persistLocked()
	r.notifyRequestLocked(connection.ID)
	r.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist connection decision", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, connection)
}

func (r *registry) cancelConnection(w http.ResponseWriter, req *http.Request) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input connectionIDInput
	if json.Unmarshal(body, &input) != nil || input.RequestID == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(input.Reason)) > maxConnectionReason {
		http.Error(w, "connection reason is too long", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	r.mu.Lock()
	if r.cleanupLocked(now) {
		if err := r.persistLocked(); err != nil {
			r.mu.Unlock()
			http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
			return
		}
	}
	connection, exists := r.state.Connections[input.RequestID]
	if !exists {
		r.mu.Unlock()
		http.Error(w, "connection request not found", http.StatusNotFound)
		return
	}
	if connection.SourceNode != nodeID {
		r.mu.Unlock()
		http.Error(w, "only the source node can cancel this request", http.StatusForbidden)
		return
	}
	if connection.State == "canceled" {
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, connection)
		return
	}
	if connectionTerminal(connection.State) {
		r.mu.Unlock()
		http.Error(w, "connection request is already terminal", http.StatusConflict)
		return
	}
	connection.State, connection.StatusCode, connection.Reason = "canceled", 499, strings.TrimSpace(input.Reason)
	connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
	r.state.Connections[connection.ID] = connection
	r.appendAuditLocked(auditEvent{Action: "connection_canceled", NodeID: nodeID, RequestID: connection.ID})
	err := r.persistLocked()
	r.notifyTargetLocked(connection.TargetNode)
	r.notifyRequestLocked(connection.ID)
	r.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist cancellation", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, connection)
}

func (r *registry) connectionStatus(w http.ResponseWriter, req *http.Request, wait bool) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input connectionStatusWaitInput
	if json.Unmarshal(body, &input) != nil || input.RequestID == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}
	timer := time.NewTimer(r.boundedConnectionWait(input.WaitSeconds))
	defer timer.Stop()
	for {
		r.mu.Lock()
		cleanupChanged := r.cleanupLocked(time.Now().UTC())
		connection, exists := r.state.Connections[input.RequestID]
		if !exists {
			r.mu.Unlock()
			http.Error(w, "connection request not found", http.StatusNotFound)
			return
		}
		if connection.SourceNode != nodeID && connection.TargetNode != nodeID {
			r.mu.Unlock()
			http.Error(w, "connection request is not visible to this node", http.StatusForbidden)
			return
		}
		if !wait || connection.State != input.KnownState || connectionTerminal(connection.State) {
			if cleanupChanged {
				if err := r.persistLocked(); err != nil {
					r.mu.Unlock()
					http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
					return
				}
			}
			r.mu.Unlock()
			writeJSON(w, http.StatusOK, connection)
			return
		}
		signal := r.requestSignalLocked(connection.ID)
		if cleanupChanged {
			if err := r.persistLocked(); err != nil {
				r.mu.Unlock()
				http.Error(w, "failed to persist connection state", http.StatusInternalServerError)
				return
			}
		}
		r.mu.Unlock()
		select {
		case <-req.Context().Done():
			return
		case <-timer.C:
			writeJSON(w, http.StatusOK, connection)
			return
		case <-signal:
		}
	}
}

func (r *registry) boundedConnectionWait(seconds int) time.Duration {
	if seconds <= 0 {
		return r.connectionWait
	}
	wait := time.Duration(seconds) * time.Second
	if wait > r.connectionWait {
		return r.connectionWait
	}
	return wait
}

func connectionTerminal(state string) bool {
	switch state {
	case "accepted", "rejected", "canceled", "expired", "closed", "failed":
		return true
	default:
		return false
	}
}

func (r *registry) targetSignalLocked(nodeID string) <-chan struct{} {
	signal := r.connectionSignals[nodeID]
	if signal == nil {
		signal = make(chan struct{})
		r.connectionSignals[nodeID] = signal
	}
	return signal
}

func (r *registry) requestSignalLocked(requestID string) <-chan struct{} {
	signal := r.requestSignals[requestID]
	if signal == nil {
		signal = make(chan struct{})
		r.requestSignals[requestID] = signal
	}
	return signal
}

func (r *registry) notifyTargetLocked(nodeID string) {
	if signal := r.connectionSignals[nodeID]; signal != nil {
		close(signal)
		delete(r.connectionSignals, nodeID)
	}
}

func (r *registry) notifyRequestLocked(requestID string) {
	if signal := r.requestSignals[requestID]; signal != nil {
		close(signal)
		delete(r.requestSignals, requestID)
	}
}

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

type controlPlaneStatus struct {
	HeartbeatLastOK   time.Time `json:"heartbeat_last_ok,omitempty"`
	HeartbeatError    string    `json:"heartbeat_error,omitempty"`
	DiscoveryLastOK   time.Time `json:"discovery_last_ok,omitempty"`
	DiscoveryError    string    `json:"discovery_error,omitempty"`
	DiscoveryRevision uint64    `json:"discovery_revision"`
	InboxLastOK       time.Time `json:"inbox_last_ok,omitempty"`
	InboxError        string    `json:"inbox_error,omitempty"`
	InboxCursor       uint64    `json:"inbox_cursor"`
	InboxWaiting      bool      `json:"inbox_waiting"`
}

var controlStatusMu sync.Mutex

func loadControlStatus(profilePath string) (controlPlaneStatus, error) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(profilePath), "control-status.json"))
	if errors.Is(err, os.ErrNotExist) {
		return controlPlaneStatus{}, nil
	}
	var status controlPlaneStatus
	if err != nil {
		return status, err
	}
	return status, json.Unmarshal(body, &status)
}

func updateControlStatus(profilePath string, update func(*controlPlaneStatus)) error {
	controlStatusMu.Lock()
	defer controlStatusMu.Unlock()
	status, _ := loadControlStatus(profilePath)
	update(&status)
	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(profilePath), "control-status.json")
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(body, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func runControlPlane(ctx context.Context, profilePath string) {
	for {
		p, err := loadProfile(profilePath)
		if err != nil {
			return
		}
		if p.Coordinator.URL == "" {
			return
		}
		if p.Coordinator.Credential == nil {
			approved, pollErr := pollEnrollment(ctx, profilePath, &p)
			if pollErr != nil {
				fmt.Fprintln(os.Stderr, "mayoiga: enrollment poll:", pollErr)
			}
			if !approved {
				if !waitContext(ctx, 5*time.Second) {
					return
				}
				continue
			}
		}
		runAuthenticatedControlPlane(ctx, profilePath, p)
		return
	}
}

func runAuthenticatedControlPlane(ctx context.Context, profilePath string, p profile) {
	revisions := make(chan uint64, 1)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		runHeartbeatWorker(ctx, profilePath, p, revisions)
	}()
	go func() {
		defer workers.Done()
		runDiscoveryWorker(ctx, profilePath, p, revisions)
	}()
	go func() {
		defer workers.Done()
		runInboxWorker(ctx, profilePath, p)
	}()
	workers.Wait()
}

func runHeartbeatWorker(ctx context.Context, profilePath string, p profile, revisions chan uint64) {
	for {
		revision, err := sendHeartbeat(ctx, p)
		now := time.Now().UTC()
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			if err != nil {
				status.HeartbeatError = err.Error()
			} else {
				status.HeartbeatLastOK, status.HeartbeatError = now, ""
			}
		})
		if err == nil {
			select {
			case revisions <- revision:
			default:
				select {
				case <-revisions:
				default:
				}
				select {
				case revisions <- revision:
				default:
				}
			}
		} else if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "mayoiga: heartbeat:", err)
		}
		if !waitContext(ctx, 30*time.Second) {
			return
		}
	}
}

func runDiscoveryWorker(ctx context.Context, profilePath string, p profile, revisions <-chan uint64) {
	status, _ := loadControlStatus(profilePath)
	current := status.DiscoveryRevision
	for {
		select {
		case <-ctx.Done():
			return
		case revision := <-revisions:
			if revision == current {
				continue
			}
			_, err := fetchDiscovery(ctx, profilePath, p, current, revision)
			now := time.Now().UTC()
			_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
				if err != nil {
					status.DiscoveryError = err.Error()
				} else {
					current = revision
					status.DiscoveryRevision = revision
					status.DiscoveryLastOK, status.DiscoveryError = now, ""
				}
			})
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "mayoiga: discovery:", err)
			}
		}
	}
}

func runInboxWorker(ctx context.Context, profilePath string, p profile) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			status.InboxWaiting = true
		})
		output, err := waitInbox(ctx, profilePath, p)
		now := time.Now().UTC()
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			status.InboxWaiting = false
			if err != nil {
				status.InboxError = err.Error()
			} else {
				status.InboxLastOK, status.InboxError = now, ""
				if output.Cursor > status.InboxCursor {
					status.InboxCursor = output.Cursor
				}
			}
		})
		if err == nil {
			dispatchAutomaticConnectionOffers(ctx, profilePath, p, output.Events)
			backoff = time.Second
			continue
		}
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintln(os.Stderr, "mayoiga: connection inbox:", err)
		if !waitContext(ctx, backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

var automaticConnectionOffers sync.Map

func dispatchAutomaticConnectionOffers(ctx context.Context, profilePath string, p profile, events []connectionRequest) {
	for _, event := range events {
		if event.TargetNode != p.Node.ID || event.ReturnRelay == "" {
			continue
		}
		if _, loaded := automaticConnectionOffers.LoadOrStore(event.ID, struct{}{}); loaded {
			continue
		}
		go func(event connectionRequest) {
			defer automaticConnectionOffers.Delete(event.ID)
			if err := serveAutomaticConnectionOffer(ctx, profilePath, p, event); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "mayoiga: reverse connection %s: %v\n", event.ID, err)
			}
		}(event)
	}
}

func serveAutomaticConnectionOffer(ctx context.Context, profilePath string, p profile, event connectionRequest) error {
	target, exists := localPublishedTarget(p, event.Service)
	if !exists {
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "published service is not local")
		return fmt.Errorf("service %q is not published locally", event.Service)
	}
	nodes, err := loadDiscovered(profilePath)
	if err != nil {
		return err
	}
	var relay discoveredNode
	for _, node := range nodes {
		if node.ID == event.ReturnRelay && node.Role == "relay" && node.Relay != nil {
			relay = node
			break
		}
	}
	if relay.ID == "" {
		return fmt.Errorf("return relay %q is not discovered", event.ReturnRelay)
	}
	// The reverse connection is already mutually authenticated and encrypted by
	// dialReverseRelay.  Re-entering the local VLESS listener here used to add a
	// second TLS handshake and a short-lived embedded Xray instance for every
	// connection.  The receiving node owns this mapping, so it can safely dial
	// the configured local target directly.
	local, err := net.DialTimeout("tcp", target, relayDialTimeout)
	if err != nil {
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "local published target is unavailable")
		return fmt.Errorf("connect local published target %q: %w", target, err)
	}
	reverse, err := dialReverseRelay(p, relay, event.IdempotencyKey, event.Service)
	if err != nil {
		local.Close()
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "return relay is unavailable")
		return fmt.Errorf("connect return relay: %w", err)
	}
	if _, err := decideConnectionRequest(ctx, p, event.ID, "accept", ""); err != nil {
		reverse.Close()
		local.Close()
		return err
	}
	_ = removeInboxRequest(profilePath, event.ID)
	go func() {
		defer local.Close()
		bridge(reverse, local)
	}()
	return nil
}

func localPublishedTarget(p profile, name string) (string, bool) {
	for _, mapping := range p.Mappings {
		if mapping.Kind == "publish" && mapping.Name == name && validateHostPort(mapping.Target) == nil {
			return mapping.Target, true
		}
	}
	return "", false
}

func localPublishedService(p profile, name string) (publishedService, bool) {
	node := localDiscoveredNode(p)
	for _, service := range node.Services {
		if service.Name != name {
			continue
		}
		for _, mapping := range p.Mappings {
			if mapping.Kind == "publish" && mapping.Name == name {
				service.DirectCandidates = []directCandidate{{Address: loopbackEndpoint(mapping.Listen)}}
				return service, true
			}
		}
	}
	return publishedService{}, false
}

func loopbackEndpoint(endpoint string) string {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

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
