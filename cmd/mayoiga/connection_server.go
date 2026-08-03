package main

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

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
