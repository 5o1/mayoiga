package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (r *registry) requestEnrollment(w http.ResponseWriter, req *http.Request) {
	var input discoveryRequest
	if !decodeJSON(w, req, &input) {
		return
	}
	n := input.Node
	if n.ID == "" || n.Name == "" || n.VirtualNetwork != r.network {
		http.Error(w, "valid node id, name, and virtual network are required", http.StatusForbidden)
		return
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(input.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		http.Error(w, "valid node public key is required", http.StatusBadRequest)
		return
	}
	secret, err := randomToken()
	if err != nil {
		http.Error(w, "secure random source unavailable", http.StatusInternalServerError)
		return
	}
	h := sha256.Sum256([]byte(secret))
	pending := pendingHandshake{
		SecretHash: hex.EncodeToString(h[:]), PublicKey: input.PublicKey,
		Node: n, Source: requestSource(req), ExpiresAt: time.Now().UTC().Add(handshakeLifetime),
	}
	r.mu.Lock()
	r.cleanupLocked(time.Now().UTC())
	if n.Role == "subnode" {
		upstream, exists := r.state.Nodes[n.UpstreamRelay]
		if !exists || upstream.Role != "relay" || upstream.Segment != n.Segment ||
			upstream.VirtualNetwork != n.VirtualNetwork {
			r.mu.Unlock()
			http.Error(w, "subnode upstream is not an active relay in the same segment", http.StatusBadRequest)
			return
		}
	}
	if len(r.state.Pending) >= maxPendingHandshakes {
		r.mu.Unlock()
		http.Error(w, "too many pending handshakes", http.StatusServiceUnavailable)
		return
	}
	sourcePending := 0
	for _, existing := range r.state.Pending {
		if existing.Source == pending.Source {
			sourcePending++
		}
	}
	if sourcePending >= maxPendingPerSource {
		r.mu.Unlock()
		http.Error(w, "too many pending handshakes from this source", http.StatusTooManyRequests)
		return
	}
	pending.RequestID, err = r.allocateRequestIDLocked()
	if err != nil {
		r.mu.Unlock()
		http.Error(w, "unable to allocate handshake request id", http.StatusServiceUnavailable)
		return
	}
	pending.DeviceCode, err = r.allocateDeviceCodeLocked()
	if err != nil {
		r.mu.Unlock()
		http.Error(w, "unable to allocate device code", http.StatusServiceUnavailable)
		return
	}
	r.state.Pending[pending.RequestID] = pending
	r.state.History[pending.RequestID] = handshakeHistory{
		RequestID: pending.RequestID, DeviceCode: pending.DeviceCode, Node: pending.Node,
		StatusCode: 100, CreatedAt: time.Now().UTC(), ExpiresAt: pending.ExpiresAt,
	}
	r.appendAuditLocked(auditEvent{
		Action: "enrollment_requested", NodeID: pending.Node.ID, NodeName: pending.Node.Name,
		RequestID: pending.RequestID, Source: pending.Source,
	})
	err = r.persistLocked()
	r.mu.Unlock()
	if err != nil {
		http.Error(w, "failed to persist handshake", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, enrollmentState{
		RequestID: pending.RequestID, Secret: secret, DeviceCode: pending.DeviceCode, ExpiresAt: pending.ExpiresAt,
	})
}

func (r *registry) allocateRequestIDLocked() (string, error) {
	for attempt := 0; attempt < deviceCodeAttempts; attempt++ {
		requestID, err := randomToken()
		if err != nil {
			return "", err
		}
		if _, exists := r.state.Pending[requestID]; exists {
			continue
		}
		if _, exists := r.state.History[requestID]; !exists {
			return requestID, nil
		}
	}
	return "", errors.New("request id collision retry limit reached")
}

func (r *registry) allocateDeviceCodeLocked() (string, error) {
	for attempt := 0; attempt < deviceCodeAttempts; attempt++ {
		code, err := randomDeviceCode()
		if err != nil {
			return "", err
		}
		unique := true
		for _, existing := range r.state.Pending {
			if existing.DeviceCode == code {
				unique = false
				break
			}
		}
		if unique {
			return code, nil
		}
	}
	return "", errors.New("device code collision retry limit reached")
}

type pollRequest struct {
	RequestID string `json:"request_id"`
	Secret    string `json:"secret"`
}

type pollResponse struct {
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
}

func (r *registry) pollEnrollment(w http.ResponseWriter, req *http.Request) {
	var input pollRequest
	if !decodeJSON(w, req, &input) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked(time.Now().UTC())
	_ = r.persistLocked()
	pending, ok := r.state.Pending[input.RequestID]
	if !ok || !matchesHash(input.Secret, pending.SecretHash) {
		http.Error(w, "handshake not found or expired", http.StatusNotFound)
		return
	}
	status := "pending"
	if pending.Approved {
		status = "approved"
	}
	if pending.Rejected {
		status = "rejected"
	}
	history := r.state.History[input.RequestID]
	writeJSON(w, http.StatusOK, pollResponse{Status: status, ExpiresAt: pending.ExpiresAt, Reason: history.Reason})
}

func (r *registry) adminAuthorized(req *http.Request) bool {
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	return len(token) == len(r.adminToken) && subtle.ConstantTimeCompare([]byte(token), []byte(r.adminToken)) == 1
}

func (r *registry) listHandshakes(w http.ResponseWriter, req *http.Request) {
	if !r.adminAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	r.cleanupLocked(time.Now().UTC())
	statusFilter := 0
	if raw := req.URL.Query().Get("status"); raw != "" {
		statusFilter, _ = strconv.Atoi(raw)
	}
	items := make([]handshakeHistory, 0, len(r.state.History))
	for _, item := range r.state.History {
		if statusFilter == 0 || item.StatusCode == statusFilter {
			items = append(items, item)
		}
	}
	_ = r.persistLocked()
	r.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	writeJSON(w, http.StatusOK, items)
}

func (r *registry) listAudit(w http.ResponseWriter, req *http.Request) {
	if !r.adminAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.mu.Lock()
	items := append([]auditEvent(nil), r.state.Audit...)
	r.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
	writeJSON(w, http.StatusOK, items)
}

type approveRequest struct {
	DeviceCode string `json:"device_code"`
	Replace    bool   `json:"replace,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func (r *registry) approveHandshake(w http.ResponseWriter, req *http.Request) {
	if !r.adminAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input approveRequest
	if !decodeJSON(w, req, &input) {
		return
	}
	code := normalizeDeviceCode(input.DeviceCode)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked(time.Now().UTC())
	var requestID string
	var pending pendingHandshake
	for id, candidate := range r.state.Pending {
		if candidate.DeviceCode == code {
			requestID, pending = id, candidate
			break
		}
	}
	if requestID == "" {
		http.Error(w, "unexpired handshake not found", http.StatusNotFound)
		return
	}
	if pending.Rejected {
		http.Error(w, "handshake was rejected", http.StatusConflict)
		return
	}
	if existing, exists := r.state.Authorized[pending.Node.ID]; exists && existing.PublicKey != pending.PublicKey && !input.Replace {
		http.Error(w, "node id is already authorized; explicit replacement is required", http.StatusConflict)
		return
	}
	if !pending.Approved {
		action := "credential_approved"
		if _, exists := r.state.Authorized[pending.Node.ID]; exists {
			action = "credential_replaced"
		}
		pending.Approved = true
		r.state.Pending[requestID] = pending
		r.state.Authorized[pending.Node.ID] = authorizedNode{PublicKey: pending.PublicKey}
		history := r.state.History[requestID]
		history.StatusCode = 200
		history.HandledAt = time.Now().UTC()
		r.state.History[requestID] = history
		r.appendAuditLocked(auditEvent{
			Action: action, NodeID: pending.Node.ID, NodeName: pending.Node.Name,
			RequestID: requestID, Source: requestSource(req),
		})
		if err := r.persistLocked(); err != nil {
			http.Error(w, "failed to persist credential", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "node": pending.Node.Name, "expires_at": pending.ExpiresAt})
}

func (r *registry) rejectHandshake(w http.ResponseWriter, req *http.Request) {
	if !r.adminAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input approveRequest
	if !decodeJSON(w, req, &input) {
		return
	}
	if len(strings.TrimSpace(input.Reason)) > maxEnrollmentReason {
		http.Error(w, "enrollment reason is too long", http.StatusBadRequest)
		return
	}
	code := normalizeDeviceCode(input.DeviceCode)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupLocked(time.Now().UTC())
	var requestID string
	var pending pendingHandshake
	for id, candidate := range r.state.Pending {
		if candidate.DeviceCode == code {
			requestID, pending = id, candidate
			break
		}
	}
	if requestID == "" {
		http.Error(w, "unexpired handshake not found", http.StatusNotFound)
		return
	}
	if pending.Approved {
		http.Error(w, "handshake was already approved", http.StatusConflict)
		return
	}
	pending.Rejected = true
	r.state.Pending[requestID] = pending
	history := r.state.History[requestID]
	history.StatusCode = 403
	history.Reason = strings.TrimSpace(input.Reason)
	history.HandledAt = time.Now().UTC()
	r.state.History[requestID] = history
	r.appendAuditLocked(auditEvent{
		Action: "enrollment_rejected", NodeID: pending.Node.ID, NodeName: pending.Node.Name,
		RequestID: requestID, Source: requestSource(req),
	})
	if err := r.persistLocked(); err != nil {
		http.Error(w, "failed to persist rejection", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "rejected", "node": pending.Node.Name})
}

type revokeRequest struct {
	NodeID string `json:"node_id"`
}

func (r *registry) revokeNode(w http.ResponseWriter, req *http.Request) {
	if !r.adminAuthorized(req) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input revokeRequest
	if !decodeJSON(w, req, &input) {
		return
	}
	if strings.TrimSpace(input.NodeID) == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.state.Authorized[input.NodeID]; !exists {
		http.Error(w, "authorized node not found", http.StatusNotFound)
		return
	}
	delete(r.state.Authorized, input.NodeID)
	delete(r.state.Nodes, input.NodeID)
	r.appendAuditLocked(auditEvent{Action: "credential_revoked", NodeID: input.NodeID, Source: requestSource(req)})
	for id, pending := range r.state.Pending {
		if pending.Node.ID == input.NodeID {
			delete(r.state.Pending, id)
			history := r.state.History[id]
			history.StatusCode = 403
			history.HandledAt = time.Now().UTC()
			r.state.History[id] = history
		}
	}
	if err := r.persistLocked(); err != nil {
		http.Error(w, "failed to persist revocation", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "node_id": input.NodeID})
}
