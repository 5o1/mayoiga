package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	handshakeLifetime       = 10 * time.Minute
	maxPendingHandshakes    = 1024
	maxPendingPerSource     = 10
	maxHandshakeHistory     = 10000
	maxAuditEvents          = 10000
	deviceCodeAttempts      = 32
	publicRequestsPerMinute = 120
	adminRequestsPerMinute  = 120
	directCandidateLease    = 90 * time.Second
	maxDirectCandidates     = 16
	maxEnrollmentReason     = 512
)

var (
	secureRandomReader = io.Reader(rand.Reader)
	interfaceAddrs     = net.InterfaceAddrs
)

type nodeConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type nodeCredential struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type enrollmentState struct {
	RequestID  string          `json:"request_id"`
	Secret     string          `json:"secret"`
	DeviceCode string          `json:"device_code"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Status     string          `json:"status,omitempty"`
	Credential *nodeCredential `json:"credential,omitempty"`
}

type coordinatorClient struct {
	URL          string           `json:"url"`
	PinnedSHA256 string           `json:"pinned_sha256"`
	Credential   *nodeCredential  `json:"credential,omitempty"`
	Enrollment   *enrollmentState `json:"enrollment,omitempty"`
}

type coordinatorServer struct {
	Listen                      string `json:"listen"`
	AdminListen                 string `json:"admin_listen"`
	AdminToken                  string `json:"admin_token"`
	Certificate                 string `json:"certificate"`
	Key                         string `json:"key"`
	PinnedSHA256                string `json:"pinned_sha256"`
	ConnectionWaitSeconds       int    `json:"connection_wait_seconds"`
	ConnectionRequestTTLSeconds int    `json:"connection_request_ttl_seconds"`
	ConnectionOfferLeaseSeconds int    `json:"connection_offer_lease_seconds"`
	ConnectionMaxPending        int    `json:"connection_max_pending"`
}

type discoveredNode struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Role           string              `json:"role"`
	Segment        string              `json:"segment"`
	VirtualNetwork string              `json:"virtual_network"`
	IdentityKey    string              `json:"identity_key,omitempty"`
	Services       []publishedService  `json:"services,omitempty"`
	Relay          *relayAdvertisement `json:"relay,omitempty"`
	UpstreamRelay  string              `json:"upstream_relay,omitempty"`
	LastSeen       time.Time           `json:"last_seen"`
}

type publishedService struct {
	NodeID           string            `json:"node_id"`
	Name             string            `json:"name"`
	Segment          string            `json:"segment"`
	DirectCandidates []directCandidate `json:"direct_candidates,omitempty"`
	UUID             string            `json:"uuid"`
	PinnedSHA256     string            `json:"pinned_sha256"`
}

// directCandidate is generated at runtime from a publisher's local network
// interfaces.  The coordinator assigns and renews ExpiresAt; it is never read
// from a profile and is distributed only to peers in the same segment.
type directCandidate struct {
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expires_at"`
}

type relayAdvertisement struct {
	Endpoint     string `json:"endpoint"`
	PinnedSHA256 string `json:"pinned_sha256"`
	Priority     int    `json:"priority"`
}

type discoveryRequest struct {
	Node      discoveredNode `json:"node"`
	PublicKey string         `json:"public_key,omitempty"`
}

type discoveryResponse struct {
	Revision uint64           `json:"revision"`
	Changed  bool             `json:"changed"`
	Nodes    []discoveredNode `json:"nodes,omitempty"`
}

type heartbeatResponse struct {
	Revision   uint64    `json:"revision"`
	ServerTime time.Time `json:"server_time"`
}

type discoverySyncRequest struct {
	AfterRevision uint64 `json:"after_revision"`
}

type pendingHandshake struct {
	RequestID  string         `json:"request_id"`
	SecretHash string         `json:"secret_hash"`
	DeviceCode string         `json:"device_code"`
	Node       discoveredNode `json:"node"`
	PublicKey  string         `json:"public_key"`
	Source     string         `json:"source,omitempty"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Approved   bool           `json:"approved,omitempty"`
	Rejected   bool           `json:"rejected,omitempty"`
}

type authorizedNode struct {
	PublicKey string `json:"public_key"`
}

type handshakeHistory struct {
	RequestID  string         `json:"request_id"`
	DeviceCode string         `json:"device_code"`
	Node       discoveredNode `json:"node"`
	StatusCode int            `json:"status_code"`
	Reason     string         `json:"reason,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	HandledAt  time.Time      `json:"handled_at,omitempty"`
}

type coordinatorState struct {
	Pending               map[string]pendingHandshake  `json:"pending"`
	History               map[string]handshakeHistory  `json:"history"`
	Authorized            map[string]authorizedNode    `json:"authorized"`
	Nodes                 map[string]discoveredNode    `json:"nodes"`
	Revision              uint64                       `json:"revision"`
	Connections           map[string]connectionRequest `json:"connections"`
	ConnectionIdempotency map[string]string            `json:"connection_idempotency"`
	ConnectionCursors     map[string]uint64            `json:"connection_cursors"`
	ConnectionAcks        map[string]uint64            `json:"connection_acks"`
	Audit                 []auditEvent                 `json:"audit"`
}

type auditEvent struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`
	NodeID    string    `json:"node_id,omitempty"`
	NodeName  string    `json:"node_name,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Source    string    `json:"source,omitempty"`
}

type registry struct {
	mu                sync.Mutex
	path              string
	adminToken        string
	network           string
	state             coordinatorState
	nonces            map[string]time.Time
	rates             map[string]rateWindow
	connectionSignals map[string]chan struct{}
	requestSignals    map[string]chan struct{}
	inboxWaiters      map[string]bool
	connectionWait    time.Duration
	connectionTTL     time.Duration
	connectionLease   time.Duration
	connectionMax     int
}

type rateWindow struct {
	Started time.Time
	Count   int
}

func newRegistry(path, adminToken, network string) (*registry, error) {
	r := &registry{
		path: path, adminToken: adminToken, network: network,
		state: coordinatorState{
			Pending: make(map[string]pendingHandshake), Authorized: make(map[string]authorizedNode),
			History: make(map[string]handshakeHistory), Nodes: make(map[string]discoveredNode),
			Connections:           make(map[string]connectionRequest),
			ConnectionIdempotency: make(map[string]string), ConnectionCursors: make(map[string]uint64),
			ConnectionAcks: make(map[string]uint64),
		},
		nonces: make(map[string]time.Time), rates: make(map[string]rateWindow),
		connectionSignals: make(map[string]chan struct{}), requestSignals: make(map[string]chan struct{}),
		inboxWaiters:   make(map[string]bool),
		connectionWait: connectionWaitMaximum, connectionTTL: connectionRequestLifetime,
		connectionLease: connectionOfferLease, connectionMax: maxConnectionRequests,
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &r.state); err != nil {
			return nil, fmt.Errorf("read coordinator state: %w", err)
		}
		if r.state.Pending == nil {
			r.state.Pending = make(map[string]pendingHandshake)
		}
		if r.state.History == nil {
			r.state.History = make(map[string]handshakeHistory)
		}
		if r.state.Authorized == nil {
			r.state.Authorized = make(map[string]authorizedNode)
		}
		if r.state.Nodes == nil {
			r.state.Nodes = make(map[string]discoveredNode)
		}
		if r.state.Connections == nil {
			r.state.Connections = make(map[string]connectionRequest)
		}
		if r.state.ConnectionIdempotency == nil {
			r.state.ConnectionIdempotency = make(map[string]string)
		}
		if r.state.ConnectionCursors == nil {
			r.state.ConnectionCursors = make(map[string]uint64)
		}
		if r.state.ConnectionAcks == nil {
			r.state.ConnectionAcks = make(map[string]uint64)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return r, nil
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.serveStructured(w, req, r.servePublic)
}

func (r *registry) servePublic(w http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/v1/connections/") {
		if r.serveConnections(w, req) {
			return
		}
		http.NotFound(w, req)
		return
	}
	limit := publicRequestsPerMinute
	rateClass := "enrollment:"
	if req.URL.Path == "/v1/nodes/register" {
		limit *= 5
		rateClass = "unauthenticated-register:"
	}
	if !r.allowRequest(rateClass+requestSource(req), limit) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/v1/enroll/request":
		r.requestEnrollment(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/enroll/poll":
		r.pollEnrollment(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/nodes/register":
		r.registerNode(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/nodes/heartbeat":
		r.heartbeatNode(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/nodes/discovery":
		r.discoverNodes(w, req)
	default:
		http.NotFound(w, req)
	}
}

func (r *registry) serveAdmin(w http.ResponseWriter, req *http.Request) {
	r.serveStructured(w, req, r.serveAdminRequest)
}

func (r *registry) serveAdminRequest(w http.ResponseWriter, req *http.Request) {
	if !isLoopbackRequest(req) {
		http.Error(w, "admin API is local only", http.StatusForbidden)
		return
	}
	if !r.allowRequest("admin:"+requestSource(req), adminRequestsPerMinute) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v1/admin/handshakes":
		r.listHandshakes(w, req)
	case req.Method == http.MethodGet && req.URL.Path == "/v1/admin/audit":
		r.listAudit(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/admin/approve":
		r.approveHandshake(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/admin/reject":
		r.rejectHandshake(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/admin/revoke":
		r.revokeNode(w, req)
	default:
		http.NotFound(w, req)
	}
}

func requestSource(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}

func isLoopbackRequest(req *http.Request) bool {
	host := requestSource(req)
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func (r *registry) allowRequest(key string, limit int) bool {
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rates) > 4096 {
		for existingKey, existing := range r.rates {
			if now.Sub(existing.Started) >= 2*time.Minute {
				delete(r.rates, existingKey)
			}
		}
	}
	return r.allowRequestLocked(key, limit, now)
}

func (r *registry) allowRequestLocked(key string, limit int, now time.Time) bool {
	window := r.rates[key]
	if window.Started.IsZero() || now.Sub(window.Started) >= time.Minute {
		window = rateWindow{Started: now}
	}
	if window.Count >= limit {
		return false
	}
	window.Count++
	r.rates[key] = window
	return true
}

func decodeJSON(w http.ResponseWriter, req *http.Request, target any) bool {
	req.Body = http.MaxBytesReader(w, req.Body, 64<<10)
	if err := json.NewDecoder(req.Body).Decode(target); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

type apiErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// structuredResponseWriter turns every coordinator error, including legacy
// http.Error calls, into a stable JSON envelope. Success responses are passed
// through byte-for-byte so long polls and existing clients remain compatible.
type structuredResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *structuredResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *structuredResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(body)
}

func (r *registry) serveStructured(w http.ResponseWriter, req *http.Request, next func(http.ResponseWriter, *http.Request)) {
	captured := &structuredResponseWriter{ResponseWriter: w}
	next(captured, req)
	status := captured.status
	if status == 0 {
		status = http.StatusOK
	}
	if status >= http.StatusBadRequest {
		message := strings.TrimSpace(captured.body.String())
		if message == "" {
			message = http.StatusText(status)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(apiErrorResponse{Code: apiErrorCode(status, message), Message: message})
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(captured.body.Bytes())
}

func apiErrorCode(status int, message string) string {
	known := map[string]string{
		"invalid body":                                                    "request_body_invalid",
		"invalid JSON":                                                    "request_json_invalid",
		"invalid JSON or node id":                                         "node_identity_invalid",
		"invalid node signature":                                          "node_signature_invalid",
		"node rate limit exceeded":                                        "node_rate_limited",
		"rate limit exceeded":                                             "request_rate_limited",
		"node must heartbeat before discovery":                            "node_not_active",
		"source or target node is not active":                             "connection_node_inactive",
		"target service is not published":                                 "published_service_missing",
		"return relay is not active in the source segment":                "return_relay_invalid",
		"connection request capacity reached":                             "connection_capacity_reached",
		"target connection queue is full":                                 "connection_target_queue_full",
		"an inbox wait is already active for this node":                   "inbox_wait_already_active",
		"cursor is ahead of server state":                                 "inbox_cursor_invalid",
		"connection request not found":                                    "connection_request_missing",
		"only the target node can decide this request":                    "connection_decision_forbidden",
		"only the source node can cancel this request":                    "connection_cancel_forbidden",
		"connection request cannot be decided in its current state":       "connection_state_terminal",
		"connection request is already terminal":                          "connection_state_terminal",
		"connection reason is too long":                                   "connection_reason_too_long",
		"enrollment reason is too long":                                   "enrollment_reason_too_long",
		"connection request is not visible to this node":                  "connection_request_hidden",
		"handshake not found or expired":                                  "enrollment_missing_or_expired",
		"unexpired handshake not found":                                   "enrollment_missing_or_expired",
		"handshake was rejected":                                          "enrollment_rejected",
		"handshake was already approved":                                  "enrollment_already_approved",
		"node id is already authorized; explicit replacement is required": "node_credential_conflict",
		"unauthorized":                                                    "admin_authentication_failed",
	}
	if code := known[message]; code != "" {
		return code
	}
	switch status {
	case http.StatusUnauthorized:
		return "authentication_failed"
	case http.StatusForbidden:
		return "access_denied"
	case http.StatusNotFound:
		return "resource_not_found"
	case http.StatusConflict:
		return "request_conflict"
	case http.StatusTooManyRequests:
		return "request_rate_limited"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "request_failed"
	}
}

func coordinatorResponseError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	var remote apiErrorResponse
	if json.Unmarshal(body, &remote) == nil && remote.Code != "" {
		message := strings.TrimSpace(remote.Message)
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("coordinator %s: %s", remote.Code, localizedError(remote.Code, message))
	}
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = response.Status
	}
	return fmt.Errorf("coordinator request failed: %s", message)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

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

func (r *registry) registerNode(w http.ResponseWriter, req *http.Request) {
	_, nodes, revision, ok := r.updateNode(w, req)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: true, Nodes: nodes})
}

func (r *registry) heartbeatNode(w http.ResponseWriter, req *http.Request) {
	_, _, revision, ok := r.updateNode(w, req)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, heartbeatResponse{Revision: revision, ServerTime: time.Now().UTC()})
}

func (r *registry) updateNode(w http.ResponseWriter, req *http.Request) (discoveredNode, []discoveredNode, uint64, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return discoveredNode{}, nil, 0, false
	}
	nodeID := req.Header.Get("X-Mayoiga-Node")
	r.mu.Lock()
	authorized, ok := r.state.Authorized[nodeID]
	if !ok || !r.verifySignatureLocked(req, body, authorized.PublicKey) {
		r.mu.Unlock()
		http.Error(w, "invalid node signature", http.StatusUnauthorized)
		return discoveredNode{}, nil, 0, false
	}
	if !r.allowRequestLocked("node:"+nodeID, publicRequestsPerMinute, time.Now().UTC()) {
		r.mu.Unlock()
		http.Error(w, "node rate limit exceeded", http.StatusTooManyRequests)
		return discoveredNode{}, nil, 0, false
	}
	var input discoveryRequest
	if err := json.Unmarshal(body, &input); err != nil || input.Node.ID != nodeID {
		r.mu.Unlock()
		http.Error(w, "invalid JSON or node id", http.StatusBadRequest)
		return discoveredNode{}, nil, 0, false
	}
	n := input.Node
	if n.Name == "" || n.VirtualNetwork != r.network {
		r.mu.Unlock()
		http.Error(w, "virtual network is not allowed", http.StatusForbidden)
		return discoveredNode{}, nil, 0, false
	}
	n.IdentityKey = authorized.PublicKey
	now := time.Now().UTC()
	for i := range n.Services {
		service := &n.Services[i]
		service.NodeID, service.Segment = n.ID, n.Segment
		candidates, candidateErr := managedDirectCandidates(service.DirectCandidates, now.Add(directCandidateLease))
		if service.Name == "" || service.UUID == "" || candidateErr != nil || !validSHA256Pin(service.PinnedSHA256) {
			r.mu.Unlock()
			http.Error(w, "invalid published service", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
		service.DirectCandidates = candidates
	}
	if n.Role == "relay" {
		if n.Relay == nil || validateHostPort(n.Relay.Endpoint) != nil || !validSHA256Pin(n.Relay.PinnedSHA256) || n.Relay.Priority < 0 {
			r.mu.Unlock()
			http.Error(w, "invalid relay advertisement", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
	} else {
		n.Relay = nil
	}
	if n.Role == "subnode" {
		if n.UpstreamRelay == "" {
			r.mu.Unlock()
			http.Error(w, "subnode has no upstream relay", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
		upstream, exists := r.state.Nodes[n.UpstreamRelay]
		if !exists || upstream.Role != "relay" || upstream.Segment != n.Segment ||
			upstream.VirtualNetwork != n.VirtualNetwork {
			r.mu.Unlock()
			http.Error(w, "subnode upstream is not an active relay in the same segment", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
	} else {
		n.UpstreamRelay = ""
	}
	old, existed := r.state.Nodes[n.ID]
	n.LastSeen = now
	r.state.Nodes[n.ID] = n
	if !existed || !sameNodeTopology(old, n) || directCandidateRenewalDue(old, now) {
		r.state.Revision++
	}
	for id, pending := range r.state.Pending {
		if pending.Node.ID == n.ID && pending.Approved && pending.PublicKey == authorized.PublicKey {
			delete(r.state.Pending, id)
			history := r.state.History[id]
			history.StatusCode = 201
			history.HandledAt = now
			r.state.History[id] = history
			r.appendAuditLocked(auditEvent{
				Action: "enrollment_completed", NodeID: n.ID, NodeName: n.Name, RequestID: id,
				Source: requestSource(req),
			})
		}
	}
	r.cleanupLocked(now)
	nodes := make([]discoveredNode, 0)
	for _, candidate := range r.state.Nodes {
		if candidate.VirtualNetwork == n.VirtualNetwork && candidate.ID != n.ID {
			nodes = append(nodes, nodeForDiscovery(n, candidate))
		}
	}
	persistErr := r.persistLocked()
	revision := r.state.Revision
	r.mu.Unlock()
	if persistErr != nil {
		http.Error(w, "failed to persist registry", http.StatusInternalServerError)
		return discoveredNode{}, nil, 0, false
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return n, nodes, revision, true
}

func sameNodeTopology(left, right discoveredNode) bool {
	left, right = topologyWithoutLeases(left), topologyWithoutLeases(right)
	leftBody, _ := json.Marshal(left)
	rightBody, _ := json.Marshal(right)
	return bytes.Equal(leftBody, rightBody)
}

// Direct-candidate lease expiry is coordinator-managed liveness metadata, not
// topology. Heartbeats renew it frequently; comparing its exact value here
// would force a discovery revision and full peer rewrite on every heartbeat.
func topologyWithoutLeases(node discoveredNode) discoveredNode {
	node.LastSeen = time.Time{}
	node.Services = append([]publishedService(nil), node.Services...)
	for serviceIndex := range node.Services {
		candidates := append([]directCandidate(nil), node.Services[serviceIndex].DirectCandidates...)
		for candidateIndex := range candidates {
			candidates[candidateIndex].ExpiresAt = time.Time{}
		}
		node.Services[serviceIndex].DirectCandidates = candidates
	}
	return node
}

// Peers must learn a renewed lease before their cached direct candidate
// expires. Refresh only in the latter half of the 90-second lease instead of
// on every 30-second heartbeat.
func directCandidateRenewalDue(node discoveredNode, now time.Time) bool {
	refreshAt := now.Add(directCandidateLease / 2)
	for _, service := range node.Services {
		for _, candidate := range service.DirectCandidates {
			if !candidate.ExpiresAt.IsZero() && !candidate.ExpiresAt.After(refreshAt) {
				return true
			}
		}
	}
	return false
}

func managedDirectCandidates(input []directCandidate, expiry time.Time) ([]directCandidate, error) {
	if len(input) > maxDirectCandidates {
		return nil, fmt.Errorf("too many direct candidates")
	}
	seen := make(map[string]struct{}, len(input))
	output := make([]directCandidate, 0, len(input))
	for _, candidate := range input {
		if err := validateDirectCandidate(candidate.Address); err != nil {
			return nil, err
		}
		if _, exists := seen[candidate.Address]; exists {
			continue
		}
		seen[candidate.Address] = struct{}{}
		output = append(output, directCandidate{Address: candidate.Address, ExpiresAt: expiry})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Address < output[j].Address })
	return output, nil
}

func validateDirectCandidate(address string) error {
	if err := validateHostPort(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("direct candidate must use a private unicast IP address")
	}
	return nil
}

// nodeForDiscovery keeps direct candidates in the coordinator's state but
// only releases them to peers in the same logical segment.  Cross-segment
// access always resolves a relay path instead of learning LAN addresses.
func nodeForDiscovery(requester, candidate discoveredNode) discoveredNode {
	if requester.Segment == candidate.Segment {
		return candidate
	}
	output := candidate
	output.Services = append([]publishedService(nil), candidate.Services...)
	for i := range output.Services {
		output.Services[i].DirectCandidates = nil
	}
	return output
}

func (r *registry) discoverNodes(w http.ResponseWriter, req *http.Request) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input discoverySyncRequest
	if json.Unmarshal(body, &input) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.cleanupLocked(time.Now().UTC())
	node, exists := r.state.Nodes[nodeID]
	if !exists {
		r.mu.Unlock()
		http.Error(w, "node must heartbeat before discovery", http.StatusConflict)
		return
	}
	revision := r.state.Revision
	if input.AfterRevision == revision {
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: false})
		return
	}
	nodes := make([]discoveredNode, 0, len(r.state.Nodes))
	for _, candidate := range r.state.Nodes {
		if candidate.VirtualNetwork == node.VirtualNetwork && candidate.ID != nodeID {
			nodes = append(nodes, nodeForDiscovery(node, candidate))
		}
	}
	r.mu.Unlock()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: true, Nodes: nodes})
}

func (r *registry) verifySignatureLocked(req *http.Request, body []byte, publicText string) bool {
	timestampText, nonce, signatureText := req.Header.Get("X-Mayoiga-Time"), req.Header.Get("X-Mayoiga-Nonce"), req.Header.Get("X-Mayoiga-Signature")
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || nonce == "" || signatureText == "" {
		return false
	}
	now := time.Now().UTC()
	sent := time.Unix(timestamp, 0)
	if sent.Before(now.Add(-2*time.Minute)) || sent.After(now.Add(2*time.Minute)) {
		return false
	}
	if expiry, exists := r.nonces[nonce]; exists && expiry.After(now) {
		return false
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(publicText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureText)
	if err != nil {
		return false
	}
	message := signedMessage(req.Method, req.URL.Path, timestampText, nonce, body)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return false
	}
	r.nonces[nonce] = now.Add(2 * time.Minute)
	return true
}

func signedMessage(method, path, timestamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

func (r *registry) cleanupLocked(now time.Time) bool {
	changed := false
	for id, pending := range r.state.Pending {
		if pending.ExpiresAt.Before(now) {
			changed = true
			delete(r.state.Pending, id)
			history := r.state.History[id]
			if history.StatusCode == 100 || history.StatusCode == 200 {
				history.StatusCode = 410
				history.HandledAt = now
				r.state.History[id] = history
				r.appendAuditLocked(auditEvent{
					Action: "enrollment_expired", NodeID: pending.Node.ID, NodeName: pending.Node.Name,
					RequestID: id,
				})
			}
		}
	}
	for id, node := range r.state.Nodes {
		if node.LastSeen.Before(now.Add(-2 * time.Minute)) {
			changed = true
			delete(r.state.Nodes, id)
			r.state.Revision++
			continue
		}
		candidatesChanged := false
		for serviceIndex := range node.Services {
			service := &node.Services[serviceIndex]
			active := service.DirectCandidates[:0]
			for _, candidate := range service.DirectCandidates {
				if candidate.ExpiresAt.After(now) {
					active = append(active, candidate)
				}
			}
			if len(active) != len(service.DirectCandidates) {
				service.DirectCandidates = active
				candidatesChanged = true
			}
		}
		if candidatesChanged {
			changed = true
			r.state.Nodes[id] = node
			r.state.Revision++
		}
	}
	for id, connection := range r.state.Connections {
		switch {
		case !connectionTerminal(connection.State) && connection.ExpiresAt.Before(now):
			changed = true
			connection.State, connection.StatusCode, connection.Reason = "expired", 410, "request expired"
			connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
			r.state.Connections[id] = connection
			r.notifyTargetLocked(connection.TargetNode)
			r.notifyRequestLocked(id)
		case connection.State == "offered" && !connection.OfferLeaseEnds.IsZero() && connection.OfferLeaseEnds.Before(now):
			changed = true
			r.state.ConnectionCursors[connection.TargetNode]++
			connection.State, connection.StatusCode = "queued", 100
			connection.Cursor = r.state.ConnectionCursors[connection.TargetNode]
			connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
			r.state.Connections[id] = connection
			r.notifyTargetLocked(connection.TargetNode)
			r.notifyRequestLocked(id)
		case connectionTerminal(connection.State) && connection.UpdatedAt.Before(now.Add(-24*time.Hour)):
			changed = true
			delete(r.state.Connections, id)
			delete(r.state.ConnectionIdempotency, connection.SourceNode+"\x00"+connection.IdempotencyKey)
			delete(r.requestSignals, id)
		}
	}
	for nonce, expiry := range r.nonces {
		if expiry.Before(now) {
			delete(r.nonces, nonce)
		}
	}
	if len(r.state.History) > maxHandshakeHistory {
		changed = true
		items := make([]handshakeHistory, 0, len(r.state.History))
		for _, history := range r.state.History {
			items = append(items, history)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
		for _, history := range items[:len(items)-maxHandshakeHistory] {
			delete(r.state.History, history.RequestID)
		}
	}
	return changed
}

func (r *registry) appendAuditLocked(event auditEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	r.state.Audit = append(r.state.Audit, event)
	if len(r.state.Audit) > maxAuditEvents {
		r.state.Audit = append([]auditEvent(nil), r.state.Audit[len(r.state.Audit)-maxAuditEvents:]...)
	}
}

func (r *registry) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

type coordinatorRuntime struct {
	servers []*http.Server
}

func (c *coordinatorRuntime) Shutdown(ctx context.Context) {
	for _, server := range c.servers {
		_ = server.Shutdown(ctx)
	}
}

func validateAdminListen(address string) error {
	if err := validateHostPort(address); err != nil {
		return fmt.Errorf("invalid coordinator admin listen address: %w", err)
	}
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("coordinator admin listener must use a loopback address")
	}
	return nil
}

func validateHostPort(address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be an explicit number from 1 to 65535")
	}
	return nil
}

func sameListenAddress(first, second string) bool {
	firstHost, firstPort, firstErr := net.SplitHostPort(first)
	secondHost, secondPort, secondErr := net.SplitHostPort(second)
	if firstErr != nil || secondErr != nil || firstPort != secondPort {
		return false
	}
	normalize := func(host string) string {
		if host == "localhost" {
			return "127.0.0.1"
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return strings.ToLower(host)
	}
	return normalize(firstHost) == normalize(secondHost) ||
		(firstHost == "" || firstHost == "0.0.0.0" || firstHost == "::") ||
		(secondHost == "" || secondHost == "0.0.0.0" || secondHost == "::")
}

func checkListenAvailable(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return listener.Close()
}

func startCoordinator(path string, p profile) (*coordinatorRuntime, <-chan error, error) {
	if p.Server.Listen == "" || p.Server.AdminListen == "" || p.Server.AdminToken == "" {
		return nil, nil, errors.New("coordinator server is not configured; use --action add-node or configure-node with --role coordinator")
	}
	if err := validateAdminListen(p.Server.AdminListen); err != nil {
		return nil, nil, err
	}
	r, err := newRegistry(filepath.Join(filepath.Dir(path), "coordinator-state.json"), p.Server.AdminToken, p.VirtualNetwork)
	if err != nil {
		return nil, nil, err
	}
	if p.Server.ConnectionWaitSeconds > 0 {
		r.connectionWait = time.Duration(p.Server.ConnectionWaitSeconds) * time.Second
	}
	if p.Server.ConnectionRequestTTLSeconds > 0 {
		r.connectionTTL = time.Duration(p.Server.ConnectionRequestTTLSeconds) * time.Second
	}
	if p.Server.ConnectionOfferLeaseSeconds > 0 {
		r.connectionLease = time.Duration(p.Server.ConnectionOfferLeaseSeconds) * time.Second
	}
	if p.Server.ConnectionMaxPending > 0 {
		r.connectionMax = p.Server.ConnectionMaxPending
	}
	publicServer := &http.Server{
		Addr: p.Server.Listen, Handler: r, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: r.connectionWait + 10*time.Second,
		IdleTimeout: r.connectionWait + 30*time.Second,
	}
	adminServer := &http.Server{
		Addr: p.Server.AdminListen, Handler: http.HandlerFunc(r.serveAdmin), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	errs := make(chan error, 2)
	runtime := &coordinatorRuntime{servers: []*http.Server{publicServer, adminServer}}
	for _, server := range runtime.servers {
		go func(server *http.Server) {
			err := server.ListenAndServeTLS(p.Server.Certificate, p.Server.Key)
			if !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}(server)
	}
	return runtime, errs, nil
}

func coordinatorHTTPClient(pinText string) (*http.Client, error) {
	pin, err := hex.DecodeString(normalizePin(pinText))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("coordinator pin must be 64 hexadecimal characters")
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec -- exact certificate pin is verified below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("coordinator sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return errors.New("coordinator certificate pin mismatch")
			}
			return nil
		},
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func coordinatorNodeHTTPClient(p profile) (*http.Client, error) {
	client, err := coordinatorHTTPClient(p.Coordinator.PinnedSHA256)
	if err != nil {
		return nil, err
	}
	if p.Role == "subnode" {
		transport := client.Transport.(*http.Transport)
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialCoordinatorViaRelay(ctx, p.VirtualNetwork, p.Node.ID, p.Subnode)
		}
	}
	return client, nil
}

func validSHA256Pin(pinText string) bool {
	pin, err := hex.DecodeString(normalizePin(pinText))
	return err == nil && len(pin) == sha256.Size
}

func requestEnrollment(ctx context.Context, path string, p *profile) error {
	if err := validateCoordinatorURL(p.Coordinator.URL); err != nil {
		return err
	}
	client, err := coordinatorNodeHTTPClient(*p)
	if err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(secureRandomReader)
	if err != nil {
		return fmt.Errorf("generate node credential: %w", err)
	}
	credential := &nodeCredential{
		PublicKey:  base64.RawStdEncoding.EncodeToString(publicKey),
		PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey),
	}
	body, _ := json.Marshal(discoveryRequest{Node: localDiscoveredNode(*p), PublicKey: credential.PublicKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Coordinator.URL+"/v1/enroll/request", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return coordinatorResponseError(resp)
	}
	var enrollment enrollmentState
	if err := json.NewDecoder(resp.Body).Decode(&enrollment); err != nil {
		return err
	}
	p.Coordinator.Enrollment = &enrollment
	p.Coordinator.Enrollment.Status = "pending"
	p.Coordinator.Enrollment.Credential = credential
	p.Coordinator.Credential = nil
	if err := saveProfile(path, *p); err != nil {
		return err
	}
	fmt.Printf("DEVICE_CODE=%s\nHANDSHAKE_EXPIRES=%s\n", enrollment.DeviceCode, enrollment.ExpiresAt.Format(time.RFC3339))
	return nil
}

func pollEnrollment(ctx context.Context, path string, p *profile) (bool, error) {
	if p.Coordinator.Credential != nil {
		return true, nil
	}
	if p.Coordinator.Enrollment == nil {
		return false, errors.New("no pending handshake; use configure-node with --coordinator and --coordinator-pin")
	}
	client, err := coordinatorNodeHTTPClient(*p)
	if err != nil {
		return false, err
	}
	body, _ := json.Marshal(pollRequest{RequestID: p.Coordinator.Enrollment.RequestID, Secret: p.Coordinator.Enrollment.Secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Coordinator.URL+"/v1/enroll/poll", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, coordinatorResponseError(resp)
	}
	var output pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return false, err
	}
	if output.Status == "rejected" {
		p.Coordinator.Enrollment.Status = "rejected"
		_ = saveProfile(path, *p)
		reason := strings.TrimSpace(output.Reason)
		if reason == "" {
			reason = localizedError("enrollment_rejected", "upstream coordinator rejected the handshake")
		}
		return false, fmt.Errorf("enrollment_rejected: %s", reason)
	}
	if output.Status != "approved" {
		return false, nil
	}
	if p.Coordinator.Enrollment.Credential == nil {
		return false, errors.New("pending handshake has no local credential")
	}
	if err := validateCredential(p.Coordinator.Enrollment.Credential); err != nil {
		return false, err
	}
	p.Coordinator.Credential = p.Coordinator.Enrollment.Credential
	p.Coordinator.Enrollment = nil
	return true, saveProfile(path, *p)
}

func syncDiscovery(ctx context.Context, path string, p *profile) ([]discoveredNode, error) {
	if p.Coordinator.URL == "" {
		return nil, errors.New("no upstream coordinator configured")
	}
	if p.Coordinator.Credential == nil {
		approved, err := pollEnrollment(ctx, path, p)
		if err != nil || !approved {
			return nil, err
		}
	}
	revision, err := sendHeartbeat(ctx, *p)
	if err != nil {
		return nil, err
	}
	return fetchDiscovery(ctx, path, *p, 0, revision)
}

func sendHeartbeat(ctx context.Context, p profile) (uint64, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/nodes/heartbeat", discoveryRequest{Node: localDiscoveredNode(p)})
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, coordinatorResponseError(response)
	}
	var output heartbeatResponse
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		return 0, err
	}
	return output.Revision, nil
}

func fetchDiscovery(ctx context.Context, path string, p profile, afterRevision, expectedRevision uint64) ([]discoveredNode, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/nodes/discovery", discoverySyncRequest{AfterRevision: afterRevision})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, coordinatorResponseError(response)
	}
	var output discoveryResponse
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		return nil, err
	}
	if expectedRevision != 0 && output.Revision < expectedRevision {
		return nil, errors.New("coordinator discovery revision moved backwards")
	}
	if !output.Changed {
		return loadDiscovered(path)
	}
	if err := saveDiscovered(path, output.Nodes); err != nil {
		return nil, err
	}
	return output.Nodes, nil
}

func localDiscoveredNode(p profile) discoveredNode {
	n := discoveredNode{ID: p.Node.ID, Name: p.Node.Name, Role: p.Role, Segment: p.Segment, VirtualNetwork: p.VirtualNetwork}
	for _, m := range p.Mappings {
		if m.Kind == "publish" {
			n.Services = append(n.Services, publishedService{
				NodeID: p.Node.ID, Name: m.Name, Segment: p.Segment,
				DirectCandidates: localDirectCandidates(m.Listen),
				UUID:             m.UUID, PinnedSHA256: m.CertificateSHA256,
			})
		}
	}
	if p.Role == "relay" {
		n.Relay = &relayAdvertisement{Endpoint: p.Relay.Endpoint, PinnedSHA256: p.Relay.PinnedSHA256, Priority: p.Relay.Priority}
	}
	if p.Role == "subnode" {
		n.UpstreamRelay = p.Subnode.RelayNodeID
	}
	return n
}

func localDirectCandidates(listen string) []directCandidate {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	addresses := make([]string, 0, maxDirectCandidates)
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		address := net.JoinHostPort(ip.String(), port)
		if validateDirectCandidate(address) == nil {
			addresses = append(addresses, address)
		}
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		interfaceAddresses, err := interfaceAddrs()
		if err != nil {
			return nil
		}
		for _, interfaceAddress := range interfaceAddresses {
			var ip net.IP
			switch value := interfaceAddress.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil {
				add(ip)
			}
		}
	default:
		add(net.ParseIP(host))
	}
	sort.Strings(addresses)
	output := make([]directCandidate, 0, len(addresses))
	for _, address := range addresses {
		if len(output) == maxDirectCandidates || (len(output) > 0 && output[len(output)-1].Address == address) {
			continue
		}
		output = append(output, directCandidate{Address: address})
	}
	return output
}

func signRequest(req *http.Request, body []byte, nodeID, privateText string) error {
	privateKey, err := base64.RawStdEncoding.DecodeString(privateText)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid node private credential")
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomToken()
	if err != nil {
		return fmt.Errorf("generate request nonce: %w", err)
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), signedMessage(req.Method, req.URL.Path, timestamp, nonce, body))
	req.Header.Set("X-Mayoiga-Node", nodeID)
	req.Header.Set("X-Mayoiga-Time", timestamp)
	req.Header.Set("X-Mayoiga-Nonce", nonce)
	req.Header.Set("X-Mayoiga-Signature", base64.RawStdEncoding.EncodeToString(signature))
	return nil
}

func validateCredential(c *nodeCredential) error {
	pub, e1 := base64.RawStdEncoding.DecodeString(c.PublicKey)
	priv, e2 := base64.RawStdEncoding.DecodeString(c.PrivateKey)
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize ||
		!bytes.Equal(pub, ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)) {
		return errors.New("invalid node credential")
	}
	return nil
}

func coordinatorAdminClient(path string) (*http.Client, string, profile, error) {
	p, err := loadProfile(path)
	if err != nil {
		return nil, "", p, err
	}
	if p.Role != "coordinator" || p.Server.AdminToken == "" {
		return nil, "", p, errors.New("this profile is not a coordinator")
	}
	client, err := coordinatorHTTPClient(p.Server.PinnedSHA256)
	if err != nil {
		return nil, "", p, err
	}
	host, port, err := net.SplitHostPort(p.Server.AdminListen)
	if err != nil {
		return nil, "", p, err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return client, "https://" + net.JoinHostPort(host, port), p, nil
}

func listPendingHandshakes(path string, statusCode int) error {
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	endpoint := origin + "/v1/admin/handshakes"
	if statusCode != 0 {
		endpoint += "?status=" + strconv.Itoa(statusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	var items []handshakeHistory
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no pending handshakes")
		return nil
	}
	for _, item := range items {
		fmt.Printf("%d\t%s\t%s\t%s\t%s\t%s\t%s\n", item.StatusCode, handshakeStatusText(item.StatusCode), item.DeviceCode, item.Node.Name, item.Node.Role, item.ExpiresAt.Format(time.RFC3339), item.Reason)
	}
	return nil
}

func listAuditEvents(path string) error {
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodGet, origin+"/v1/admin/audit", nil)
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	var items []auditEvent
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no audit events")
		return nil
	}
	for _, item := range items {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", item.Time.Format(time.RFC3339), item.Action, item.NodeID, item.NodeName, item.Source)
	}
	return nil
}

func approveDeviceCode(path, code string, replace bool) error {
	return decideDeviceCode(path, code, "approve", replace, "")
}

func rejectDeviceCode(path, code, reason string) error {
	return decideDeviceCode(path, code, "reject", false, reason)
}

func decideDeviceCode(path, code, decision string, replace bool, reason string) error {
	if normalizeDeviceCode(code) == "" {
		return errors.New("--device-code is required")
	}
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(approveRequest{DeviceCode: code, Replace: replace, Reason: reason})
	req, _ := http.NewRequest(http.MethodPost, origin+"/v1/admin/"+decision, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	fmt.Println("handshake " + map[string]string{"approve": "approved", "reject": "rejected"}[decision])
	return nil
}

func revokeNodeID(path, nodeID string) error {
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("--node-id is required")
	}
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(revokeRequest{NodeID: nodeID})
	req, _ := http.NewRequest(http.MethodPost, origin+"/v1/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	fmt.Println("node revoked")
	return nil
}

func handshakeStatusText(code int) string {
	switch code {
	case 100:
		return "pending"
	case 200:
		return "approved"
	case 201:
		return "completed"
	case 403:
		return "rejected"
	case 410:
		return "expired"
	default:
		return "unknown"
	}
}

func saveDiscovered(profilePath string, nodes []discoveredNode) error {
	b, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	path, tmp := filepath.Join(filepath.Dir(profilePath), "peers.json"), filepath.Join(filepath.Dir(profilePath), "peers.json.new")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadDiscovered(profilePath string) ([]discoveredNode, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(profilePath), "peers.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var nodes []discoveredNode
	return nodes, json.Unmarshal(b, &nodes)
}

func syncAndPrint(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	nodes, err := syncDiscovery(context.Background(), path, &p)
	if err != nil {
		return err
	}
	if p.Coordinator.Credential == nil {
		fmt.Println("handshake pending")
		return nil
	}
	return printNodes(nodes)
}

func printDiscovered(path string) error {
	nodes, err := loadDiscovered(path)
	if err != nil {
		return err
	}
	return printNodes(nodes)
}

func printNodes(nodes []discoveredNode) error {
	if len(nodes) == 0 {
		fmt.Println("no discovered nodes")
		return nil
	}
	fmt.Println("NODE_ID\tNAME\tROLE\tSEGMENT\tRELAY\tUPSTREAM_RELAY\tLAST_SEEN")
	for _, n := range nodes {
		relay := "-"
		if n.Relay != nil {
			relay = fmt.Sprintf("%s(priority=%d)", n.Relay.Endpoint, n.Relay.Priority)
		}
		upstream := n.UpstreamRelay
		if upstream == "" {
			upstream = "-"
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Name, n.Role, n.Segment, relay, upstream, n.LastSeen.Format(time.RFC3339))
		for _, service := range n.Services {
			addresses := make([]string, 0, len(service.DirectCandidates))
			for _, candidate := range service.DirectCandidates {
				addresses = append(addresses, candidate.Address)
			}
			fmt.Printf("  service\t%s\tdirect=%s\n", service.Name, strings.Join(addresses, ","))
		}
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(secureRandomReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomDeviceCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	random := make([]byte, 8)
	if _, err := io.ReadFull(secureRandomReader, random); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}

func normalizeDeviceCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

func matchesHash(secret, expected string) bool {
	h := sha256.Sum256([]byte(secret))
	got := hex.EncodeToString(h[:])
	return len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func normalizePin(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func validateCoordinatorURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("coordinator must be an HTTPS origin URL without credentials, a path, query, or fragment")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return errors.New("coordinator URL must include an explicit port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("coordinator URL port must be a number from 1 to 65535")
	}
	return nil
}
