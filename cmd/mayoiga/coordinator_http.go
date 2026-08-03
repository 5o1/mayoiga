package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

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
