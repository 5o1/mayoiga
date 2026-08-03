package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminAPIIsSeparatedAndLocalOnly(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	publicRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/handshakes", nil)
	publicRequest.RemoteAddr = "127.0.0.1:10001"
	publicRequest.Header.Set("Authorization", "Bearer secret")
	publicResponse := httptest.NewRecorder()
	r.ServeHTTP(publicResponse, publicRequest)
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("admin endpoint exposed on public handler: %d", publicResponse.Code)
	}

	remoteRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/handshakes", nil)
	remoteRequest.RemoteAddr = "192.0.2.20:10002"
	remoteRequest.Header.Set("Authorization", "Bearer secret")
	remoteResponse := httptest.NewRecorder()
	r.serveAdmin(remoteResponse, remoteRequest)
	if remoteResponse.Code != http.StatusForbidden {
		t.Fatalf("remote admin request status=%d", remoteResponse.Code)
	}

	localRequest := httptest.NewRequest(http.MethodGet, "/v1/admin/handshakes", nil)
	localRequest.RemoteAddr = "127.0.0.1:10003"
	localRequest.Header.Set("Authorization", "Bearer secret")
	localResponse := httptest.NewRecorder()
	r.serveAdmin(localResponse, localRequest)
	if localResponse.Code != http.StatusOK {
		t.Fatalf("local admin request status=%d body=%s", localResponse.Code, localResponse.Body)
	}
}

func TestEnrollmentLimits(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.RawStdEncoding.EncodeToString(publicKey)
	for i := 0; i <= maxPendingPerSource; i++ {
		body, _ := json.Marshal(discoveryRequest{
			Node:      discoveredNode{ID: fmt.Sprintf("node-%d", i), Name: "node", VirtualNetwork: "mesh"},
			PublicKey: key,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll/request", bytes.NewReader(body))
		req.RemoteAddr = "192.0.2.10:20000"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		want := http.StatusCreated
		if i == maxPendingPerSource {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("request %d status=%d want=%d body=%s", i, rec.Code, want, rec.Body)
		}
	}
}

func TestRateAndPersistentLogBounds(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if !r.allowRequest("test", 2) || !r.allowRequest("test", 2) || r.allowRequest("test", 2) {
		t.Fatal("fixed-window rate limit was not enforced")
	}
	r.mu.Lock()
	for i := 0; i < maxHandshakeHistory+1; i++ {
		id := fmt.Sprintf("history-%d", i)
		r.state.History[id] = handshakeHistory{RequestID: id, CreatedAt: time.Unix(int64(i), 0)}
	}
	for i := 0; i < maxAuditEvents+1; i++ {
		r.appendAuditLocked(auditEvent{Action: "test", Time: time.Unix(int64(i), 0)})
	}
	r.cleanupLocked(time.Now())
	historyCount, auditCount := len(r.state.History), len(r.state.Audit)
	r.mu.Unlock()
	if historyCount != maxHandshakeHistory || auditCount != maxAuditEvents {
		t.Fatalf("bounded logs history=%d audit=%d", historyCount, auditCount)
	}
}

func TestCredentialReplacementAndRevocation(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	adminCall := func(path string, input any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(input)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:30000"
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		r.serveAdmin(rec, req)
		return rec
	}
	enroll := func(credential nodeCredential) enrollmentState {
		body, _ := json.Marshal(discoveryRequest{
			Node:      discoveredNode{ID: "same-id", Name: "node", VirtualNetwork: "mesh"},
			PublicKey: credential.PublicKey,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/enroll/request", bytes.NewReader(body))
		req.RemoteAddr = "192.0.2.30:30001"
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("enroll status=%d body=%s", rec.Code, rec.Body)
		}
		var state enrollmentState
		_ = json.Unmarshal(rec.Body.Bytes(), &state)
		return state
	}
	makeCredential := func() nodeCredential {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return nodeCredential{
			PublicKey:  base64.RawStdEncoding.EncodeToString(publicKey),
			PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey),
		}
	}
	register := func(credential nodeCredential) int {
		body, _ := json.Marshal(discoveryRequest{
			Node: discoveredNode{ID: "same-id", Name: "node", VirtualNetwork: "mesh"},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
		req.RemoteAddr = "192.0.2.30:30002"
		if err := signRequest(req, body, "same-id", credential.PrivateKey); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	first := makeCredential()
	firstState := enroll(first)
	if rec := adminCall("/v1/admin/approve", approveRequest{DeviceCode: firstState.DeviceCode}); rec.Code != http.StatusOK {
		t.Fatalf("first approval status=%d body=%s", rec.Code, rec.Body)
	}
	if status := register(first); status != http.StatusOK {
		t.Fatalf("first credential registration status=%d", status)
	}
	second := makeCredential()
	secondState := enroll(second)
	if rec := adminCall("/v1/admin/approve", approveRequest{DeviceCode: secondState.DeviceCode}); rec.Code != http.StatusConflict {
		t.Fatalf("replacement without confirmation status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := adminCall("/v1/admin/approve", approveRequest{DeviceCode: secondState.DeviceCode, Replace: true}); rec.Code != http.StatusOK {
		t.Fatalf("explicit replacement status=%d body=%s", rec.Code, rec.Body)
	}
	if r.state.Authorized["same-id"].PublicKey != second.PublicKey {
		t.Fatal("replacement did not install the new public key")
	}
	if status := register(first); status != http.StatusUnauthorized {
		t.Fatalf("replaced credential registration status=%d", status)
	}
	if status := register(second); status != http.StatusOK {
		t.Fatalf("replacement credential registration status=%d", status)
	}
	if rec := adminCall("/v1/admin/revoke", revokeRequest{NodeID: "same-id"}); rec.Code != http.StatusOK {
		t.Fatalf("revocation status=%d body=%s", rec.Code, rec.Body)
	}
	if _, exists := r.state.Authorized["same-id"]; exists {
		t.Fatal("revoked credential remains authorized")
	}
	if status := register(second); status != http.StatusUnauthorized {
		t.Fatalf("revoked credential registration status=%d", status)
	}
	actions := make(map[string]bool)
	for _, event := range r.state.Audit {
		actions[event.Action] = true
		if strings.Contains(event.Action+event.NodeID+event.NodeName+event.Source, first.PrivateKey) {
			t.Fatal("audit event leaked a private key")
		}
	}
	for _, action := range []string{"enrollment_requested", "credential_approved", "credential_replaced", "credential_revoked"} {
		if !actions[action] {
			t.Fatalf("audit action %q missing: %+v", action, r.state.Audit)
		}
	}
}
