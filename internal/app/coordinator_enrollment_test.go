package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentSigningDiscoveryAndHistory(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "nodes.json"), "secret", "mesh-a")
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, input any, admin bool) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(input)
		req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
		req.RemoteAddr = "127.0.0.1:12345"
		if admin {
			req.Header.Set("Authorization", "Bearer secret")
		}
		rec := httptest.NewRecorder()
		if strings.HasPrefix(path, "/v1/admin/") {
			r.serveAdmin(rec, req)
		} else {
			r.ServeHTTP(rec, req)
		}
		return rec
	}
	publicKey := func() string {
		t.Helper()
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawStdEncoding.EncodeToString(key)
	}
	enroll := func(node discoveredNode) (enrollmentState, nodeCredential) {
		t.Helper()
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		credential := nodeCredential{
			PublicKey:  base64.RawStdEncoding.EncodeToString(publicKey),
			PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey),
		}
		rec := call(http.MethodPost, "/v1/enroll/request", discoveryRequest{Node: node, PublicKey: credential.PublicKey}, false)
		if rec.Code != http.StatusCreated {
			t.Fatalf("enroll status=%d body=%s", rec.Code, rec.Body.String())
		}
		var state enrollmentState
		if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		rec = call(http.MethodPost, "/v1/admin/approve", approveRequest{DeviceCode: state.DeviceCode}, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("approve status=%d body=%s", rec.Code, rec.Body.String())
		}
		rec = call(http.MethodGet, "/v1/admin/handshakes?status=200", nil, true)
		var approved []handshakeHistory
		if err := json.Unmarshal(rec.Body.Bytes(), &approved); err != nil || len(approved) == 0 {
			t.Fatalf("approved history missing: err=%v body=%s", err, rec.Body.String())
		}
		rec = call(http.MethodPost, "/v1/enroll/poll", pollRequest{RequestID: state.RequestID, Secret: state.Secret}, false)
		var polled pollResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &polled); err != nil {
			t.Fatal(err)
		}
		if polled.Status != "approved" {
			t.Fatalf("approved status missing: %+v", polled)
		}
		if strings.Contains(string(mustRead(t, r.path)), "private_key") {
			t.Fatal("coordinator state retained a node private key")
		}
		return state, credential
	}
	register := func(node discoveredNode, credential nodeCredential) discoveryResponse {
		t.Helper()
		body, _ := json.Marshal(discoveryRequest{Node: node})
		req := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
		if err := signRequest(req, body, node.ID, credential.PrivateKey); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("register status=%d body=%s", rec.Code, rec.Body.String())
		}
		var response discoveryResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	alpha := discoveredNode{ID: "a", Name: "alpha", VirtualNetwork: "mesh-a"}
	_, alphaCredential := enroll(alpha)
	if got := register(alpha, alphaCredential); len(got.Nodes) != 0 {
		t.Fatalf("first node discovered %+v", got.Nodes)
	}
	beta := discoveredNode{ID: "b", Name: "beta", VirtualNetwork: "mesh-a"}
	_, betaCredential := enroll(beta)
	if got := register(beta, betaCredential); len(got.Nodes) != 1 || got.Nodes[0].ID != "a" {
		t.Fatalf("unexpected discovered nodes: %+v", got.Nodes)
	}
	if strings.Contains(string(mustRead(t, r.path)), "private_key") {
		t.Fatal("completed coordinator state retained a node private key")
	}

	replayBody, _ := json.Marshal(discoveryRequest{Node: alpha})
	first := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(replayBody))
	if err := signRequest(first, replayBody, alpha.ID, alphaCredential.PrivateKey); err != nil {
		t.Fatal(err)
	}
	second := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(replayBody))
	for key, values := range first.Header {
		second.Header[key] = append([]string(nil), values...)
	}
	firstRec, secondRec := httptest.NewRecorder(), httptest.NewRecorder()
	r.ServeHTTP(firstRec, first)
	r.ServeHTTP(secondRec, second)
	if firstRec.Code != http.StatusOK || secondRec.Code != http.StatusUnauthorized {
		t.Fatalf("replay statuses first=%d second=%d", firstRec.Code, secondRec.Code)
	}
	rec := call(http.MethodGet, "/v1/admin/handshakes?status=201", nil, true)
	var history []handshakeHistory
	if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 {
		t.Fatalf("completed history=%+v", history)
	}

	rejected := discoveredNode{ID: "c", Name: "rejected", VirtualNetwork: "mesh-a"}
	rec = call(http.MethodPost, "/v1/enroll/request", discoveryRequest{Node: rejected, PublicKey: publicKey()}, false)
	var rejectedState enrollmentState
	_ = json.Unmarshal(rec.Body.Bytes(), &rejectedState)
	rec = call(http.MethodPost, "/v1/admin/reject", approveRequest{DeviceCode: rejectedState.DeviceCode, Reason: "owner declined this device"}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status=%d", rec.Code)
	}
	rec = call(http.MethodPost, "/v1/enroll/poll", pollRequest{RequestID: rejectedState.RequestID, Secret: rejectedState.Secret}, false)
	var rejectedPoll pollResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &rejectedPoll)
	if rejectedPoll.Status != "rejected" {
		t.Fatalf("poll status=%q", rejectedPoll.Status)
	}
	if rejectedPoll.Reason != "owner declined this device" {
		t.Fatalf("poll reason=%q", rejectedPoll.Reason)
	}
	rec = call(http.MethodGet, "/v1/admin/handshakes?status=403", nil, true)
	var rejectedHistory []handshakeHistory
	_ = json.Unmarshal(rec.Body.Bytes(), &rejectedHistory)
	if len(rejectedHistory) != 1 {
		t.Fatalf("rejected history=%+v", rejectedHistory)
	}
	if rejectedHistory[0].Reason != "owner declined this device" {
		t.Fatalf("history reason=%q", rejectedHistory[0].Reason)
	}

	rec = call(http.MethodPost, "/v1/enroll/request", discoveryRequest{Node: discoveredNode{ID: "x", Name: "other", VirtualNetwork: "mesh-b"}}, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("other network enrollment status = %d", rec.Code)
	}

	expiring := discoveredNode{ID: "d", Name: "expired", VirtualNetwork: "mesh-a"}
	rec = call(http.MethodPost, "/v1/enroll/request", discoveryRequest{Node: expiring, PublicKey: publicKey()}, false)
	var expiringState enrollmentState
	_ = json.Unmarshal(rec.Body.Bytes(), &expiringState)
	r.mu.Lock()
	pending := r.state.Pending[expiringState.RequestID]
	pending.ExpiresAt = time.Now().Add(-time.Second)
	r.state.Pending[expiringState.RequestID] = pending
	r.mu.Unlock()
	rec = call(http.MethodGet, "/v1/admin/handshakes?status=410", nil, true)
	var expiredHistory []handshakeHistory
	_ = json.Unmarshal(rec.Body.Bytes(), &expiredHistory)
	if len(expiredHistory) != 1 {
		t.Fatalf("expired history=%+v", expiredHistory)
	}
}
