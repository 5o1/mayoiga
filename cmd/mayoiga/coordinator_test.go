package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	rec = call(http.MethodPost, "/v1/admin/reject", approveRequest{DeviceCode: rejectedState.DeviceCode}, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status=%d", rec.Code)
	}
	rec = call(http.MethodPost, "/v1/enroll/poll", pollRequest{RequestID: rejectedState.RequestID, Secret: rejectedState.Secret}, false)
	var rejectedPoll pollResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &rejectedPoll)
	if rejectedPoll.Status != "rejected" {
		t.Fatalf("poll status=%q", rejectedPoll.Status)
	}
	rec = call(http.MethodGet, "/v1/admin/handshakes?status=403", nil, true)
	var rejectedHistory []handshakeHistory
	_ = json.Unmarshal(rec.Body.Bytes(), &rejectedHistory)
	if len(rejectedHistory) != 1 {
		t.Fatalf("rejected history=%+v", rejectedHistory)
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

func TestCoordinatorPinnedTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	pin, err := makeCertificate(certPath, filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := coordinatorHTTPClient(pin)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(mustRead(t, certPath))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if err := transport.TLSClientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Fatal(err)
	}
	wrong, err := coordinatorHTTPClient(strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := wrong.Transport.(*http.Transport).TLSClientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err == nil {
		t.Fatal("wrong certificate pin was accepted")
	}
}

func TestClientKeepsEnrollmentPrivateKeyLocal(t *testing.T) {
	dir := t.TempDir()
	r, err := newRegistry(filepath.Join(dir, "coordinator-state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(r)
	defer server.Close()
	certificateHash := sha256.Sum256(server.Certificate().Raw)
	p := profile{
		Version: profileVersion, Instance: "client", Role: "client", Segment: "site", VirtualNetwork: "mesh",
		Node: nodeConfig{ID: "local-node", Name: "local-node"},
		Coordinator: coordinatorClient{
			URL: server.URL, PinnedSHA256: hex.EncodeToString(certificateHash[:]),
		},
	}
	profilePath := filepath.Join(dir, "profile.json")
	if err := requestEnrollment(context.Background(), profilePath, &p); err != nil {
		t.Fatal(err)
	}
	if p.Coordinator.Enrollment == nil || p.Coordinator.Enrollment.Credential == nil {
		t.Fatal("node did not retain its locally generated pending credential")
	}
	privateKey := p.Coordinator.Enrollment.Credential.PrivateKey
	if privateKey == "" || strings.Contains(string(mustRead(t, r.path)), privateKey) {
		t.Fatal("coordinator state retained the node private key")
	}
	approveBody, _ := json.Marshal(approveRequest{DeviceCode: p.Coordinator.Enrollment.DeviceCode})
	approve := httptest.NewRequest(http.MethodPost, "/v1/admin/approve", bytes.NewReader(approveBody))
	approve.RemoteAddr = "127.0.0.1:40000"
	approve.Header.Set("Authorization", "Bearer secret")
	approveResponse := httptest.NewRecorder()
	r.serveAdmin(approveResponse, approve)
	if approveResponse.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approveResponse.Code, approveResponse.Body)
	}
	approved, err := pollEnrollment(context.Background(), profilePath, &p)
	if err != nil || !approved {
		t.Fatalf("poll approved=%v err=%v", approved, err)
	}
	if p.Coordinator.Credential == nil || p.Coordinator.Credential.PrivateKey != privateKey || p.Coordinator.Enrollment != nil {
		t.Fatal("node did not promote its local credential after approval")
	}
	if _, err := syncDiscovery(context.Background(), profilePath, &p); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustRead(t, r.path)), privateKey) {
		t.Fatal("coordinator state retained the private key after registration")
	}
}

func TestCoordinatorPublishesVerifiedNodeCapabilities(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	credential := testNodeCredential(t)
	r.state.Authorized["relay"] = authorizedNode{PublicKey: credential.PublicKey}
	node := discoveredNode{
		ID: "relay", Name: "relay", Role: "relay", Segment: "home", VirtualNetwork: "mesh",
		IdentityKey: "spoofed",
		Services: []publishedService{{
			NodeID: "spoofed", Name: "nas", Segment: "spoofed", Endpoint: "relay.test:18443",
			UUID: "uuid", PinnedSHA256: strings.Repeat("a", 64),
		}},
		Relay: &relayAdvertisement{
			Endpoint: "relay.test:19443", PinnedSHA256: strings.Repeat("b", 64), Priority: 10,
		},
	}
	body, _ := json.Marshal(discoveryRequest{Node: node})
	req := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.40:40000"
	if err := signRequest(req, body, node.ID, credential.PrivateKey); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", rec.Code, rec.Body)
	}
	stored := r.state.Nodes["relay"]
	if stored.IdentityKey != credential.PublicKey {
		t.Fatal("coordinator accepted a spoofed identity public key")
	}
	if len(stored.Services) != 1 || stored.Services[0].NodeID != "relay" || stored.Services[0].Segment != "home" {
		t.Fatalf("coordinator did not bind service ownership: %+v", stored.Services)
	}
	if stored.Relay == nil || stored.Relay.Priority != 10 {
		t.Fatalf("relay capability missing: %+v", stored.Relay)
	}
}

func TestValidateCoordinatorURL(t *testing.T) {
	tests := []struct {
		url  string
		good bool
	}{
		{"https://control.example:8443", true},
		{"https://control.example", false},
		{"https://control.example:0", false},
		{"http://control.example:8443", false},
		{"https://user:pass@control.example", false},
		{"https://control.example/api", false},
	}
	for _, test := range tests {
		if got := validateCoordinatorURL(test.url) == nil; got != test.good {
			t.Errorf("validateCoordinatorURL(%q) good=%v, want %v", test.url, got, test.good)
		}
	}
}

func TestHostPortRequiresExplicitUsableNumericPort(t *testing.T) {
	tests := []struct {
		address string
		good    bool
	}{
		{"127.0.0.1:12345", true},
		{"example.test:443", true},
		{"[::1]:23456", true},
		{"example.test", false},
		{"example.test:http", false},
		{"127.0.0.1:0", false},
		{"127.0.0.1:65536", false},
	}
	for _, test := range tests {
		if got := validateHostPort(test.address) == nil; got != test.good {
			t.Errorf("validateHostPort(%q) good=%v want=%v", test.address, got, test.good)
		}
	}
}

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

func TestListenConflictAndAdminAddressValidation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := checkListenAvailable(address); err == nil {
		t.Fatal("occupied port was accepted")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkListenAvailable(address); err != nil {
		t.Fatalf("released port was rejected: %v", err)
	}
	if err := validateAdminListen("0.0.0.0:12345"); err == nil {
		t.Fatal("non-loopback admin address was accepted")
	}
	if !sameListenAddress("0.0.0.0:12345", "127.0.0.1:12345") {
		t.Fatal("wildcard listener conflict was not detected")
	}
}

func TestCoordinatorStartsSeparatePublicAndAdminListeners(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "coordinator.crt")
	keyPath := filepath.Join(dir, "coordinator.key")
	pin, err := makeCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	p := profile{
		VirtualNetwork: "mesh",
		Server: coordinatorServer{
			Listen: freeAddress(t), AdminListen: freeAddress(t), AdminToken: "secret",
			Certificate: certPath, Key: keyPath, PinnedSHA256: pin,
		},
	}
	runtime, errorsChannel, err := startCoordinator(filepath.Join(dir, "profile.json"), p)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Shutdown(context.Background())
	client, err := coordinatorHTTPClient(pin)
	if err != nil {
		t.Fatal(err)
	}
	request := func(address, path string, admin bool) *http.Response {
		t.Helper()
		var response *http.Response
		for attempt := 0; attempt < 20; attempt++ {
			req, _ := http.NewRequest(http.MethodGet, "https://"+address+path, nil)
			if admin {
				req.Header.Set("Authorization", "Bearer secret")
			}
			response, err = client.Do(req)
			if err == nil {
				return response
			}
			select {
			case serverErr := <-errorsChannel:
				t.Fatalf("coordinator server failed: %v", serverErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
		t.Fatalf("coordinator did not become ready: %v", err)
		return nil
	}
	publicResponse := request(p.Server.Listen, "/v1/admin/handshakes", true)
	publicResponse.Body.Close()
	if publicResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("public listener exposed admin API: %d", publicResponse.StatusCode)
	}
	adminResponse := request(p.Server.AdminListen, "/v1/admin/handshakes", true)
	adminResponse.Body.Close()
	if adminResponse.StatusCode != http.StatusOK {
		t.Fatalf("admin listener status=%d", adminResponse.StatusCode)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("random unavailable")
}

func TestRandomSourceErrorsAreReturned(t *testing.T) {
	old := secureRandomReader
	secureRandomReader = failingReader{}
	t.Cleanup(func() { secureRandomReader = old })
	if _, err := randomToken(); err == nil {
		t.Fatal("randomToken ignored random source failure")
	}
	if _, err := randomDeviceCode(); err == nil {
		t.Fatal("randomDeviceCode ignored random source failure")
	}
	if _, _, err := ed25519.GenerateKey(io.Reader(secureRandomReader)); err == nil {
		t.Fatal("credential generation ignored random source failure")
	}
}

func TestRandomIdentifierCollisionRetriesAreBounded(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	r.state.Pending["existing"] = pendingHandshake{DeviceCode: "AAAA-AAAA"}
	old := secureRandomReader
	t.Cleanup(func() { secureRandomReader = old })

	secureRandomReader = bytes.NewReader(make([]byte, deviceCodeAttempts*8))
	if _, err := r.allocateDeviceCodeLocked(); err == nil {
		t.Fatal("device-code collision retries were unbounded or accepted a duplicate")
	}

	zeroID := strings.Repeat("0", 64)
	r.state.History[zeroID] = handshakeHistory{RequestID: zeroID}
	secureRandomReader = bytes.NewReader(make([]byte, deviceCodeAttempts*32))
	if _, err := r.allocateRequestIDLocked(); err == nil {
		t.Fatal("request-id collision retries were unbounded or accepted a duplicate")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
