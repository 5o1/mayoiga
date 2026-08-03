package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
			NodeID: "spoofed", Name: "nas", Segment: "spoofed",
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

func TestCoordinatorLeasesAndScopesDirectCandidates(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	publisherCredential := testNodeCredential(t)
	sameSegmentCredential := testNodeCredential(t)
	crossSegmentCredential := testNodeCredential(t)
	r.mu.Lock()
	r.state.Authorized["publisher"] = authorizedNode{PublicKey: publisherCredential.PublicKey}
	r.state.Authorized["same"] = authorizedNode{PublicKey: sameSegmentCredential.PublicKey}
	r.state.Authorized["cross"] = authorizedNode{PublicKey: crossSegmentCredential.PublicKey}
	r.state.Nodes["same"] = discoveredNode{ID: "same", Name: "same", Role: "client", Segment: "school", VirtualNetwork: "mesh", LastSeen: time.Now().UTC()}
	r.state.Nodes["cross"] = discoveredNode{ID: "cross", Name: "cross", Role: "client", Segment: "home", VirtualNetwork: "mesh", LastSeen: time.Now().UTC()}
	r.mu.Unlock()

	publisher := discoveredNode{
		ID: "publisher", Name: "publisher", Role: "client", Segment: "school", VirtualNetwork: "mesh",
		Services: []publishedService{{
			Name: "nas", UUID: "uuid", PinnedSHA256: strings.Repeat("a", 64),
			DirectCandidates: []directCandidate{{Address: "192.168.50.7:28443", ExpiresAt: time.Now().Add(24 * time.Hour)}},
		}},
	}
	body, _ := json.Marshal(discoveryRequest{Node: publisher})
	request := httptest.NewRequest(http.MethodPost, "/v1/nodes/register", bytes.NewReader(body))
	if err := signRequest(request, body, "publisher", publisherCredential.PrivateKey); err != nil {
		t.Fatal(err)
	}
	registered := httptest.NewRecorder()
	r.ServeHTTP(registered, request)
	if registered.Code != http.StatusOK {
		t.Fatalf("register status=%d body=%s", registered.Code, registered.Body)
	}

	r.mu.Lock()
	stored := r.state.Nodes["publisher"].Services[0].DirectCandidates
	r.mu.Unlock()
	if len(stored) != 1 || stored[0].Address != "192.168.50.7:28443" || stored[0].ExpiresAt.Before(time.Now().Add(60*time.Second)) || stored[0].ExpiresAt.After(time.Now().Add(2*directCandidateLease)) {
		t.Fatalf("coordinator did not assign candidate lease: %+v", stored)
	}

	discover := func(nodeID string, credential nodeCredential) []discoveredNode {
		input, _ := json.Marshal(discoverySyncRequest{})
		request := httptest.NewRequest(http.MethodPost, "/v1/nodes/discovery", bytes.NewReader(input))
		if err := signRequest(request, input, nodeID, credential.PrivateKey); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		r.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s discovery status=%d body=%s", nodeID, response.Code, response.Body)
		}
		var output discoveryResponse
		if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
			t.Fatal(err)
		}
		return output.Nodes
	}
	findPublisher := func(nodes []discoveredNode) publishedService {
		for _, node := range nodes {
			if node.ID == "publisher" {
				return node.Services[0]
			}
		}
		t.Fatal("publisher missing from discovery")
		return publishedService{}
	}
	if got := findPublisher(discover("same", sameSegmentCredential)).DirectCandidates; len(got) != 1 || got[0].Address != "192.168.50.7:28443" {
		t.Fatalf("same segment did not receive managed candidate: %+v", got)
	}
	if got := findPublisher(discover("cross", crossSegmentCredential)).DirectCandidates; len(got) != 0 {
		t.Fatalf("cross segment received LAN candidate: %+v", got)
	}

	r.mu.Lock()
	node := r.state.Nodes["publisher"]
	node.Services[0].DirectCandidates[0].ExpiresAt = time.Now().Add(-time.Second)
	r.state.Nodes["publisher"] = node
	r.cleanupLocked(time.Now().UTC())
	got := r.state.Nodes["publisher"].Services[0].DirectCandidates
	r.mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("expired candidate was retained: %+v", got)
	}
}

func TestLocalDirectCandidatesAreDerivedAtRuntime(t *testing.T) {
	previous := interfaceAddrs
	defer func() { interfaceAddrs = previous }()
	interfaceAddrs = func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.168.8.9")},
			&net.IPNet{IP: net.ParseIP("10.8.0.2")},
			&net.IPNet{IP: net.ParseIP("127.0.0.1")},
			&net.IPNet{IP: net.ParseIP("203.0.113.8")},
		}, nil
	}
	got := localDirectCandidates("0.0.0.0:28443")
	if len(got) != 2 || got[0].Address != "10.8.0.2:28443" || got[1].Address != "192.168.8.9:28443" {
		t.Fatalf("runtime candidates=%+v", got)
	}
	if !got[0].ExpiresAt.IsZero() {
		t.Fatalf("node assigned its own candidate lease: %+v", got[0])
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
