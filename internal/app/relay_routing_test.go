package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubnodeEnrollsSyncsAndRoutesOnlyThroughUpstreamRelay(t *testing.T) {
	dir := t.TempDir()
	registry, err := newRegistry(filepath.Join(dir, "coordinator-state.json"), "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewTLSServer(registry)
	defer coordinator.Close()
	coordinatorHash := sha256.Sum256(coordinator.Certificate().Raw)
	coordinatorPin := hex.EncodeToString(coordinatorHash[:])

	approve := func(p *profile) {
		t.Helper()
		body, _ := json.Marshal(approveRequest{DeviceCode: p.Coordinator.Enrollment.DeviceCode})
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/approve", bytes.NewReader(body))
		request.RemoteAddr = "127.0.0.1:50001"
		request.Header.Set("Authorization", "Bearer admin")
		response := httptest.NewRecorder()
		registry.serveAdmin(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("approval status=%d body=%s", response.Code, response.Body)
		}
	}

	relayListen := freeAddress(t)
	relayCertificate := filepath.Join(dir, "relay.crt")
	relayKey := filepath.Join(dir, "relay.key")
	relayPin, err := makeCertificate(relayCertificate, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	relayProfile := profile{
		Version: profileVersion, Instance: "relay", Role: "relay",
		Segment: "home", VirtualNetwork: "mesh", Node: nodeConfig{ID: "relay", Name: "relay"},
		Coordinator: coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin},
		Relay: relayConfig{
			Listen: relayListen, Endpoint: relayListen, Priority: 10,
			Certificate: relayCertificate, Key: relayKey, PinnedSHA256: relayPin,
			AdmissionTokenHash: relayAdmissionTokenHash("subnode-token"),
		},
	}
	relayPath := filepath.Join(dir, "relay", "profile.json")
	if err := requestEnrollment(context.Background(), relayPath, &relayProfile); err != nil {
		t.Fatal(err)
	}
	approve(&relayProfile)
	if approved, err := pollEnrollment(context.Background(), relayPath, &relayProfile); err != nil || !approved {
		t.Fatalf("relay approval=%v err=%v", approved, err)
	}
	if _, err := syncDiscovery(context.Background(), relayPath, &relayProfile); err != nil {
		t.Fatal(err)
	}
	relayServer, err := startRelayServer(relayProfile, relayPath)
	if err != nil {
		t.Fatal(err)
	}
	defer relayServer.Close()

	targetRelayListen := freeAddress(t)
	targetRelayCertificate := filepath.Join(dir, "target-relay.crt")
	targetRelayKey := filepath.Join(dir, "target-relay.key")
	targetRelayPin, err := makeCertificate(targetRelayCertificate, targetRelayKey)
	if err != nil {
		t.Fatal(err)
	}
	targetRelayProfile := profile{
		Version: profileVersion, Instance: "target-relay", Role: "relay",
		Segment: "school", VirtualNetwork: "mesh", Node: nodeConfig{ID: "target-relay", Name: "target-relay"},
		Coordinator: coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin},
		Relay: relayConfig{
			Listen: targetRelayListen, Endpoint: targetRelayListen, Priority: 10,
			Certificate: targetRelayCertificate, Key: targetRelayKey, PinnedSHA256: targetRelayPin,
		},
	}
	targetRelayPath := filepath.Join(dir, "target-relay", "profile.json")
	if err := requestEnrollment(context.Background(), targetRelayPath, &targetRelayProfile); err != nil {
		t.Fatal(err)
	}
	approve(&targetRelayProfile)
	if approved, err := pollEnrollment(context.Background(), targetRelayPath, &targetRelayProfile); err != nil || !approved {
		t.Fatalf("target relay approval=%v err=%v", approved, err)
	}
	if _, err := syncDiscovery(context.Background(), targetRelayPath, &targetRelayProfile); err != nil {
		t.Fatal(err)
	}
	targetRelayServer, err := startRelayServer(targetRelayProfile, targetRelayPath)
	if err != nil {
		t.Fatal(err)
	}
	defer targetRelayServer.Close()

	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()
	publishListen := freeAddress(t)
	publishCertificate := filepath.Join(dir, "publish.crt")
	publishKey := filepath.Join(dir, "publish.key")
	publishPin, err := makeCertificate(publishCertificate, publishKey)
	if err != nil {
		t.Fatal(err)
	}
	publishUUID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	publish := mapping{
		Name: "echo", Kind: "publish", Listen: publishListen,
		Target: echoAddress, UUID: publishUUID, Certificate: publishCertificate,
		Key: publishKey, CertificateSHA256: publishPin,
	}
	targetProfile := profile{
		Version: profileVersion, Instance: "target", Role: "client",
		Segment: "school", VirtualNetwork: "mesh", Node: nodeConfig{ID: "target", Name: "target"},
		Coordinator: coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin},
		Mappings:    []mapping{publish},
	}
	targetPath := filepath.Join(dir, "target", "profile.json")
	if err := requestEnrollment(context.Background(), targetPath, &targetProfile); err != nil {
		t.Fatal(err)
	}
	approve(&targetProfile)
	if approved, err := pollEnrollment(context.Background(), targetPath, &targetProfile); err != nil || !approved {
		t.Fatalf("target approval=%v err=%v", approved, err)
	}
	if _, err := syncDiscovery(context.Background(), targetPath, &targetProfile); err != nil {
		t.Fatal(err)
	}
	publisher, err := startMapping(publish)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runInboxWorker(ctx, targetPath, targetProfile)

	subnodeProfile := profile{
		Version: profileVersion, Instance: "offline", Role: "subnode",
		Segment: "home", VirtualNetwork: "mesh", Node: nodeConfig{ID: "offline", Name: "z-offline"},
		Coordinator: coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin},
		Subnode: subnodeConfig{
			RelayNodeID: "relay", RelayEndpoint: relayListen, RelayPinnedSHA256: relayPin, RelayToken: "subnode-token",
		},
	}
	subnodePath := filepath.Join(dir, "offline", "profile.json")
	if connection, err := dialCoordinatorViaRelay(context.Background(), "mesh", "untrusted", subnodeConfig{
		RelayNodeID: "relay", RelayEndpoint: relayListen, RelayPinnedSHA256: relayPin, RelayToken: "incorrect-token",
	}); err == nil {
		connection.Close()
		t.Fatal("relay accepted a coordinator tunnel without its admission token")
	}
	if err := requestEnrollment(context.Background(), subnodePath, &subnodeProfile); err != nil {
		t.Fatalf("subnode enrollment through relay: %v", err)
	}
	approve(&subnodeProfile)
	if approved, err := pollEnrollment(context.Background(), subnodePath, &subnodeProfile); err != nil || !approved {
		t.Fatalf("subnode approval through relay=%v err=%v", approved, err)
	}
	if _, err := syncDiscovery(context.Background(), subnodePath, &subnodeProfile); err != nil {
		t.Fatalf("subnode discovery through relay: %v", err)
	}
	if _, err := syncDiscovery(context.Background(), relayPath, &relayProfile); err != nil {
		t.Fatal(err)
	}
	if _, err := syncDiscovery(context.Background(), targetRelayPath, &targetRelayProfile); err != nil {
		t.Fatal(err)
	}

	pullListen := freeAddress(t)
	pull, err := startSmartPull(subnodeProfile, subnodePath, mapping{
		Name: "echo", Kind: "pull", Listen: pullListen, TargetNode: "target", Service: "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()
	assertEcho(t, pullListen, "subnode-upstream-relay")
}

func TestTargetSideRelayFailoverAndDirectFallback(t *testing.T) {
	dir := t.TempDir()
	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()

	publishListen := freeAddress(t)
	publishCertificate := filepath.Join(dir, "publish.crt")
	publishKey := filepath.Join(dir, "publish.key")
	publishPin, err := makeCertificate(publishCertificate, publishKey)
	if err != nil {
		t.Fatal(err)
	}
	publishUUID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	publish := mapping{
		Name: "echo", Kind: "publish", Listen: publishListen,
		Target: echoAddress, UUID: publishUUID,
		Certificate: publishCertificate, Key: publishKey, CertificateSHA256: publishPin,
	}
	publishInstance, err := startMapping(publish)
	if err != nil {
		t.Fatal(err)
	}
	defer publishInstance.Close()
	service := publishedService{
		NodeID: "target", Name: "echo", Segment: "home", DirectCandidates: []directCandidate{{Address: publishListen}},
		UUID: publishUUID, PinnedSHA256: publishPin,
	}
	target := discoveredNode{
		ID: "target", Name: "target", Role: "client", Segment: "home",
		VirtualNetwork: "mesh", Services: []publishedService{service},
	}

	sourceCredential := testNodeCredential(t)
	sourceNode := discoveredNode{
		ID: "source", Name: "source", Role: "client", Segment: "school",
		VirtualNetwork: "mesh", IdentityKey: sourceCredential.PublicKey,
	}
	relayListen := freeAddress(t)
	relayCertificate := filepath.Join(dir, "relay.crt")
	relayKey := filepath.Join(dir, "relay.key")
	relayPin, err := makeCertificate(relayCertificate, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	relayProfilePath := filepath.Join(dir, "relay", "profile.json")
	if err := os.MkdirAll(filepath.Dir(relayProfilePath), 0700); err != nil {
		t.Fatal(err)
	}
	relayProfile := profile{
		Version: profileVersion, Instance: "relay-live", Role: "relay", Segment: "home", VirtualNetwork: "mesh",
		Node: nodeConfig{ID: "relay-live", Name: "relay-live"},
		Relay: relayConfig{
			Listen: relayListen, Endpoint: relayListen, Priority: 20,
			Certificate: relayCertificate, Key: relayKey, PinnedSHA256: relayPin,
		},
	}
	if err := saveDiscovered(relayProfilePath, []discoveredNode{sourceNode, target}); err != nil {
		t.Fatal(err)
	}
	relayServer, err := startRelayServer(relayProfile, relayProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer relayServer.Close()

	deadEndpoint := freeAddress(t)
	deadRelay := discoveredNode{
		ID: "relay-dead", Name: "relay-dead", Role: "relay", Segment: "home", VirtualNetwork: "mesh",
		Relay: &relayAdvertisement{Endpoint: deadEndpoint, PinnedSHA256: relayPin, Priority: 10},
	}
	liveRelay := discoveredNode{
		ID: "relay-live", Name: "relay-live", Role: "relay", Segment: "home", VirtualNetwork: "mesh",
		Relay: &relayAdvertisement{Endpoint: relayListen, PinnedSHA256: relayPin, Priority: 20},
	}
	sourceProfilePath := filepath.Join(dir, "source", "profile.json")
	if err := os.MkdirAll(filepath.Dir(sourceProfilePath), 0700); err != nil {
		t.Fatal(err)
	}
	sourceProfile := profile{
		Version: profileVersion, Instance: "source", Role: "client", Segment: "school", VirtualNetwork: "mesh",
		Node:        nodeConfig{ID: "source", Name: "source"},
		Coordinator: coordinatorClient{Credential: &sourceCredential},
	}
	if err := saveProfile(sourceProfilePath, sourceProfile); err != nil {
		t.Fatal(err)
	}
	if err := saveDiscovered(sourceProfilePath, []discoveredNode{target, deadRelay, liveRelay}); err != nil {
		t.Fatal(err)
	}
	pullListen := freeAddress(t)
	pull, err := startSmartPull(sourceProfile, sourceProfilePath, mapping{
		Name: "echo", Kind: "pull", Listen: pullListen, TargetNode: "target", Service: "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(t, pullListen, "through-relay")
	pull.Close()
	if !pull.cooling[deadEndpoint].After(time.Now()) {
		t.Fatal("failed first relay was not placed in cooldown")
	}

	sourceProfile.Segment = "home"
	if err := saveProfile(sourceProfilePath, sourceProfile); err != nil {
		t.Fatal(err)
	}
	if err := saveDiscovered(sourceProfilePath, []discoveredNode{target, deadRelay}); err != nil {
		t.Fatal(err)
	}
	fallbackListen := freeAddress(t)
	fallback, err := startSmartPull(sourceProfile, sourceProfilePath, mapping{
		Name: "fallback", Kind: "pull", Listen: fallbackListen, TargetNode: "target", Service: "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fallback.Close()
	assertEcho(t, fallbackListen, "direct-fallback")
}

func TestRouteRulesPreferDirectSameSegmentAndTransitForCrossSegmentRelay(t *testing.T) {
	local := profile{Segment: "home", Node: nodeConfig{ID: "source"}}
	service := publishedService{NodeID: "target", Name: "svc", Segment: "home"}
	target := discoveredNode{ID: "target", Role: "client", Segment: "home", Services: []publishedService{service}}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := saveDiscovered(path, []discoveredNode{target}); err != nil {
		t.Fatal(err)
	}
	resolved, _, relays, err := resolveRoute(local, path, mapping{TargetNode: "target", Service: "svc"})
	if err != nil || resolved.ID != "target" || len(relays) != 0 {
		t.Fatalf("same-segment route target=%+v relays=%+v err=%v", resolved, relays, err)
	}
	if candidates := routeRelayCandidates(local, resolved, relays); len(candidates) != 0 {
		t.Fatalf("same-segment target unexpectedly selected transit: %+v", candidates)
	}

	local.Segment = "school"
	target.Role = "relay"
	target.Relay = &relayAdvertisement{Endpoint: "target.example:29443", Priority: 20}
	otherRelay := discoveredNode{
		ID: "other-relay", Role: "relay", Segment: "home",
		Relay: &relayAdvertisement{Endpoint: "other.example:29443", Priority: 1},
	}
	if err := saveDiscovered(path, []discoveredNode{target, otherRelay}); err != nil {
		t.Fatal(err)
	}
	resolved, _, relays, err = resolveRoute(local, path, mapping{TargetNode: "target", Service: "svc"})
	if err != nil || resolved.Role != "relay" {
		t.Fatalf("relay target route target=%+v err=%v", resolved, err)
	}
	candidates := routeRelayCandidates(local, resolved, relays)
	if len(candidates) != 1 || candidates[0].ID != "target" {
		t.Fatalf("cross-segment relay target did not select its own transit: %+v", candidates)
	}

	target.Role, target.UpstreamRelay = "subnode", "home-relay"
	target.Relay = nil
	target.Segment = "home"
	upstreamRelay := discoveredNode{
		ID: "home-relay", Role: "relay", Segment: "home",
		Relay: &relayAdvertisement{Endpoint: "relay.example:29443", Priority: 10},
	}
	otherRelay = discoveredNode{
		ID: "other-relay", Role: "relay", Segment: "home",
		Relay: &relayAdvertisement{Endpoint: "other.example:29443", Priority: 1},
	}
	if err := saveDiscovered(path, []discoveredNode{target, otherRelay, upstreamRelay}); err != nil {
		t.Fatal(err)
	}
	_, _, relays, err = resolveRoute(local, path, mapping{TargetNode: "target", Service: "svc"})
	if err != nil || len(relays) != 1 || relays[0].ID != "home-relay" {
		t.Fatalf("subnode did not force its upstream relay: relays=%+v err=%v", relays, err)
	}
}

func testNodeCredential(t *testing.T) nodeCredential {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return nodeCredential{
		PublicKey:  base64.RawStdEncoding.EncodeToString(publicKey),
		PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey),
	}
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	return listener.Addr().String(), func() { _ = listener.Close() }
}

func assertEcho(t *testing.T, address, text string) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := connection.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(text))
	if _, err := io.ReadFull(connection, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != text {
		t.Fatalf("echo=%q want=%q", buffer, text)
	}
}
