package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func TestRegisteredRelayEndToEnd(t *testing.T) {
	dir := t.TempDir()
	registry, err := newRegistry(filepath.Join(dir, "coordinator-state.json"), "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewTLSServer(registry)
	defer coordinator.Close()
	hash := sha256.Sum256(coordinator.Certificate().Raw)
	coordinatorPin := hex.EncodeToString(hash[:])

	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()
	publishListen := freeAddress(t)
	publishCertificate, publishKey := filepath.Join(dir, "service.crt"), filepath.Join(dir, "service.key")
	publishPin, err := makeCertificate(publishCertificate, publishKey)
	if err != nil {
		t.Fatal(err)
	}
	publishUUID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	targetMapping := mapping{
		Name: "echo", Kind: "publish", Listen: publishListen,
		Target: echoAddress, UUID: publishUUID,
		Certificate: publishCertificate, Key: publishKey, CertificateSHA256: publishPin,
	}

	relayListen := freeAddress(t)
	relayCertificate, relayKey := filepath.Join(dir, "transit.crt"), filepath.Join(dir, "transit.key")
	relayPin, err := makeCertificate(relayCertificate, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]*profile{
		"target": {
			Version: profileVersion, Instance: "target", Role: "client", Segment: "home", VirtualNetwork: "mesh",
			Node: nodeConfig{ID: "target", Name: "target"}, Mappings: []mapping{targetMapping},
		},
		"relay": {
			Version: profileVersion, Instance: "relay", Role: "relay", Segment: "home", VirtualNetwork: "mesh",
			Node: nodeConfig{ID: "relay", Name: "relay"},
			Relay: relayConfig{
				Listen: relayListen, Endpoint: relayListen, Priority: 10,
				Certificate: relayCertificate, Key: relayKey, PinnedSHA256: relayPin,
			},
		},
		"source": {
			Version: profileVersion, Instance: "source", Role: "client", Segment: "school", VirtualNetwork: "mesh",
			Node: nodeConfig{ID: "source", Name: "source"},
		},
	}
	paths := make(map[string]string)
	for name, p := range profiles {
		path := filepath.Join(dir, name, "profile.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		p.Coordinator = coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin}
		if err := requestEnrollment(context.Background(), path, p); err != nil {
			t.Fatalf("%s enrollment: %v", name, err)
		}
		approveBody, _ := json.Marshal(approveRequest{DeviceCode: p.Coordinator.Enrollment.DeviceCode})
		approve := httptest.NewRequest(http.MethodPost, "/v1/admin/approve", bytes.NewReader(approveBody))
		approve.RemoteAddr = "127.0.0.1:50000"
		approve.Header.Set("Authorization", "Bearer admin")
		response := httptest.NewRecorder()
		registry.serveAdmin(response, approve)
		if response.Code != http.StatusOK {
			t.Fatalf("%s approval status=%d body=%s", name, response.Code, response.Body)
		}
		if approved, err := pollEnrollment(context.Background(), path, p); err != nil || !approved {
			t.Fatalf("%s poll approved=%v err=%v", name, approved, err)
		}
		paths[name] = path
	}

	for _, name := range []string{"target", "relay", "source", "relay", "source", "target"} {
		if _, err := syncDiscovery(context.Background(), paths[name], profiles[name]); err != nil {
			t.Fatalf("%s sync: %v", name, err)
		}
	}
	targetInstance, err := startMapping(targetMapping)
	if err != nil {
		t.Fatal(err)
	}
	defer targetInstance.Close()
	transit, err := startRelayServer(*profiles["relay"], paths["relay"])
	if err != nil {
		t.Fatal(err)
	}
	defer transit.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runInboxWorker(ctx, paths["target"], *profiles["target"])
	pullListen := freeAddress(t)
	pull, err := startSmartPull(*profiles["source"], paths["source"], mapping{
		Name: "echo", Kind: "pull", Listen: pullListen, TargetNode: "target", Service: "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()
	assertEcho(t, pullListen, "registered-relay")
}

func TestCrossSegmentRelayPublishesThroughItsOwnTransit(t *testing.T) {
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
		Target: echoAddress, UUID: publishUUID, Certificate: publishCertificate,
		Key: publishKey, CertificateSHA256: publishPin,
	}

	transitListen := freeAddress(t)
	transitCertificate := filepath.Join(dir, "transit.crt")
	transitKey := filepath.Join(dir, "transit.key")
	transitPin, err := makeCertificate(transitCertificate, transitKey)
	if err != nil {
		t.Fatal(err)
	}
	relayProfile := profile{
		Version: profileVersion, Instance: "target-relay", Role: "relay",
		Segment: "home", VirtualNetwork: "mesh",
		Node: nodeConfig{ID: "target-relay", Name: "target-relay"},
		Relay: relayConfig{
			Listen: transitListen, Endpoint: transitListen, Priority: 10,
			Certificate: transitCertificate, Key: transitKey, PinnedSHA256: transitPin,
		},
		Mappings: []mapping{publish},
	}
	sourceCredential := testNodeCredential(t)
	sourceProfile := profile{
		Version: profileVersion, Instance: "source", Role: "client",
		Segment: "school", VirtualNetwork: "mesh",
		Node: nodeConfig{ID: "source", Name: "source"},
		Coordinator: coordinatorClient{
			Credential: &sourceCredential,
		},
	}
	sourceNode := localDiscoveredNode(sourceProfile)
	sourceNode.IdentityKey = sourceCredential.PublicKey
	relayNode := localDiscoveredNode(relayProfile)

	relayPath := filepath.Join(dir, "relay", "profile.json")
	sourcePath := filepath.Join(dir, "source", "profile.json")
	if err := os.MkdirAll(filepath.Dir(relayPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveProfile(sourcePath, sourceProfile); err != nil {
		t.Fatal(err)
	}
	if err := saveDiscovered(relayPath, []discoveredNode{sourceNode}); err != nil {
		t.Fatal(err)
	}
	if err := saveDiscovered(sourcePath, []discoveredNode{relayNode}); err != nil {
		t.Fatal(err)
	}

	publisher, err := startMapping(publish)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	transit, err := startRelayServer(relayProfile, relayPath)
	if err != nil {
		t.Fatal(err)
	}
	defer transit.Close()
	pullListen := freeAddress(t)
	pull, err := startSmartPull(sourceProfile, sourcePath, mapping{
		Name: "echo", Kind: "pull", Listen: pullListen,
		TargetNode: "target-relay", Service: "echo",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()
	assertEcho(t, pullListen, "relay-self-publish-via-transit")
}

func TestOnDemandReverseConnectionThroughSourceRelay(t *testing.T) {
	dir := t.TempDir()
	registry, err := newRegistry(filepath.Join(dir, "coordinator-state.json"), "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	coordinator := httptest.NewTLSServer(registry)
	defer coordinator.Close()
	coordinatorHash := sha256.Sum256(coordinator.Certificate().Raw)
	coordinatorPin := hex.EncodeToString(coordinatorHash[:])

	echoAddress, closeEcho := startEchoServer(t)
	defer closeEcho()
	publishListen := freeAddress(t)
	publishCertificate := filepath.Join(dir, "school-publish.crt")
	publishKey := filepath.Join(dir, "school-publish.key")
	publishPin, err := makeCertificate(publishCertificate, publishKey)
	if err != nil {
		t.Fatal(err)
	}
	publishUUID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	schoolPublish := mapping{
		Name: "school-service", Kind: "publish", Listen: publishListen,
		// The school node is behind NAT.  No publisher endpoint is configured;
		// the relay must reach it through the outbound reverse offer.
		Target: echoAddress, UUID: publishUUID,
		Certificate: publishCertificate, Key: publishKey, CertificateSHA256: publishPin,
	}

	relayListen := freeAddress(t)
	relayCertificate := filepath.Join(dir, "home-relay.crt")
	relayKey := filepath.Join(dir, "home-relay.key")
	relayPin, err := makeCertificate(relayCertificate, relayKey)
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]*profile{
		"home-relay": {
			Version: profileVersion, Instance: "home-relay", Role: "relay",
			Segment: "home", VirtualNetwork: "mesh",
			Node: nodeConfig{ID: "home-relay", Name: "home-relay"},
			Relay: relayConfig{
				Listen: relayListen, Endpoint: relayListen, Priority: 10,
				Certificate: relayCertificate, Key: relayKey, PinnedSHA256: relayPin,
			},
		},
		"school": {
			Version: profileVersion, Instance: "school", Role: "client",
			Segment: "school", VirtualNetwork: "mesh",
			Node:     nodeConfig{ID: "school", Name: "school"},
			Mappings: []mapping{schoolPublish},
		},
	}
	paths := make(map[string]string)
	for name, p := range profiles {
		path := filepath.Join(dir, name, "profile.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		p.Coordinator = coordinatorClient{URL: coordinator.URL, PinnedSHA256: coordinatorPin}
		if err := requestEnrollment(context.Background(), path, p); err != nil {
			t.Fatalf("%s enrollment: %v", name, err)
		}
		approveBody, _ := json.Marshal(approveRequest{DeviceCode: p.Coordinator.Enrollment.DeviceCode})
		approve := httptest.NewRequest(http.MethodPost, "/v1/admin/approve", bytes.NewReader(approveBody))
		approve.RemoteAddr = "127.0.0.1:50000"
		approve.Header.Set("Authorization", "Bearer admin")
		response := httptest.NewRecorder()
		registry.serveAdmin(response, approve)
		if response.Code != http.StatusOK {
			t.Fatalf("%s approval status=%d body=%s", name, response.Code, response.Body)
		}
		if approved, err := pollEnrollment(context.Background(), path, p); err != nil || !approved {
			t.Fatalf("%s approval=%v err=%v", name, approved, err)
		}
		paths[name] = path
	}
	for _, name := range []string{"school", "home-relay", "school", "home-relay"} {
		if _, err := syncDiscovery(context.Background(), paths[name], profiles[name]); err != nil {
			t.Fatalf("%s sync: %v", name, err)
		}
	}

	// A reverse offer dials the local publish target directly. It must not need
	// a second local VLESS/Xray listener before it can bridge the encrypted
	// return connection.
	transit, err := startRelayServer(*profiles["home-relay"], paths["home-relay"])
	if err != nil {
		t.Fatal(err)
	}
	defer transit.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runInboxWorker(ctx, paths["school"], *profiles["school"])

	pullListen := freeAddress(t)
	pull, err := startSmartPull(*profiles["home-relay"], paths["home-relay"], mapping{
		Name: "school-service", Kind: "pull", Listen: pullListen,
		TargetNode: "school", Service: "school-service",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pull.Close()
	for _, payload := range []string{"on-demand-reverse-1", "on-demand-reverse-2", "on-demand-reverse-3"} {
		assertEcho(t, pullListen, payload)
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	accepted := 0
	for _, request := range registry.state.Connections {
		if request.SourceNode == "home-relay" && request.TargetNode == "school" &&
			request.ReturnRelay == "home-relay" && request.State == "accepted" {
			accepted++
		}
	}
	if accepted != 3 {
		t.Fatalf("accepted reverse connection requests=%d, want 3", accepted)
	}
}

func TestReverseBrokerBindsRequestTargetAndService(t *testing.T) {
	connectionReady, cancel := reverseBroker.expect("token", "school", "socks")
	defer cancel()
	if _, ok := reverseBroker.take("token", "other-node", "socks"); ok {
		t.Fatal("broker accepted the wrong target node")
	}
	if _, ok := reverseBroker.take("token", "school", "other-service"); ok {
		t.Fatal("broker accepted the wrong service")
	}
	ready, ok := reverseBroker.take("token", "school", "socks")
	if !ok {
		t.Fatal("broker rejected matching reverse connection")
	}
	if _, ok := reverseBroker.take("token", "school", "socks"); ok {
		t.Fatal("broker allowed request replay")
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	go func() { ready.connection <- left }()
	if got := <-connectionReady; got != left {
		t.Fatal("broker delivered the wrong connection")
	}

	_, cancelRace := reverseBroker.expect("cancel-token", "school", "socks")
	expectation, ok := reverseBroker.take("cancel-token", "school", "socks")
	if !ok {
		t.Fatal("broker could not take cancellation-race expectation")
	}
	cancelRace()
	select {
	case <-expectation.done:
	default:
		t.Fatal("taken expectation did not observe source cancellation")
	}
}

func TestReverseDialWaitsForRelayConfirmation(t *testing.T) {
	dir := t.TempDir()
	certificatePath, keyPath := filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
	pin, err := makeCertificate(certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	credential := testNodeCredential(t)
	local := profile{
		Version: profileVersion, Instance: "target", Role: "client", Segment: "home", VirtualNetwork: "mesh",
		Node: nodeConfig{ID: "target", Name: "target"}, Coordinator: coordinatorClient{Credential: &credential},
	}
	relay := discoveredNode{ID: "relay", Relay: &relayAdvertisement{Endpoint: listener.Addr().String(), PinnedSHA256: pin}}
	received, allowConfirmation := make(chan struct{}), make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(connection).ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		var handshake relayHandshake
		if err := json.Unmarshal([]byte(line), &handshake); err != nil || handshake.Mode != "reverse" {
			serverErr <- fmt.Errorf("reverse handshake=%+v err=%v", handshake, err)
			return
		}
		close(received)
		<-allowConfirmation
		_, err = io.WriteString(connection, "OK\n")
		serverErr <- err
	}()

	result := make(chan error, 1)
	go func() {
		connection, err := dialReverseRelay(local, relay, "request", "service")
		if connection != nil {
			connection.Close()
		}
		result <- err
	}()
	<-received
	select {
	case err := <-result:
		t.Fatalf("reverse dial returned before relay confirmation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(allowConfirmation)
	if err := <-result; err != nil {
		t.Fatalf("reverse dial after confirmation: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestRelayErrorResponseKeepsCodeAndExplanation(t *testing.T) {
	err := relayResponseError("ERR coordinator_tunnel_unauthorized relay token is invalid\n")
	if err == nil || !strings.Contains(err.Error(), "coordinator_tunnel_unauthorized") || !strings.Contains(err.Error(), "relay token is invalid") {
		t.Fatalf("relay error=%v", err)
	}
}

func TestSubnodeGatewayAuthorizationScansAllPeers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	relay := relayServer{profile: profile{Segment: "home", Node: nodeConfig{ID: "home-relay"}}, path: path}
	if err := saveDiscovered(path, []discoveredNode{
		{ID: "ordinary-client", Role: "client", Segment: "home"},
		{ID: "offline", Role: "subnode", Segment: "home", UpstreamRelay: "home-relay"},
	}); err != nil {
		t.Fatal(err)
	}
	if !relay.isAuthorizedSubnodeGateway("offline") {
		t.Fatal("authorized subnode after another peer was not found")
	}
}

func TestServiceHandshakeSignatureMessageRemainsCompatible(t *testing.T) {
	handshake := relayHandshake{
		Version: 1, Mode: "service", Network: "mesh", SourceNode: "source",
		RelayNode: "relay", TargetNode: "target", Service: "svc",
		RequestID: "ignored-for-service", Timestamp: 123, Nonce: "nonce",
	}
	want := "1\nservice\nmesh\nsource\nrelay\ntarget\nsvc\n123\nnonce"
	if got := string(relayHandshakeMessage(handshake)); got != want {
		t.Fatalf("service handshake message changed:\n got %q\nwant %q", got, want)
	}
	handshake.Mode = "reverse"
	if got := string(relayHandshakeMessage(handshake)); !strings.HasSuffix(got, "\nignored-for-service") {
		t.Fatalf("reverse request ID is not signed: %q", got)
	}
}

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

	target.Role, target.UpstreamRelay = "subnode", "home-gateway"
	target.Relay = nil
	target.Segment = "home"
	gateway := discoveredNode{
		ID: "home-gateway", Role: "relay", Segment: "home",
		Relay: &relayAdvertisement{Endpoint: "relay.example:29443", Priority: 10},
	}
	otherRelay = discoveredNode{
		ID: "other-relay", Role: "relay", Segment: "home",
		Relay: &relayAdvertisement{Endpoint: "other.example:29443", Priority: 1},
	}
	if err := saveDiscovered(path, []discoveredNode{target, otherRelay, gateway}); err != nil {
		t.Fatal(err)
	}
	_, _, relays, err = resolveRoute(local, path, mapping{TargetNode: "target", Service: "svc"})
	if err != nil || len(relays) != 1 || relays[0].ID != "home-gateway" {
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
