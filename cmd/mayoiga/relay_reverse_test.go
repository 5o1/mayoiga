package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
