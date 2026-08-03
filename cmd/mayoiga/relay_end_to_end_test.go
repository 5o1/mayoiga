package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
