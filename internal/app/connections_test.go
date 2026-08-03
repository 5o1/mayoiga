package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type connectionTestRegistry struct {
	registry    *registry
	credentials map[string]nodeCredential
}

func newConnectionTestRegistry(t *testing.T) connectionTestRegistry {
	t.Helper()
	r, err := newRegistry(filepath.Join(t.TempDir(), "coordinator-state.json"), "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	credentials := map[string]nodeCredential{
		"source": testNodeCredential(t),
		"target": testNodeCredential(t),
	}
	r.mu.Lock()
	for id, credential := range credentials {
		r.state.Authorized[id] = authorizedNode{PublicKey: credential.PublicKey}
	}
	r.state.Nodes["source"] = discoveredNode{
		ID: "source", Name: "source", Role: "client", Segment: "home",
		VirtualNetwork: "mesh", LastSeen: time.Now().UTC(),
	}
	r.state.Nodes["target"] = discoveredNode{
		ID: "target", Name: "target", Role: "client", Segment: "school",
		VirtualNetwork: "mesh", LastSeen: time.Now().UTC(),
		Services: []publishedService{{
			NodeID: "target", Name: "svc", Segment: "school",
			UUID: "uuid", PinnedSHA256: stringsOfHex("a"),
		}},
	}
	r.state.Revision = 2
	if err := r.persistLocked(); err != nil {
		r.mu.Unlock()
		t.Fatal(err)
	}
	r.mu.Unlock()
	return connectionTestRegistry{registry: r, credentials: credentials}
}

func stringsOfHex(character string) string {
	var output string
	for len(output) < 64 {
		output += character
	}
	return output
}

func (fixture connectionTestRegistry) call(t *testing.T, nodeID, endpoint string, input any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err := signRequest(request, body, nodeID, fixture.credentials[nodeID].PrivateKey); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	fixture.registry.ServeHTTP(recorder, request)
	return recorder
}

func decodeConnection(t *testing.T, recorder *httptest.ResponseRecorder) connectionRequest {
	t.Helper()
	var connection connectionRequest
	if err := json.Unmarshal(recorder.Body.Bytes(), &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func TestConnectionLongPollWakesImmediatelyAndRequestIsIdempotent(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	waitDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		waitDone <- fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{
			WaitSeconds: 2, MaxEvents: 4,
		})
	}()
	time.Sleep(30 * time.Millisecond)
	started := time.Now()
	created := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "same-operation", TargetNode: "target", Service: "svc",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body)
	}
	var inbox inboxWaitResponse
	select {
	case response := <-waitDone:
		if response.Code != http.StatusOK {
			t.Fatalf("wait status=%d body=%s", response.Code, response.Body)
		}
		if err := json.Unmarshal(response.Body.Bytes(), &inbox); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("long poll was not woken by a queued connection")
	}
	if time.Since(started) >= time.Second || len(inbox.Events) != 1 {
		t.Fatalf("long poll latency/events=%v/%+v", time.Since(started), inbox.Events)
	}
	duplicate := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "same-operation", TargetNode: "target", Service: "svc",
	})
	if duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d body=%s", duplicate.Code, duplicate.Body)
	}
	if decodeConnection(t, created).ID != decodeConnection(t, duplicate).ID {
		t.Fatal("idempotent retry created a different request")
	}
	fixture.registry.mu.Lock()
	count := len(fixture.registry.state.Connections)
	fixture.registry.mu.Unlock()
	if count != 1 {
		t.Fatalf("idempotent request count=%d", count)
	}
}

func TestConnectionErrorsAreStructuredAndRejectionReasonIsVisible(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	missing := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "missing-service", TargetNode: "target", Service: "missing",
	})
	if missing.Code != http.StatusNotFound || !strings.HasPrefix(missing.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("missing service response=%d content-type=%q", missing.Code, missing.Header().Get("Content-Type"))
	}
	var remote apiErrorResponse
	if err := json.Unmarshal(missing.Body.Bytes(), &remote); err != nil {
		t.Fatal(err)
	}
	if remote.Code != "published_service_missing" || remote.Message != "target service is not published" {
		t.Fatalf("structured error=%+v", remote)
	}
	err := coordinatorResponseError(&http.Response{
		StatusCode: missing.Code, Status: "404 Not Found", Body: io.NopCloser(bytes.NewReader(missing.Body.Bytes())),
	})
	if err == nil || !strings.Contains(err.Error(), "published_service_missing") || !strings.Contains(err.Error(), remote.Message) {
		t.Fatalf("parsed coordinator error=%v", err)
	}

	created := decodeConnection(t, fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "rejection-reason", TargetNode: "target", Service: "svc",
	}))
	rejected := decodeConnection(t, fixture.call(t, "target", "/v1/connections/reject", connectionIDInput{
		RequestID: created.ID, Reason: "service is under maintenance",
	}))
	if rejected.State != "rejected" || rejected.Reason != "service is under maintenance" {
		t.Fatalf("rejection=%+v", rejected)
	}
	status := decodeConnection(t, fixture.call(t, "source", "/v1/connections/status", connectionStatusWaitInput{RequestID: created.ID}))
	if status.Reason != rejected.Reason {
		t.Fatalf("source reason=%q, want %q", status.Reason, rejected.Reason)
	}
}

func TestConnectionOfferLeaseRedeliveryDecisionsAndRestartRecovery(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	created := decodeConnection(t, fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "lease", TargetNode: "target", Service: "svc",
	}))
	first := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{WaitSeconds: 1})
	var firstInbox inboxWaitResponse
	if err := json.Unmarshal(first.Body.Bytes(), &firstInbox); err != nil || len(firstInbox.Events) != 1 {
		t.Fatalf("first inbox err=%v body=%s", err, first.Body)
	}
	fixture.registry.mu.Lock()
	offered := fixture.registry.state.Connections[created.ID]
	offered.OfferLeaseEnds = time.Now().Add(-time.Second)
	fixture.registry.state.Connections[created.ID] = offered
	fixture.registry.mu.Unlock()
	second := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{
		AfterCursor: firstInbox.Cursor, WaitSeconds: 1,
	})
	var secondInbox inboxWaitResponse
	if err := json.Unmarshal(second.Body.Bytes(), &secondInbox); err != nil || len(secondInbox.Events) != 1 {
		t.Fatalf("redelivery err=%v body=%s", err, second.Body)
	}
	if secondInbox.Events[0].Cursor <= firstInbox.Events[0].Cursor {
		t.Fatal("redelivered event did not receive a new cursor")
	}
	accepted := fixture.call(t, "target", "/v1/connections/accept", connectionIDInput{RequestID: created.ID})
	if accepted.Code != http.StatusOK || decodeConnection(t, accepted).State != "accepted" {
		t.Fatalf("accept status=%d body=%s", accepted.Code, accepted.Body)
	}
	repeated := fixture.call(t, "target", "/v1/connections/accept", connectionIDInput{RequestID: created.ID})
	if repeated.Code != http.StatusOK || decodeConnection(t, repeated).State != "accepted" {
		t.Fatalf("idempotent accept status=%d body=%s", repeated.Code, repeated.Body)
	}
	reloaded, err := newRegistry(fixture.registry.path, "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.state.Connections[created.ID].State != "accepted" {
		t.Fatal("accepted request was not recovered after coordinator restart")
	}
}

func TestConnectionCancelAndExpiryAreVisibleToStatusWait(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	created := decodeConnection(t, fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "cancel", TargetNode: "target", Service: "svc",
	}))
	waitDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		waitDone <- fixture.call(t, "source", "/v1/connections/status/wait", connectionStatusWaitInput{
			RequestID: created.ID, KnownState: "queued", WaitSeconds: 2,
		})
	}()
	time.Sleep(30 * time.Millisecond)
	canceled := fixture.call(t, "source", "/v1/connections/cancel", connectionIDInput{RequestID: created.ID})
	if canceled.Code != http.StatusOK {
		t.Fatalf("cancel status=%d body=%s", canceled.Code, canceled.Body)
	}
	select {
	case status := <-waitDone:
		if got := decodeConnection(t, status); got.State != "canceled" {
			t.Fatalf("status wait state=%s", got.State)
		}
	case <-time.After(time.Second):
		t.Fatal("source status wait was not woken by cancellation")
	}

	expiring := decodeConnection(t, fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "expire", TargetNode: "target", Service: "svc",
	}))
	fixture.registry.mu.Lock()
	value := fixture.registry.state.Connections[expiring.ID]
	value.ExpiresAt = time.Now().Add(-time.Second)
	fixture.registry.state.Connections[expiring.ID] = value
	fixture.registry.mu.Unlock()
	status := fixture.call(t, "source", "/v1/connections/status", connectionStatusWaitInput{RequestID: expiring.ID})
	if got := decodeConnection(t, status); got.State != "expired" || got.StatusCode != 410 {
		t.Fatalf("expired status=%+v", got)
	}
	reloaded, err := newRegistry(fixture.registry.path, "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.state.Connections[expiring.ID]; got.State != "expired" {
		t.Fatalf("expired state was not persisted: %+v", got)
	}
	cancelExpired := fixture.call(t, "source", "/v1/connections/cancel", connectionIDInput{RequestID: expiring.ID})
	if cancelExpired.Code != http.StatusConflict {
		t.Fatalf("expired cancellation status=%d body=%s", cancelExpired.Code, cancelExpired.Body)
	}
}

func TestHeartbeatAndRevisionDiscoveryAreIndependent(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	heartbeat := func(node discoveredNode) heartbeatResponse {
		t.Helper()
		recorder := fixture.call(t, node.ID, "/v1/nodes/heartbeat", discoveryRequest{Node: node})
		if recorder.Code != http.StatusOK {
			t.Fatalf("heartbeat status=%d body=%s", recorder.Code, recorder.Body)
		}
		var output heartbeatResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &output); err != nil {
			t.Fatal(err)
		}
		return output
	}
	source := fixture.registry.state.Nodes["source"]
	first := heartbeat(source)
	second := heartbeat(source)
	if first.Revision != second.Revision {
		t.Fatalf("unchanged heartbeat advanced revision: %d -> %d", first.Revision, second.Revision)
	}
	discovery := fixture.call(t, "source", "/v1/nodes/discovery", discoverySyncRequest{AfterRevision: first.Revision})
	var unchanged discoveryResponse
	if err := json.Unmarshal(discovery.Body.Bytes(), &unchanged); err != nil || unchanged.Changed {
		t.Fatalf("unchanged discovery err=%v body=%s", err, discovery.Body)
	}
	source.Name = "renamed"
	changedHeartbeat := heartbeat(source)
	if changedHeartbeat.Revision <= second.Revision {
		t.Fatal("topology change did not advance revision")
	}
	discovery = fixture.call(t, "source", "/v1/nodes/discovery", discoverySyncRequest{AfterRevision: second.Revision})
	var changed discoveryResponse
	if err := json.Unmarshal(discovery.Body.Bytes(), &changed); err != nil || !changed.Changed {
		t.Fatalf("changed discovery err=%v body=%s", err, discovery.Body)
	}
}

func TestHeartbeatLeaseRenewalDoesNotAdvanceRevisionEveryTime(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	fixture.registry.mu.Lock()
	publisher := fixture.registry.state.Nodes["source"]
	publisher.Services = []publishedService{{
		NodeID: "source", Name: "published", Segment: "home", UUID: "uuid",
		PinnedSHA256: stringsOfHex("b"), DirectCandidates: []directCandidate{{Address: "10.0.0.2:9443"}},
	}}
	fixture.registry.state.Nodes["source"] = publisher
	fixture.registry.mu.Unlock()

	heartbeat := func() heartbeatResponse {
		t.Helper()
		recorder := fixture.call(t, "source", "/v1/nodes/heartbeat", discoveryRequest{Node: publisher})
		if recorder.Code != http.StatusOK {
			t.Fatalf("heartbeat status=%d body=%s", recorder.Code, recorder.Body)
		}
		var response heartbeatResponse
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	first, second := heartbeat(), heartbeat()
	if first.Revision != second.Revision {
		t.Fatalf("lease-only heartbeat advanced revision: %d -> %d", first.Revision, second.Revision)
	}

	fixture.registry.mu.Lock()
	stored := fixture.registry.state.Nodes["source"]
	stored.Services[0].DirectCandidates[0].ExpiresAt = time.Now().Add(directCandidateLease / 3)
	fixture.registry.state.Nodes["source"] = stored
	fixture.registry.mu.Unlock()
	third := heartbeat()
	if third.Revision <= second.Revision {
		t.Fatal("expiring direct-candidate lease did not refresh discovery")
	}
}

func TestNodeInboxClientPersistsEventBeforeAcknowledging(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	server := httptest.NewTLSServer(fixture.registry)
	defer server.Close()
	hash := sha256.Sum256(server.Certificate().Raw)
	pin := hex.EncodeToString(hash[:])
	profilePath := filepath.Join(t.TempDir(), "profile.json")
	targetCredential := fixture.credentials["target"]
	targetProfile := profile{
		Version: profileVersion, Instance: "target", Role: "client", Segment: "school",
		VirtualNetwork: "mesh", Node: nodeConfig{ID: "target", Name: "target"},
		Coordinator: coordinatorClient{
			URL: server.URL, PinnedSHA256: pin, Credential: &targetCredential,
		},
	}
	if err := saveProfile(profilePath, targetProfile); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, err := waitInbox(ctx, profilePath, targetProfile)
		result <- err
	}()
	time.Sleep(30 * time.Millisecond)
	created := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "client-cache", TargetNode: "target", Service: "svc",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	inbox, err := loadInbox(profilePath)
	if err != nil || len(inbox.Events) != 1 {
		t.Fatalf("cached inbox err=%v value=%+v", err, inbox)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(profilePath), "connection-inbox.json")); err != nil {
		t.Fatal(err)
	}
	fixture.registry.mu.Lock()
	ack := fixture.registry.state.ConnectionAcks["target"]
	fixture.registry.mu.Unlock()
	if ack != inbox.Cursor {
		t.Fatalf("server acknowledgement cursor=%d, want %d", ack, inbox.Cursor)
	}
	reloaded, err := newRegistry(fixture.registry.path, "admin", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.state.ConnectionAcks["target"] != inbox.Cursor {
		t.Fatal("acknowledgement cursor was not recovered after restart")
	}
}

func TestConnectionInboxBatchCursorDoesNotSkipRemainingEvents(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	for i := 0; i < 3; i++ {
		response := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
			IdempotencyKey: fmt.Sprintf("batch-%d", i), TargetNode: "target", Service: "svc",
		})
		if response.Code != http.StatusCreated {
			t.Fatalf("create %d status=%d body=%s", i, response.Code, response.Body)
		}
	}
	firstResponse := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{
		WaitSeconds: 1, MaxEvents: 2,
	})
	var first inboxWaitResponse
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &first); err != nil || len(first.Events) != 2 {
		t.Fatalf("first batch err=%v body=%s", err, firstResponse.Body)
	}
	secondResponse := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{
		AfterCursor: first.Cursor, WaitSeconds: 1, MaxEvents: 2,
	})
	var second inboxWaitResponse
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &second); err != nil || len(second.Events) != 1 {
		t.Fatalf("second batch err=%v body=%s", err, secondResponse.Body)
	}
	if second.Events[0].Cursor <= first.Cursor {
		t.Fatalf("remaining event cursor=%d, first cursor=%d", second.Events[0].Cursor, first.Cursor)
	}
}

func TestConnectionInboxAllowsOnlyOneWaitPerNode(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	fixture.registry.connectionWait = 2 * time.Second
	waitDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		waitDone <- fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{WaitSeconds: 2})
	}()
	deadline := time.Now().Add(time.Second)
	for {
		fixture.registry.mu.Lock()
		active := fixture.registry.inboxWaiters["target"]
		fixture.registry.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first inbox wait did not become active")
		}
		time.Sleep(time.Millisecond)
	}
	conflict := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{WaitSeconds: 1})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("second wait status=%d body=%s", conflict.Code, conflict.Body)
	}
	created := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "release-waiter", TargetNode: "target", Service: "svc",
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body)
	}
	select {
	case response := <-waitDone:
		if response.Code != http.StatusOK {
			t.Fatalf("first wait status=%d body=%s", response.Code, response.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("first wait did not finish")
	}
}

func TestConnectionInboxEmptyTimeoutIsNormal(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	fixture.registry.connectionWait = 40 * time.Millisecond
	started := time.Now()
	response := fixture.call(t, "target", "/v1/connections/inbox/wait", inboxWaitInput{})
	if response.Code != http.StatusOK {
		t.Fatalf("wait status=%d body=%s", response.Code, response.Body)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("unexpected empty wait duration %v", elapsed)
	}
	var inbox inboxWaitResponse
	if err := json.Unmarshal(response.Body.Bytes(), &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Events) != 0 {
		t.Fatalf("empty wait returned events: %+v", inbox.Events)
	}
}

func TestConnectionRequestRequiresActiveRegisteredTargetService(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	missing := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "missing", TargetNode: "target", Service: "unknown",
	})
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown service status=%d body=%s", missing.Code, missing.Body)
	}
	fixture.registry.mu.Lock()
	target := fixture.registry.state.Nodes["target"]
	target.VirtualNetwork = "other"
	fixture.registry.state.Nodes["target"] = target
	fixture.registry.mu.Unlock()
	otherNetwork := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "other-network", TargetNode: "target", Service: "svc",
	})
	if otherNetwork.Code != http.StatusNotFound {
		t.Fatalf("cross-network status=%d body=%s", otherNetwork.Code, otherNetwork.Body)
	}
}

func TestConnectionRequestValidatesReturnRelay(t *testing.T) {
	fixture := newConnectionTestRegistry(t)
	fixture.registry.mu.Lock()
	fixture.registry.state.Nodes["home-relay"] = discoveredNode{
		ID: "home-relay", Name: "home-relay", Role: "relay", Segment: "home",
		VirtualNetwork: "mesh", LastSeen: time.Now().UTC(),
		Relay: &relayAdvertisement{
			Endpoint: "relay.example:29443", PinnedSHA256: stringsOfHex("b"), Priority: 10,
		},
	}
	fixture.registry.mu.Unlock()
	valid := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "valid-return", TargetNode: "target", Service: "svc", ReturnRelay: "home-relay",
	})
	if valid.Code != http.StatusCreated {
		t.Fatalf("valid return relay status=%d body=%s", valid.Code, valid.Body)
	}
	if got := decodeConnection(t, valid); got.ReturnRelay != "home-relay" {
		t.Fatalf("return relay was not persisted: %+v", got)
	}

	fixture.registry.mu.Lock()
	relay := fixture.registry.state.Nodes["home-relay"]
	relay.Segment = "other"
	fixture.registry.state.Nodes["home-relay"] = relay
	fixture.registry.mu.Unlock()
	wrongSegment := fixture.call(t, "source", "/v1/connections/request", createConnectionInput{
		IdempotencyKey: "wrong-return", TargetNode: "target", Service: "svc", ReturnRelay: "home-relay",
	})
	if wrongSegment.Code != http.StatusBadRequest {
		t.Fatalf("wrong-segment relay status=%d body=%s", wrongSegment.Code, wrongSegment.Body)
	}
}
