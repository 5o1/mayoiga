package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	relayHandshakeVersion = 1
	relayHandshakeLimit   = 16 << 10
	relayDialTimeout      = 5 * time.Second
	relayFailureCooldown  = 30 * time.Second
	maxCoordinatorTunnels = 32
)

// A shared cache allows TLS 1.3 tickets to be reused by the many short-lived
// reverse connections that a SOCKS proxy naturally creates. Session tickets
// remain bound to the relay certificate and are still checked by
// VerifyConnection below.
var relayClientSessions = tls.NewLRUClientSessionCache(256)

type relayHandshake struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	Network    string `json:"network"`
	SourceNode string `json:"source_node"`
	RelayNode  string `json:"relay_node"`
	TargetNode string `json:"target_node"`
	Service    string `json:"service"`
	RequestID  string `json:"request_id,omitempty"`
	RelayToken string `json:"relay_token,omitempty"`
	Timestamp  int64  `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

type connectorEntry struct {
	address  string
	instance interface{ Close() error }
}

type reverseExpectation struct {
	targetNode string
	service    string
	connection chan net.Conn
	done       chan struct{}
	cancel     sync.Once
}

type reverseConnectionBroker struct {
	mu      sync.Mutex
	waiting map[string]*reverseExpectation
}

var reverseBroker = reverseConnectionBroker{waiting: make(map[string]*reverseExpectation)}

func (b *reverseConnectionBroker) expect(requestID, targetNode, service string) (<-chan net.Conn, func()) {
	b.mu.Lock()
	expectation := &reverseExpectation{
		targetNode: targetNode, service: service, connection: make(chan net.Conn), done: make(chan struct{}),
	}
	b.waiting[requestID] = expectation
	b.mu.Unlock()
	return expectation.connection, func() {
		expectation.cancel.Do(func() {
			close(expectation.done)
			b.mu.Lock()
			if b.waiting[requestID] == expectation {
				delete(b.waiting, requestID)
			}
			b.mu.Unlock()
		})
	}
}

func (b *reverseConnectionBroker) take(requestID, targetNode, service string) (*reverseExpectation, bool) {
	b.mu.Lock()
	expectation, exists := b.waiting[requestID]
	if !exists || expectation.targetNode != targetNode || expectation.service != service {
		b.mu.Unlock()
		return nil, false
	}
	delete(b.waiting, requestID)
	b.mu.Unlock()
	return expectation, true
}

type connectorCache struct {
	mu      sync.Mutex
	entries map[string]connectorEntry
}

func newConnectorCache() *connectorCache {
	return &connectorCache{entries: make(map[string]connectorEntry)}
}

func (c *connectorCache) dial(service publishedService, upstream string) (net.Conn, error) {
	keyBytes, _ := json.Marshal(struct {
		Service  publishedService `json:"service"`
		Upstream string           `json:"upstream"`
	}{Service: service, Upstream: upstream})
	key := string(keyBytes)
	c.mu.Lock()
	entry, exists := c.entries[key]
	if !exists {
		listenAddress, err := freeLoopbackAddress()
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		internal := mapping{
			Name: "route-" + shortHash(key), Kind: "pull", Listen: listenAddress,
			Upstream: upstream, UUID: service.UUID,
			PinnedSHA256: service.PinnedSHA256,
		}
		instance, err := startMapping(internal)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		entry = connectorEntry{address: listenAddress, instance: instance}
		c.entries[key] = entry
	}
	c.mu.Unlock()
	return net.DialTimeout("tcp", entry.address, relayDialTimeout)
}

func (c *connectorCache) dialDirectCandidates(service publishedService) (net.Conn, error) {
	var lastErr error
	active := 0
	for _, candidate := range service.DirectCandidates {
		if !candidate.ExpiresAt.IsZero() && !candidate.ExpiresAt.After(time.Now()) {
			continue
		}
		active++
		if err := probePinnedTLS(candidate.Address, service.PinnedSHA256); err != nil {
			lastErr = err
			continue
		}
		connection, err := c.dial(service, candidate.Address)
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	if active == 0 {
		return nil, errors.New("published service has no active direct candidate")
	}
	return nil, fmt.Errorf("all direct candidates failed: %w", lastErr)
}

func (c *connectorCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		_ = entry.instance.Close()
		delete(c.entries, key)
	}
	return nil
}

func freeLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return address, nil
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:6])
}

type smartPull struct {
	listener net.Listener
	profile  profile
	path     string
	mapping  mapping
	cache    *connectorCache
	mu       sync.Mutex
	cooling  map[string]time.Time
}

func startSmartPull(p profile, profilePath string, m mapping) (*smartPull, error) {
	listener, err := net.Listen("tcp", m.Listen)
	if err != nil {
		return nil, err
	}
	pull := &smartPull{
		listener: listener, profile: p, path: profilePath, mapping: m,
		cache: newConnectorCache(), cooling: make(map[string]time.Time),
	}
	go pull.accept()
	return pull, nil
}

func (p *smartPull) Close() error {
	err := p.listener.Close()
	_ = p.cache.Close()
	return err
}

func (p *smartPull) accept() {
	for {
		connection, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(connection)
	}
}

func (p *smartPull) handle(application net.Conn) {
	defer application.Close()
	current, err := loadProfile(p.path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mayoiga: route profile:", err)
		return
	}
	target, service, relays, err := resolveRoute(current, p.path, p.mapping)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mayoiga: route:", err)
		return
	}
	if current.Role == "subnode" {
		upstream := discoveredNode{
			ID: current.Subnode.RelayNodeID,
			Relay: &relayAdvertisement{
				Endpoint: current.Subnode.RelayEndpoint, PinnedSHA256: current.Subnode.RelayPinnedSHA256,
			},
		}
		connection, err := dialRelay(current, upstream, p.mapping.TargetNode, p.mapping.Service)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mayoiga: upstream relay:", err)
			return
		}
		bridge(application, connection)
		return
	}
	tryDirect := current.Segment == target.Segment && target.Role != "subnode"
	if tryDirect {
		if connection, err := p.cache.dialDirectCandidates(service); err == nil {
			bridge(application, connection)
			return
		} else if len(service.DirectCandidates) > 0 {
			fmt.Fprintln(os.Stderr, "mayoiga: coordinator direct candidates unavailable:", err)
		}
	}
	candidates := routeRelayCandidates(current, target, relays)
	if len(candidates) > 0 {
		for _, relay := range candidates {
			if p.isCooling(relay.Relay.Endpoint) {
				continue
			}
			connection, err := dialRelay(current, relay, p.mapping.TargetNode, p.mapping.Service)
			if err == nil {
				bridge(application, connection)
				return
			}
			p.markFailure(relay.Relay.Endpoint)
			fmt.Fprintf(os.Stderr, "mayoiga: relay %s unavailable: %v\n", relay.ID, err)
		}
		if target.Role == "subnode" {
			fmt.Fprintln(os.Stderr, "mayoiga: target subnode upstream relay is unavailable")
			return
		}
	}
	if p.tryReverse(application, current, target, service) {
		return
	}
	fmt.Fprintln(os.Stderr, "mayoiga: coordinator direct and relay paths unavailable")
}

func (p *smartPull) tryReverse(application net.Conn, current profile, target discoveredNode, service publishedService) bool {
	if current.Role != "relay" || current.Relay.Endpoint == "" ||
		current.Coordinator.URL == "" || current.Coordinator.Credential == nil {
		return false
	}
	idempotency, err := randomToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, "mayoiga: reverse connection token:", err)
		return false
	}
	connectionReady, stopWaiting := reverseBroker.expect(idempotency, target.ID, service.Name)
	defer stopWaiting()
	request, err := createConnectionRequest(
		context.Background(), current, target.ID, service.Name, current.Node.ID, idempotency,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mayoiga: reverse connection request:", err)
		return false
	}
	wait := time.Until(request.ExpiresAt)
	if wait <= 0 {
		wait = connectionRequestLifetime
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case reverse := <-connectionReady:
		bridge(application, reverse)
		return true
	case <-timer.C:
		_, _ = decideConnectionRequest(context.Background(), current, request.ID, "cancel", "reverse connection timed out")
		fmt.Fprintf(os.Stderr, "mayoiga: reverse connection %s timed out\n", request.ID)
		return false
	}
}

func routeRelayCandidates(current profile, target discoveredNode, relays []discoveredNode) []discoveredNode {
	if target.Role == "relay" {
		if target.Relay == nil {
			return nil
		}
		return []discoveredNode{target}
	}
	return relays
}

func (p *smartPull) isCooling(endpoint string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cooling[endpoint].After(time.Now())
}

func (p *smartPull) markFailure(endpoint string) {
	p.mu.Lock()
	p.cooling[endpoint] = time.Now().Add(relayFailureCooldown)
	p.mu.Unlock()
}

func resolveRoute(local profile, profilePath string, pull mapping) (discoveredNode, publishedService, []discoveredNode, error) {
	nodes, err := loadDiscovered(profilePath)
	if err != nil {
		return discoveredNode{}, publishedService{}, nil, err
	}
	nodes = append(nodes, localDiscoveredNode(local))
	var target discoveredNode
	var service publishedService
	for _, node := range nodes {
		if node.ID != pull.TargetNode {
			continue
		}
		target = node
		for _, candidate := range node.Services {
			if candidate.Name == pull.Service {
				service = candidate
				break
			}
		}
		break
	}
	if target.ID == "" {
		return target, service, nil, fmt.Errorf("target node %q is not discovered", pull.TargetNode)
	}
	if service.Name == "" {
		return target, service, nil, fmt.Errorf("service %q is not published by node %q", pull.Service, pull.TargetNode)
	}
	var relays []discoveredNode
	for _, node := range nodes {
		if node.ID != local.Node.ID && node.Role == "relay" && node.Segment == target.Segment && node.Relay != nil {
			if target.Role == "subnode" && node.ID != target.UpstreamRelay {
				continue
			}
			relays = append(relays, node)
		}
	}
	if target.Role == "subnode" && len(relays) == 0 {
		return target, service, nil, fmt.Errorf("subnode %q upstream relay %q is not discovered", target.ID, target.UpstreamRelay)
	}
	sort.Slice(relays, func(i, j int) bool {
		if relays[i].Relay.Priority != relays[j].Relay.Priority {
			return relays[i].Relay.Priority < relays[j].Relay.Priority
		}
		return relays[i].ID < relays[j].ID
	})
	return target, service, relays, nil
}

func startRelayServer(p profile, profilePath string) (*relayServer, error) {
	certificate, err := tls.LoadX509KeyPair(p.Relay.Certificate, p.Relay.Key)
	if err != nil {
		return nil, err
	}
	listener, err := tls.Listen("tcp", p.Relay.Listen, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		return nil, err
	}
	server := &relayServer{
		listener: listener, profile: p, path: profilePath, cache: newConnectorCache(),
		nonces: make(map[string]time.Time), coordinatorTunnels: make(chan struct{}, maxCoordinatorTunnels),
	}
	go server.accept()
	return server, nil
}

type relayServer struct {
	listener           net.Listener
	profile            profile
	path               string
	cache              *connectorCache
	mu                 sync.Mutex
	nonces             map[string]time.Time
	coordinatorTunnels chan struct{}
}

func (r *relayServer) Close() error {
	err := r.listener.Close()
	_ = r.cache.Close()
	return err
}

func (r *relayServer) accept() {
	for {
		connection, err := r.listener.Accept()
		if err != nil {
			return
		}
		go r.handle(connection)
	}
}

func (r *relayServer) handle(connection net.Conn) {
	transferred := false
	defer func() {
		if !transferred {
			connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(connection, relayHandshakeLimit)
	line, err := reader.ReadString('\n')
	if err != nil || len(line) > relayHandshakeLimit {
		writeRelayError(connection, "handshake_invalid", "the relay handshake is invalid or incomplete")
		return
	}
	var handshake relayHandshake
	if json.Unmarshal([]byte(line), &handshake) != nil {
		writeRelayError(connection, "handshake_invalid", "the relay handshake is invalid JSON")
		return
	}
	if handshake.Mode == "coordinator" {
		r.handleCoordinatorTunnel(connection, reader, handshake)
		return
	}
	if !r.verify(handshake) {
		writeRelayError(connection, "source_unauthorized", "the source node signature is invalid, expired, or unknown")
		return
	}
	if !r.acceptsSourceRoute(handshake.SourceNode) {
		writeRelayError(connection, "source_route_denied", "the subnode is assigned to another upstream relay")
		return
	}
	if handshake.Mode == "reverse" {
		expectation, expected := reverseBroker.take(handshake.RequestID, handshake.SourceNode, handshake.Service)
		if handshake.RequestID == "" || !expected {
			writeRelayError(connection, "reverse_unexpected", "the reverse connection request is no longer pending")
			return
		}
		// Transfer only to a live source waiter before confirming success. The
		// publisher must not mark a coordinator request accepted merely because
		// its TCP write reached the relay kernel buffer.
		_ = connection.SetDeadline(time.Time{})
		select {
		case expectation.connection <- &bufferedConn{Conn: connection, reader: reader}:
			if _, err := io.WriteString(connection, "OK\n"); err != nil {
				return
			}
			transferred = true
		case <-expectation.done:
		}
		return
	}
	if handshake.Mode != "service" {
		writeRelayError(connection, "mode_unsupported", "the relay handshake mode is unsupported")
		return
	}
	// A NAT reverse offer is delivered through the target's independent inbox
	// worker and may take a full long-poll interval.  Keep the inbound request
	// alive for the request lifetime while the relay waits for that offer.
	_ = connection.SetDeadline(time.Now().Add(connectionRequestLifetime))
	targetNode, service, relays, err := resolveRoute(r.profile, r.path, mapping{TargetNode: handshake.TargetNode, Service: handshake.Service})
	if err != nil {
		writeRelayError(connection, "target_service_missing", "the target node or published service is unavailable")
		return
	}
	var target net.Conn
	if service.Segment == r.profile.Segment {
		if targetNode.ID == r.profile.Node.ID {
			local, exists := localPublishedService(r.profile, service.Name)
			if !exists {
				err = errors.New("relay service is not published locally")
			} else {
				target, err = r.cache.dialDirectCandidates(local)
			}
		} else {
			target, err = r.dialService(service)
		}
		if err != nil {
			target, err = r.dialReverseService(targetNode, service)
		}
	} else {
		if !r.isAuthorizedSubnodeGateway(handshake.SourceNode) {
			writeRelayError(connection, "cross_segment_denied", "this source is not authorized for cross-segment gateway routing")
			return
		}
		if targetNode.Role == "relay" {
			target, err = dialRelay(r.profile, targetNode, handshake.TargetNode, handshake.Service)
		} else {
			for _, candidate := range relays {
				target, err = dialRelay(r.profile, candidate, handshake.TargetNode, handshake.Service)
				if err == nil {
					break
				}
			}
		}
		if target == nil {
			target, err = r.dialService(service)
		}
		if target == nil {
			target, err = r.dialReverseService(targetNode, service)
		}
	}
	if err != nil {
		writeRelayError(connection, "target_unavailable", "no authenticated path to the target service is currently available")
		return
	}
	defer target.Close()
	if _, err := io.WriteString(connection, "OK\n"); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	bridgeReaders(reader, connection, target)
}

func (r *relayServer) dialService(service publishedService) (net.Conn, error) {
	return r.cache.dialDirectCandidates(service)
}

// dialReverseService asks the publisher to connect back to this relay.  The
// relay therefore never needs the publisher's LAN or public address.  The
// request id binds the authenticated reverse handshake to this exact target
// service and the expectation is removed on timeout or cancellation.
func (r *relayServer) dialReverseService(target discoveredNode, service publishedService) (net.Conn, error) {
	if r.profile.Coordinator.URL == "" || r.profile.Coordinator.Credential == nil {
		return nil, errors.New("coordinator credential is unavailable for reverse service")
	}
	idempotency, err := randomToken()
	if err != nil {
		return nil, fmt.Errorf("generate reverse connection token: %w", err)
	}
	connectionReady, stopWaiting := reverseBroker.expect(idempotency, target.ID, service.Name)
	defer stopWaiting()
	request, err := createConnectionRequest(
		context.Background(), r.profile, target.ID, service.Name, r.profile.Node.ID, idempotency,
	)
	if err != nil {
		return nil, fmt.Errorf("request reverse service connection: %w", err)
	}
	wait := time.Until(request.ExpiresAt)
	if wait <= 0 {
		wait = connectionRequestLifetime
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case connection := <-connectionReady:
		if connection == nil {
			return nil, errors.New("reverse service connection closed")
		}
		return connection, nil
	case <-timer.C:
		_, _ = decideConnectionRequest(context.Background(), r.profile, request.ID, "cancel", "reverse service connection timed out")
		return nil, errors.New("reverse service connection timed out")
	}
}

func (r *relayServer) isAuthorizedSubnodeGateway(sourceNode string) bool {
	nodes, err := loadDiscovered(r.path)
	if err != nil {
		return false
	}
	for _, node := range nodes {
		if node.ID != sourceNode {
			continue
		}
		return node.Role == "subnode" && node.Segment == r.profile.Segment && node.UpstreamRelay == r.profile.Node.ID
	}
	return false
}

func (r *relayServer) acceptsSourceRoute(sourceNode string) bool {
	nodes, err := loadDiscovered(r.path)
	if err != nil {
		return false
	}
	for _, node := range nodes {
		if node.ID != sourceNode {
			continue
		}
		return node.Role != "subnode" ||
			(node.Segment == r.profile.Segment && node.UpstreamRelay == r.profile.Node.ID)
	}
	return false
}

func (r *relayServer) handleCoordinatorTunnel(connection net.Conn, reader *bufio.Reader, handshake relayHandshake) {
	if handshake.Version != relayHandshakeVersion || handshake.Network != r.profile.VirtualNetwork ||
		handshake.RelayNode != r.profile.Node.ID || handshake.SourceNode == "" ||
		!r.acceptsCoordinatorTunnel(handshake) ||
		r.profile.Coordinator.URL == "" {
		writeRelayError(connection, "coordinator_tunnel_unauthorized", "the relay admission token is missing, invalid, or not assigned to this subnode")
		return
	}
	select {
	case r.coordinatorTunnels <- struct{}{}:
		defer func() { <-r.coordinatorTunnels }()
	default:
		writeRelayError(connection, "coordinator_tunnel_busy", "the relay has reached its coordinator tunnel capacity; retry shortly")
		return
	}
	coordinatorURL, err := url.Parse(r.profile.Coordinator.URL)
	if err != nil || coordinatorURL.Host == "" {
		writeRelayError(connection, "coordinator_tunnel_unavailable", "the relay has no valid upstream coordinator configuration")
		return
	}
	upstream, err := net.DialTimeout("tcp", coordinatorURL.Host, relayDialTimeout)
	if err != nil {
		writeRelayError(connection, "coordinator_unavailable", "the relay cannot reach its configured coordinator")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(connection, "OK\n"); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	bridgeReaders(reader, connection, upstream)
}

// acceptsCoordinatorTunnel permits only a holder of the relay-local admission
// token to use the otherwise opaque coordinator tunnel. A pending subnode is
// not in discovery yet, so an unknown source node is allowed only during its
// credential enrollment; a known source must already be this relay's subnode.
func (r *relayServer) acceptsCoordinatorTunnel(handshake relayHandshake) bool {
	if !relayAdmissionTokenMatches(r.profile.Relay.AdmissionTokenHash, handshake.RelayToken) {
		return false
	}
	nodes, err := loadDiscovered(r.path)
	if err != nil {
		return false
	}
	for _, node := range nodes {
		if node.ID != handshake.SourceNode {
			continue
		}
		return node.Role == "subnode" && node.Segment == r.profile.Segment && node.UpstreamRelay == r.profile.Node.ID
	}
	return true
}

func relayAdmissionTokenHash(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func validRelayAdmissionTokenHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func relayAdmissionTokenMatches(expectedHash, token string) bool {
	expected, err := hex.DecodeString(expectedHash)
	if err != nil || len(expected) != sha256.Size || strings.TrimSpace(token) == "" {
		return false
	}
	actual, err := hex.DecodeString(relayAdmissionTokenHash(token))
	return err == nil && subtle.ConstantTimeCompare(expected, actual) == 1
}

func (r *relayServer) verify(handshake relayHandshake) bool {
	if handshake.Version != relayHandshakeVersion || handshake.Network != r.profile.VirtualNetwork ||
		handshake.SourceNode == "" || handshake.RelayNode != r.profile.Node.ID ||
		handshake.TargetNode == "" || handshake.Service == "" ||
		handshake.Nonce == "" || handshake.Signature == "" {
		return false
	}
	now := time.Now()
	sent := time.Unix(handshake.Timestamp, 0)
	if sent.Before(now.Add(-2*time.Minute)) || sent.After(now.Add(2*time.Minute)) {
		return false
	}
	nodes, err := loadDiscovered(r.path)
	if err != nil {
		return false
	}
	var publicText string
	for _, node := range nodes {
		if node.ID == handshake.SourceNode {
			publicText = node.IdentityKey
			break
		}
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(publicText)
	signature, signatureErr := base64.RawStdEncoding.DecodeString(handshake.Signature)
	if err != nil || signatureErr != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), relayHandshakeMessage(handshake), signature) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for nonce, expiry := range r.nonces {
		if expiry.Before(now) {
			delete(r.nonces, nonce)
		}
	}
	if expiry := r.nonces[handshake.Nonce]; expiry.After(now) {
		return false
	}
	r.nonces[handshake.Nonce] = now.Add(2 * time.Minute)
	return true
}

func dialRelay(local profile, relay discoveredNode, targetNode, service string) (net.Conn, error) {
	return dialSignedRelay(local, relay, "service", targetNode, service, "")
}

func dialReverseRelay(local profile, relay discoveredNode, requestID, service string) (net.Conn, error) {
	return dialSignedRelay(local, relay, "reverse", local.Node.ID, service, requestID)
}

func dialSignedRelay(local profile, relay discoveredNode, mode, targetNode, service, requestID string) (net.Conn, error) {
	if relay.Relay == nil || local.Coordinator.Credential == nil {
		return nil, errors.New("relay or node credential is unavailable")
	}
	config, err := pinnedTLSConfig(relay.Relay.PinnedSHA256)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", relay.Relay.Endpoint, config)
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		connection.Close()
		return nil, err
	}
	handshake := relayHandshake{
		Version: relayHandshakeVersion, Mode: mode, Network: local.VirtualNetwork, SourceNode: local.Node.ID,
		RelayNode: relay.ID, TargetNode: targetNode, Service: service, RequestID: requestID,
		Timestamp: time.Now().Unix(), Nonce: nonce,
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(local.Coordinator.Credential.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		connection.Close()
		return nil, errors.New("invalid local node credential")
	}
	handshake.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(privateKey), relayHandshakeMessage(handshake)))
	body, _ := json.Marshal(handshake)
	if _, err := connection.Write(append(body, '\n')); err != nil {
		connection.Close()
		return nil, err
	}
	_ = connection.SetReadDeadline(time.Now().Add(relayDialTimeout))
	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	if err != nil || response != "OK\n" {
		connection.Close()
		if err == nil {
			err = relayResponseError(response)
		}
		return nil, err
	}
	_ = connection.SetReadDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func dialCoordinatorViaRelay(ctx context.Context, network, nodeID string, subnode subnodeConfig) (net.Conn, error) {
	config, err := pinnedTLSConfig(subnode.RelayPinnedSHA256)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", subnode.RelayEndpoint, config)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	body, _ := json.Marshal(relayHandshake{
		Version: relayHandshakeVersion, Mode: "coordinator", Network: network, SourceNode: nodeID,
		RelayNode: subnode.RelayNodeID, RelayToken: subnode.RelayToken,
	})
	if _, err := connection.Write(append(body, '\n')); err != nil {
		connection.Close()
		return nil, err
	}
	reader := bufio.NewReader(connection)
	response, err := reader.ReadString('\n')
	if err != nil || response != "OK\n" {
		connection.Close()
		if err == nil {
			err = relayResponseError(response)
		}
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return &bufferedConn{Conn: connection, reader: reader}, nil
}

func relayHandshakeMessage(handshake relayHandshake) []byte {
	fields := []string{
		strconv.Itoa(handshake.Version), handshake.Mode, handshake.Network, handshake.SourceNode,
		handshake.RelayNode, handshake.TargetNode, handshake.Service,
		strconv.FormatInt(handshake.Timestamp, 10), handshake.Nonce,
	}
	if handshake.Mode == "reverse" {
		fields = append(fields, handshake.RequestID)
	}
	return []byte(strings.Join(fields, "\n"))
}

func probePinnedTLS(endpoint, pin string) error {
	config, err := pinnedTLSConfig(pin)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", endpoint, config)
	if err == nil {
		err = connection.Close()
	}
	return err
}

func pinnedTLSConfig(pinText string) (*tls.Config, error) {
	pin, err := hex.DecodeString(normalizePin(pinText))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("certificate pin must be 64 hexadecimal characters")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec -- exact pin below.
		ClientSessionCache: relayClientSessions,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("peer sent no certificate")
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

func writeRelayError(writer io.Writer, code, message string) {
	_, _ = io.WriteString(writer, "ERR "+code+" "+message+"\n")
}

func relayResponseError(response string) error {
	response = strings.TrimSpace(response)
	parts := strings.SplitN(response, " ", 3)
	if len(parts) == 3 && parts[0] == "ERR" && strings.Contains(parts[1], "_") {
		return fmt.Errorf("relay %s: %s", parts[1], localizedError(parts[1], parts[2]))
	}
	return fmt.Errorf("relay request rejected: %s", response)
}

func bridge(left, right net.Conn) {
	defer right.Close()
	bridgeReaders(left, left, right)
}

func bridgeReaders(leftReader io.Reader, left net.Conn, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(right, leftReader)
		closeWrite(right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(left, right)
		closeWrite(left)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(connection net.Conn) {
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func (c *bufferedConn) CloseWrite() error {
	if halfCloser, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}
