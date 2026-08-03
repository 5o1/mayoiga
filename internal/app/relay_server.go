package app

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
	"strings"
	"sync"
	"time"
)

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
		if !r.isAuthorizedSubnodeRelay(handshake.SourceNode) {
			writeRelayError(connection, "cross_segment_denied", "this source is not authorized for cross-segment relay routing")
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

func (r *relayServer) isAuthorizedSubnodeRelay(sourceNode string) bool {
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
