package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

func (r *registry) registerNode(w http.ResponseWriter, req *http.Request) {
	_, nodes, revision, ok := r.updateNode(w, req)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: true, Nodes: nodes})
}

func (r *registry) heartbeatNode(w http.ResponseWriter, req *http.Request) {
	_, _, revision, ok := r.updateNode(w, req)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, heartbeatResponse{Revision: revision, ServerTime: time.Now().UTC()})
}

func (r *registry) updateNode(w http.ResponseWriter, req *http.Request) (discoveredNode, []discoveredNode, uint64, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 64<<10))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return discoveredNode{}, nil, 0, false
	}
	nodeID := req.Header.Get("X-Mayoiga-Node")
	r.mu.Lock()
	authorized, ok := r.state.Authorized[nodeID]
	if !ok || !r.verifySignatureLocked(req, body, authorized.PublicKey) {
		r.mu.Unlock()
		http.Error(w, "invalid node signature", http.StatusUnauthorized)
		return discoveredNode{}, nil, 0, false
	}
	if !r.allowRequestLocked("node:"+nodeID, publicRequestsPerMinute, time.Now().UTC()) {
		r.mu.Unlock()
		http.Error(w, "node rate limit exceeded", http.StatusTooManyRequests)
		return discoveredNode{}, nil, 0, false
	}
	var input discoveryRequest
	if err := json.Unmarshal(body, &input); err != nil || input.Node.ID != nodeID {
		r.mu.Unlock()
		http.Error(w, "invalid JSON or node id", http.StatusBadRequest)
		return discoveredNode{}, nil, 0, false
	}
	n := input.Node
	if n.Name == "" || n.VirtualNetwork != r.network {
		r.mu.Unlock()
		http.Error(w, "virtual network is not allowed", http.StatusForbidden)
		return discoveredNode{}, nil, 0, false
	}
	n.IdentityKey = authorized.PublicKey
	now := time.Now().UTC()
	for i := range n.Services {
		service := &n.Services[i]
		service.NodeID, service.Segment = n.ID, n.Segment
		candidates, candidateErr := managedDirectCandidates(service.DirectCandidates, now.Add(directCandidateLease))
		if service.Name == "" || service.UUID == "" || candidateErr != nil || !validSHA256Pin(service.PinnedSHA256) {
			r.mu.Unlock()
			http.Error(w, "invalid published service", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
		service.DirectCandidates = candidates
	}
	if n.Role == "relay" {
		if n.Relay == nil || validateHostPort(n.Relay.Endpoint) != nil || !validSHA256Pin(n.Relay.PinnedSHA256) || n.Relay.Priority < 0 {
			r.mu.Unlock()
			http.Error(w, "invalid relay advertisement", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
	} else {
		n.Relay = nil
	}
	if n.Role == "subnode" {
		if n.UpstreamRelay == "" {
			r.mu.Unlock()
			http.Error(w, "subnode has no upstream relay", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
		upstream, exists := r.state.Nodes[n.UpstreamRelay]
		if !exists || upstream.Role != "relay" || upstream.Segment != n.Segment ||
			upstream.VirtualNetwork != n.VirtualNetwork {
			r.mu.Unlock()
			http.Error(w, "subnode upstream is not an active relay in the same segment", http.StatusBadRequest)
			return discoveredNode{}, nil, 0, false
		}
	} else {
		n.UpstreamRelay = ""
	}
	old, existed := r.state.Nodes[n.ID]
	n.LastSeen = now
	r.state.Nodes[n.ID] = n
	if !existed || !sameNodeTopology(old, n) || directCandidateRenewalDue(old, now) {
		r.state.Revision++
	}
	for id, pending := range r.state.Pending {
		if pending.Node.ID == n.ID && pending.Approved && pending.PublicKey == authorized.PublicKey {
			delete(r.state.Pending, id)
			history := r.state.History[id]
			history.StatusCode = 201
			history.HandledAt = now
			r.state.History[id] = history
			r.appendAuditLocked(auditEvent{
				Action: "enrollment_completed", NodeID: n.ID, NodeName: n.Name, RequestID: id,
				Source: requestSource(req),
			})
		}
	}
	r.cleanupLocked(now)
	nodes := make([]discoveredNode, 0)
	for _, candidate := range r.state.Nodes {
		if candidate.VirtualNetwork == n.VirtualNetwork && candidate.ID != n.ID {
			nodes = append(nodes, nodeForDiscovery(n, candidate))
		}
	}
	persistErr := r.persistLocked()
	revision := r.state.Revision
	r.mu.Unlock()
	if persistErr != nil {
		http.Error(w, "failed to persist registry", http.StatusInternalServerError)
		return discoveredNode{}, nil, 0, false
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return n, nodes, revision, true
}

func sameNodeTopology(left, right discoveredNode) bool {
	left, right = topologyWithoutLeases(left), topologyWithoutLeases(right)
	leftBody, _ := json.Marshal(left)
	rightBody, _ := json.Marshal(right)
	return bytes.Equal(leftBody, rightBody)
}

// Direct-candidate lease expiry is coordinator-managed liveness metadata, not
// topology. Heartbeats renew it frequently; comparing its exact value here
// would force a discovery revision and full peer rewrite on every heartbeat.
func topologyWithoutLeases(node discoveredNode) discoveredNode {
	node.LastSeen = time.Time{}
	node.Services = append([]publishedService(nil), node.Services...)
	for serviceIndex := range node.Services {
		candidates := append([]directCandidate(nil), node.Services[serviceIndex].DirectCandidates...)
		for candidateIndex := range candidates {
			candidates[candidateIndex].ExpiresAt = time.Time{}
		}
		node.Services[serviceIndex].DirectCandidates = candidates
	}
	return node
}

// Peers must learn a renewed lease before their cached direct candidate
// expires. Refresh only in the latter half of the 90-second lease instead of
// on every 30-second heartbeat.
func directCandidateRenewalDue(node discoveredNode, now time.Time) bool {
	refreshAt := now.Add(directCandidateLease / 2)
	for _, service := range node.Services {
		for _, candidate := range service.DirectCandidates {
			if !candidate.ExpiresAt.IsZero() && !candidate.ExpiresAt.After(refreshAt) {
				return true
			}
		}
	}
	return false
}

func managedDirectCandidates(input []directCandidate, expiry time.Time) ([]directCandidate, error) {
	if len(input) > maxDirectCandidates {
		return nil, fmt.Errorf("too many direct candidates")
	}
	seen := make(map[string]struct{}, len(input))
	output := make([]directCandidate, 0, len(input))
	for _, candidate := range input {
		if err := validateDirectCandidate(candidate.Address); err != nil {
			return nil, err
		}
		if _, exists := seen[candidate.Address]; exists {
			continue
		}
		seen[candidate.Address] = struct{}{}
		output = append(output, directCandidate{Address: candidate.Address, ExpiresAt: expiry})
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Address < output[j].Address })
	return output, nil
}

func validateDirectCandidate(address string) error {
	if err := validateHostPort(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("direct candidate must use a private unicast IP address")
	}
	return nil
}

// nodeForDiscovery keeps direct candidates in the coordinator's state but
// only releases them to peers in the same logical segment.  Cross-segment
// access always resolves a relay path instead of learning LAN addresses.
func nodeForDiscovery(requester, candidate discoveredNode) discoveredNode {
	if requester.Segment == candidate.Segment {
		return candidate
	}
	output := candidate
	output.Services = append([]publishedService(nil), candidate.Services...)
	for i := range output.Services {
		output.Services[i].DirectCandidates = nil
	}
	return output
}

func (r *registry) discoverNodes(w http.ResponseWriter, req *http.Request) {
	body, nodeID, ok := r.authenticatedConnectionBody(w, req)
	if !ok {
		return
	}
	var input discoverySyncRequest
	if json.Unmarshal(body, &input) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.cleanupLocked(time.Now().UTC())
	node, exists := r.state.Nodes[nodeID]
	if !exists {
		r.mu.Unlock()
		http.Error(w, "node must heartbeat before discovery", http.StatusConflict)
		return
	}
	revision := r.state.Revision
	if input.AfterRevision == revision {
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: false})
		return
	}
	nodes := make([]discoveredNode, 0, len(r.state.Nodes))
	for _, candidate := range r.state.Nodes {
		if candidate.VirtualNetwork == node.VirtualNetwork && candidate.ID != nodeID {
			nodes = append(nodes, nodeForDiscovery(node, candidate))
		}
	}
	r.mu.Unlock()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	writeJSON(w, http.StatusOK, discoveryResponse{Revision: revision, Changed: true, Nodes: nodes})
}

func (r *registry) verifySignatureLocked(req *http.Request, body []byte, publicText string) bool {
	timestampText, nonce, signatureText := req.Header.Get("X-Mayoiga-Time"), req.Header.Get("X-Mayoiga-Nonce"), req.Header.Get("X-Mayoiga-Signature")
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || nonce == "" || signatureText == "" {
		return false
	}
	now := time.Now().UTC()
	sent := time.Unix(timestamp, 0)
	if sent.Before(now.Add(-2*time.Minute)) || sent.After(now.Add(2*time.Minute)) {
		return false
	}
	if expiry, exists := r.nonces[nonce]; exists && expiry.After(now) {
		return false
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(publicText)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureText)
	if err != nil {
		return false
	}
	message := signedMessage(req.Method, req.URL.Path, timestampText, nonce, body)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return false
	}
	r.nonces[nonce] = now.Add(2 * time.Minute)
	return true
}

func signedMessage(method, path, timestamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(h[:]))
}

func (r *registry) cleanupLocked(now time.Time) bool {
	changed := false
	for id, pending := range r.state.Pending {
		if pending.ExpiresAt.Before(now) {
			changed = true
			delete(r.state.Pending, id)
			history := r.state.History[id]
			if history.StatusCode == 100 || history.StatusCode == 200 {
				history.StatusCode = 410
				history.HandledAt = now
				r.state.History[id] = history
				r.appendAuditLocked(auditEvent{
					Action: "enrollment_expired", NodeID: pending.Node.ID, NodeName: pending.Node.Name,
					RequestID: id,
				})
			}
		}
	}
	for id, node := range r.state.Nodes {
		if node.LastSeen.Before(now.Add(-2 * time.Minute)) {
			changed = true
			delete(r.state.Nodes, id)
			r.state.Revision++
			continue
		}
		candidatesChanged := false
		for serviceIndex := range node.Services {
			service := &node.Services[serviceIndex]
			active := service.DirectCandidates[:0]
			for _, candidate := range service.DirectCandidates {
				if candidate.ExpiresAt.After(now) {
					active = append(active, candidate)
				}
			}
			if len(active) != len(service.DirectCandidates) {
				service.DirectCandidates = active
				candidatesChanged = true
			}
		}
		if candidatesChanged {
			changed = true
			r.state.Nodes[id] = node
			r.state.Revision++
		}
	}
	for id, connection := range r.state.Connections {
		switch {
		case !connectionTerminal(connection.State) && connection.ExpiresAt.Before(now):
			changed = true
			connection.State, connection.StatusCode, connection.Reason = "expired", 410, "request expired"
			connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
			r.state.Connections[id] = connection
			r.notifyTargetLocked(connection.TargetNode)
			r.notifyRequestLocked(id)
		case connection.State == "offered" && !connection.OfferLeaseEnds.IsZero() && connection.OfferLeaseEnds.Before(now):
			changed = true
			r.state.ConnectionCursors[connection.TargetNode]++
			connection.State, connection.StatusCode = "queued", 100
			connection.Cursor = r.state.ConnectionCursors[connection.TargetNode]
			connection.UpdatedAt, connection.OfferLeaseEnds = now, time.Time{}
			r.state.Connections[id] = connection
			r.notifyTargetLocked(connection.TargetNode)
			r.notifyRequestLocked(id)
		case connectionTerminal(connection.State) && connection.UpdatedAt.Before(now.Add(-24*time.Hour)):
			changed = true
			delete(r.state.Connections, id)
			delete(r.state.ConnectionIdempotency, connection.SourceNode+"\x00"+connection.IdempotencyKey)
			delete(r.requestSignals, id)
		}
	}
	for nonce, expiry := range r.nonces {
		if expiry.Before(now) {
			delete(r.nonces, nonce)
		}
	}
	if len(r.state.History) > maxHandshakeHistory {
		changed = true
		items := make([]handshakeHistory, 0, len(r.state.History))
		for _, history := range r.state.History {
			items = append(items, history)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
		for _, history := range items[:len(items)-maxHandshakeHistory] {
			delete(r.state.History, history.RequestID)
		}
	}
	return changed
}

func (r *registry) appendAuditLocked(event auditEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	r.state.Audit = append(r.state.Audit, event)
	if len(r.state.Audit) > maxAuditEvents {
		r.state.Audit = append([]auditEvent(nil), r.state.Audit[len(r.state.Audit)-maxAuditEvents:]...)
	}
}

func (r *registry) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
