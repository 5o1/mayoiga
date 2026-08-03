package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
