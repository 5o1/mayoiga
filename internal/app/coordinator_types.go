package app

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	handshakeLifetime       = 10 * time.Minute
	maxPendingHandshakes    = 1024
	maxPendingPerSource     = 10
	maxHandshakeHistory     = 10000
	maxAuditEvents          = 10000
	deviceCodeAttempts      = 32
	publicRequestsPerMinute = 120
	adminRequestsPerMinute  = 120
	directCandidateLease    = 90 * time.Second
	maxDirectCandidates     = 16
	maxEnrollmentReason     = 512
)

var (
	secureRandomReader = io.Reader(rand.Reader)
	interfaceAddrs     = net.InterfaceAddrs
)

type nodeConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type nodeCredential struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type enrollmentState struct {
	RequestID  string          `json:"request_id"`
	Secret     string          `json:"secret"`
	DeviceCode string          `json:"device_code"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Status     string          `json:"status,omitempty"`
	Credential *nodeCredential `json:"credential,omitempty"`
}

type coordinatorClient struct {
	URL          string           `json:"url"`
	PinnedSHA256 string           `json:"pinned_sha256"`
	Credential   *nodeCredential  `json:"credential,omitempty"`
	Enrollment   *enrollmentState `json:"enrollment,omitempty"`
}

type coordinatorServer struct {
	Listen                      string `json:"listen"`
	AdminListen                 string `json:"admin_listen"`
	AdminToken                  string `json:"admin_token"`
	Certificate                 string `json:"certificate"`
	Key                         string `json:"key"`
	PinnedSHA256                string `json:"pinned_sha256"`
	ConnectionWaitSeconds       int    `json:"connection_wait_seconds"`
	ConnectionRequestTTLSeconds int    `json:"connection_request_ttl_seconds"`
	ConnectionOfferLeaseSeconds int    `json:"connection_offer_lease_seconds"`
	ConnectionMaxPending        int    `json:"connection_max_pending"`
}

type discoveredNode struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Role           string              `json:"role"`
	Segment        string              `json:"segment"`
	VirtualNetwork string              `json:"virtual_network"`
	IdentityKey    string              `json:"identity_key,omitempty"`
	Services       []publishedService  `json:"services,omitempty"`
	Relay          *relayAdvertisement `json:"relay,omitempty"`
	UpstreamRelay  string              `json:"upstream_relay,omitempty"`
	LastSeen       time.Time           `json:"last_seen"`
}

type publishedService struct {
	NodeID           string            `json:"node_id"`
	Name             string            `json:"name"`
	Segment          string            `json:"segment"`
	DirectCandidates []directCandidate `json:"direct_candidates,omitempty"`
	UUID             string            `json:"uuid"`
	PinnedSHA256     string            `json:"pinned_sha256"`
}

// directCandidate is generated at runtime from a publisher's local network
// interfaces.  The coordinator assigns and renews ExpiresAt; it is never read
// from a profile and is distributed only to peers in the same segment.
type directCandidate struct {
	Address   string    `json:"address"`
	ExpiresAt time.Time `json:"expires_at"`
}

type relayAdvertisement struct {
	Endpoint     string `json:"endpoint"`
	PinnedSHA256 string `json:"pinned_sha256"`
	Priority     int    `json:"priority"`
}

type discoveryRequest struct {
	Node      discoveredNode `json:"node"`
	PublicKey string         `json:"public_key,omitempty"`
}

type discoveryResponse struct {
	Revision uint64           `json:"revision"`
	Changed  bool             `json:"changed"`
	Nodes    []discoveredNode `json:"nodes,omitempty"`
}

type heartbeatResponse struct {
	Revision   uint64    `json:"revision"`
	ServerTime time.Time `json:"server_time"`
}

type discoverySyncRequest struct {
	AfterRevision uint64 `json:"after_revision"`
}

type pendingHandshake struct {
	RequestID  string         `json:"request_id"`
	SecretHash string         `json:"secret_hash"`
	DeviceCode string         `json:"device_code"`
	Node       discoveredNode `json:"node"`
	PublicKey  string         `json:"public_key"`
	Source     string         `json:"source,omitempty"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Approved   bool           `json:"approved,omitempty"`
	Rejected   bool           `json:"rejected,omitempty"`
}

type authorizedNode struct {
	PublicKey string `json:"public_key"`
}

type handshakeHistory struct {
	RequestID  string         `json:"request_id"`
	DeviceCode string         `json:"device_code"`
	Node       discoveredNode `json:"node"`
	StatusCode int            `json:"status_code"`
	Reason     string         `json:"reason,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	HandledAt  time.Time      `json:"handled_at,omitempty"`
}

type coordinatorState struct {
	Pending               map[string]pendingHandshake  `json:"pending"`
	History               map[string]handshakeHistory  `json:"history"`
	Authorized            map[string]authorizedNode    `json:"authorized"`
	Nodes                 map[string]discoveredNode    `json:"nodes"`
	Revision              uint64                       `json:"revision"`
	Connections           map[string]connectionRequest `json:"connections"`
	ConnectionIdempotency map[string]string            `json:"connection_idempotency"`
	ConnectionCursors     map[string]uint64            `json:"connection_cursors"`
	ConnectionAcks        map[string]uint64            `json:"connection_acks"`
	Audit                 []auditEvent                 `json:"audit"`
}

type auditEvent struct {
	Time      time.Time `json:"time"`
	Action    string    `json:"action"`
	NodeID    string    `json:"node_id,omitempty"`
	NodeName  string    `json:"node_name,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Source    string    `json:"source,omitempty"`
}

type registry struct {
	mu                sync.Mutex
	path              string
	adminToken        string
	network           string
	state             coordinatorState
	nonces            map[string]time.Time
	rates             map[string]rateWindow
	connectionSignals map[string]chan struct{}
	requestSignals    map[string]chan struct{}
	inboxWaiters      map[string]bool
	connectionWait    time.Duration
	connectionTTL     time.Duration
	connectionLease   time.Duration
	connectionMax     int
}

type rateWindow struct {
	Started time.Time
	Count   int
}

func newRegistry(path, adminToken, network string) (*registry, error) {
	r := &registry{
		path: path, adminToken: adminToken, network: network,
		state: coordinatorState{
			Pending: make(map[string]pendingHandshake), Authorized: make(map[string]authorizedNode),
			History: make(map[string]handshakeHistory), Nodes: make(map[string]discoveredNode),
			Connections:           make(map[string]connectionRequest),
			ConnectionIdempotency: make(map[string]string), ConnectionCursors: make(map[string]uint64),
			ConnectionAcks: make(map[string]uint64),
		},
		nonces: make(map[string]time.Time), rates: make(map[string]rateWindow),
		connectionSignals: make(map[string]chan struct{}), requestSignals: make(map[string]chan struct{}),
		inboxWaiters:   make(map[string]bool),
		connectionWait: connectionWaitMaximum, connectionTTL: connectionRequestLifetime,
		connectionLease: connectionOfferLease, connectionMax: maxConnectionRequests,
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &r.state); err != nil {
			return nil, fmt.Errorf("read coordinator state: %w", err)
		}
		if r.state.Pending == nil {
			r.state.Pending = make(map[string]pendingHandshake)
		}
		if r.state.History == nil {
			r.state.History = make(map[string]handshakeHistory)
		}
		if r.state.Authorized == nil {
			r.state.Authorized = make(map[string]authorizedNode)
		}
		if r.state.Nodes == nil {
			r.state.Nodes = make(map[string]discoveredNode)
		}
		if r.state.Connections == nil {
			r.state.Connections = make(map[string]connectionRequest)
		}
		if r.state.ConnectionIdempotency == nil {
			r.state.ConnectionIdempotency = make(map[string]string)
		}
		if r.state.ConnectionCursors == nil {
			r.state.ConnectionCursors = make(map[string]uint64)
		}
		if r.state.ConnectionAcks == nil {
			r.state.ConnectionAcks = make(map[string]uint64)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return r, nil
}
