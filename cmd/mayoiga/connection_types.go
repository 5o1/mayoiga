package main

import "time"

const (
	connectionRequestLifetime = 2 * time.Minute
	connectionOfferLease      = 15 * time.Second
	connectionWaitMaximum     = 25 * time.Second
	maxConnectionRequests     = 10000
	maxConnectionsPerTarget   = 128
	maxInboxEvents            = 32
	maxConnectionReason       = 512
)

type connectionRequest struct {
	ID             string    `json:"id"`
	IdempotencyKey string    `json:"idempotency_key"`
	SourceNode     string    `json:"source_node"`
	TargetNode     string    `json:"target_node"`
	Service        string    `json:"service"`
	ReturnRelay    string    `json:"return_relay,omitempty"`
	State          string    `json:"state"`
	StatusCode     int       `json:"status_code"`
	Reason         string    `json:"reason,omitempty"`
	Cursor         uint64    `json:"cursor"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	OfferLeaseEnds time.Time `json:"offer_lease_ends,omitempty"`
}

type createConnectionInput struct {
	IdempotencyKey string `json:"idempotency_key"`
	TargetNode     string `json:"target_node"`
	Service        string `json:"service"`
	ReturnRelay    string `json:"return_relay,omitempty"`
}

type connectionIDInput struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason,omitempty"`
}

type inboxWaitInput struct {
	AfterCursor uint64 `json:"after_cursor"`
	WaitSeconds int    `json:"wait_seconds"`
	MaxEvents   int    `json:"max_events"`
}

type inboxWaitResponse struct {
	Cursor uint64              `json:"cursor"`
	Events []connectionRequest `json:"events"`
}

type inboxAckInput struct {
	Cursor uint64 `json:"cursor"`
}

type connectionStatusWaitInput struct {
	RequestID   string `json:"request_id"`
	KnownState  string `json:"known_state"`
	WaitSeconds int    `json:"wait_seconds"`
}
