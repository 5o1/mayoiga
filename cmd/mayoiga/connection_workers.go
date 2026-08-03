package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type controlPlaneStatus struct {
	HeartbeatLastOK   time.Time `json:"heartbeat_last_ok,omitempty"`
	HeartbeatError    string    `json:"heartbeat_error,omitempty"`
	DiscoveryLastOK   time.Time `json:"discovery_last_ok,omitempty"`
	DiscoveryError    string    `json:"discovery_error,omitempty"`
	DiscoveryRevision uint64    `json:"discovery_revision"`
	InboxLastOK       time.Time `json:"inbox_last_ok,omitempty"`
	InboxError        string    `json:"inbox_error,omitempty"`
	InboxCursor       uint64    `json:"inbox_cursor"`
	InboxWaiting      bool      `json:"inbox_waiting"`
}

var controlStatusMu sync.Mutex

func loadControlStatus(profilePath string) (controlPlaneStatus, error) {
	body, err := os.ReadFile(filepath.Join(filepath.Dir(profilePath), "control-status.json"))
	if errors.Is(err, os.ErrNotExist) {
		return controlPlaneStatus{}, nil
	}
	var status controlPlaneStatus
	if err != nil {
		return status, err
	}
	return status, json.Unmarshal(body, &status)
}

func updateControlStatus(profilePath string, update func(*controlPlaneStatus)) error {
	controlStatusMu.Lock()
	defer controlStatusMu.Unlock()
	status, _ := loadControlStatus(profilePath)
	update(&status)
	body, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(filepath.Dir(profilePath), "control-status.json")
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(body, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func runControlPlane(ctx context.Context, profilePath string) {
	for {
		p, err := loadProfile(profilePath)
		if err != nil {
			return
		}
		if p.Coordinator.URL == "" {
			return
		}
		if p.Coordinator.Credential == nil {
			approved, pollErr := pollEnrollment(ctx, profilePath, &p)
			if pollErr != nil {
				fmt.Fprintln(os.Stderr, "mayoiga: enrollment poll:", pollErr)
			}
			if !approved {
				if !waitContext(ctx, 5*time.Second) {
					return
				}
				continue
			}
		}
		runAuthenticatedControlPlane(ctx, profilePath, p)
		return
	}
}

func runAuthenticatedControlPlane(ctx context.Context, profilePath string, p profile) {
	revisions := make(chan uint64, 1)
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		runHeartbeatWorker(ctx, profilePath, p, revisions)
	}()
	go func() {
		defer workers.Done()
		runDiscoveryWorker(ctx, profilePath, p, revisions)
	}()
	go func() {
		defer workers.Done()
		runInboxWorker(ctx, profilePath, p)
	}()
	workers.Wait()
}

func runHeartbeatWorker(ctx context.Context, profilePath string, p profile, revisions chan uint64) {
	for {
		revision, err := sendHeartbeat(ctx, p)
		now := time.Now().UTC()
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			if err != nil {
				status.HeartbeatError = err.Error()
			} else {
				status.HeartbeatLastOK, status.HeartbeatError = now, ""
			}
		})
		if err == nil {
			select {
			case revisions <- revision:
			default:
				select {
				case <-revisions:
				default:
				}
				select {
				case revisions <- revision:
				default:
				}
			}
		} else if ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "mayoiga: heartbeat:", err)
		}
		if !waitContext(ctx, 30*time.Second) {
			return
		}
	}
}

func runDiscoveryWorker(ctx context.Context, profilePath string, p profile, revisions <-chan uint64) {
	status, _ := loadControlStatus(profilePath)
	current := status.DiscoveryRevision
	for {
		select {
		case <-ctx.Done():
			return
		case revision := <-revisions:
			if revision == current {
				continue
			}
			_, err := fetchDiscovery(ctx, profilePath, p, current, revision)
			now := time.Now().UTC()
			_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
				if err != nil {
					status.DiscoveryError = err.Error()
				} else {
					current = revision
					status.DiscoveryRevision = revision
					status.DiscoveryLastOK, status.DiscoveryError = now, ""
				}
			})
			if err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "mayoiga: discovery:", err)
			}
		}
	}
}

func runInboxWorker(ctx context.Context, profilePath string, p profile) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			status.InboxWaiting = true
		})
		output, err := waitInbox(ctx, profilePath, p)
		now := time.Now().UTC()
		_ = updateControlStatus(profilePath, func(status *controlPlaneStatus) {
			status.InboxWaiting = false
			if err != nil {
				status.InboxError = err.Error()
			} else {
				status.InboxLastOK, status.InboxError = now, ""
				if output.Cursor > status.InboxCursor {
					status.InboxCursor = output.Cursor
				}
			}
		})
		if err == nil {
			dispatchAutomaticConnectionOffers(ctx, profilePath, p, output.Events)
			backoff = time.Second
			continue
		}
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintln(os.Stderr, "mayoiga: connection inbox:", err)
		if !waitContext(ctx, backoff) {
			return
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

var automaticConnectionOffers sync.Map

func dispatchAutomaticConnectionOffers(ctx context.Context, profilePath string, p profile, events []connectionRequest) {
	for _, event := range events {
		if event.TargetNode != p.Node.ID || event.ReturnRelay == "" {
			continue
		}
		if _, loaded := automaticConnectionOffers.LoadOrStore(event.ID, struct{}{}); loaded {
			continue
		}
		go func(event connectionRequest) {
			defer automaticConnectionOffers.Delete(event.ID)
			if err := serveAutomaticConnectionOffer(ctx, profilePath, p, event); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "mayoiga: reverse connection %s: %v\n", event.ID, err)
			}
		}(event)
	}
}

func serveAutomaticConnectionOffer(ctx context.Context, profilePath string, p profile, event connectionRequest) error {
	target, exists := localPublishedTarget(p, event.Service)
	if !exists {
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "published service is not local")
		return fmt.Errorf("service %q is not published locally", event.Service)
	}
	nodes, err := loadDiscovered(profilePath)
	if err != nil {
		return err
	}
	var relay discoveredNode
	for _, node := range nodes {
		if node.ID == event.ReturnRelay && node.Role == "relay" && node.Relay != nil {
			relay = node
			break
		}
	}
	if relay.ID == "" {
		return fmt.Errorf("return relay %q is not discovered", event.ReturnRelay)
	}
	// The reverse connection is already mutually authenticated and encrypted by
	// dialReverseRelay.  Re-entering the local VLESS listener here used to add a
	// second TLS handshake and a short-lived embedded Xray instance for every
	// connection.  The receiving node owns this mapping, so it can safely dial
	// the configured local target directly.
	local, err := net.DialTimeout("tcp", target, relayDialTimeout)
	if err != nil {
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "local published target is unavailable")
		return fmt.Errorf("connect local published target %q: %w", target, err)
	}
	reverse, err := dialReverseRelay(p, relay, event.IdempotencyKey, event.Service)
	if err != nil {
		local.Close()
		_, _ = decideConnectionRequest(ctx, p, event.ID, "reject", "return relay is unavailable")
		return fmt.Errorf("connect return relay: %w", err)
	}
	if _, err := decideConnectionRequest(ctx, p, event.ID, "accept", ""); err != nil {
		reverse.Close()
		local.Close()
		return err
	}
	_ = removeInboxRequest(profilePath, event.ID)
	go func() {
		defer local.Close()
		bridge(reverse, local)
	}()
	return nil
}

func localPublishedTarget(p profile, name string) (string, bool) {
	for _, mapping := range p.Mappings {
		if mapping.Kind == "publish" && mapping.Name == name && validateHostPort(mapping.Target) == nil {
			return mapping.Target, true
		}
	}
	return "", false
}

func localPublishedService(p profile, name string) (publishedService, bool) {
	node := localDiscoveredNode(p)
	for _, service := range node.Services {
		if service.Name != name {
			continue
		}
		for _, mapping := range p.Mappings {
			if mapping.Kind == "publish" && mapping.Name == name {
				service.DirectCandidates = []directCandidate{{Address: loopbackEndpoint(mapping.Listen)}}
				return service, true
			}
		}
	}
	return publishedService{}, false
}

func loopbackEndpoint(endpoint string) string {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
