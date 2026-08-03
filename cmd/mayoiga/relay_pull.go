package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

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
