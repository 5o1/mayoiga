package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func install(o options, path string, configure bool) error {
	if configure {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("node instance %q does not exist", o.instance)
		}
	} else if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("node instance %q already exists; use configure-node", o.instance)
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	p.Instance = o.instance
	if !configure || o.set["role"] {
		p.Role = o.role
	}
	if p.Role == "" {
		return errors.New("--role is required")
	}
	switch p.Role {
	case "client", "gateway", "relay", "subnode", "coordinator":
	default:
		return errors.New("--role must be client, gateway, relay, subnode, or coordinator")
	}
	if !configure || o.set["segment"] {
		p.Segment = o.segment
	}
	if !configure || o.set["network"] {
		p.VirtualNetwork = o.network
	}
	if strings.TrimSpace(p.VirtualNetwork) == "" || strings.TrimSpace(p.Segment) == "" {
		return errors.New("--network and --segment cannot be empty")
	}
	if p.Node.ID == "" {
		p.Node.ID, err = randomUUID()
		if err != nil {
			return fmt.Errorf("generate node id: %w", err)
		}
	}
	if !configure || o.set["node-name"] {
		p.Node.Name = o.nodeName
		if p.Node.Name == "" {
			p.Node.Name, _ = os.Hostname()
		}
	}
	needsEnrollment := false
	generatedRelayToken := ""
	if p.Role == "coordinator" && (!configure || o.set["listen"] || o.set["admin-listen"] ||
		o.set["connection-wait-seconds"] || o.set["connection-request-ttl-seconds"] ||
		o.set["connection-offer-lease-seconds"] || o.set["connection-max-pending"] ||
		p.Server.AdminToken == "") {
		if configure && !o.set["listen"] {
			o.listen = p.Server.Listen
		}
		if o.listen == "" {
			return errors.New("--listen is required for a coordinator")
		}
		if err := validateHostPort(o.listen); err != nil {
			return fmt.Errorf("invalid coordinator public listen address: %w", err)
		}
		p.Server.Listen = o.listen
		if !configure || o.set["admin-listen"] || p.Server.AdminListen == "" {
			p.Server.AdminListen = o.adminListen
			if p.Server.AdminListen == "" {
				return errors.New("--admin-listen is required for a coordinator")
			}
			if err := validateAdminListen(p.Server.AdminListen); err != nil {
				return err
			}
		}
		if sameListenAddress(p.Server.Listen, p.Server.AdminListen) {
			return errors.New("--listen and --admin-listen must use different addresses")
		}
		if configure && !o.set["connection-wait-seconds"] {
			o.connectionWaitSeconds = p.Server.ConnectionWaitSeconds
		}
		if configure && !o.set["connection-request-ttl-seconds"] {
			o.connectionTTLSeconds = p.Server.ConnectionRequestTTLSeconds
		}
		if configure && !o.set["connection-offer-lease-seconds"] {
			o.connectionLeaseSeconds = p.Server.ConnectionOfferLeaseSeconds
		}
		if configure && !o.set["connection-max-pending"] {
			o.connectionMaxPending = p.Server.ConnectionMaxPending
		}
		if o.connectionWaitSeconds == 0 {
			o.connectionWaitSeconds = int(connectionWaitMaximum / time.Second)
		}
		if o.connectionTTLSeconds == 0 {
			o.connectionTTLSeconds = int(connectionRequestLifetime / time.Second)
		}
		if o.connectionLeaseSeconds == 0 {
			o.connectionLeaseSeconds = int(connectionOfferLease / time.Second)
		}
		if o.connectionMaxPending == 0 {
			o.connectionMaxPending = maxConnectionRequests
		}
		if o.connectionWaitSeconds < 1 || o.connectionWaitSeconds > 120 ||
			o.connectionTTLSeconds < 10 || o.connectionTTLSeconds > 3600 ||
			o.connectionLeaseSeconds < 1 || o.connectionLeaseSeconds >= o.connectionTTLSeconds ||
			o.connectionMaxPending < 1 || o.connectionMaxPending > 100000 {
			return errors.New("invalid connection control limits")
		}
		p.Server.ConnectionWaitSeconds = o.connectionWaitSeconds
		p.Server.ConnectionRequestTTLSeconds = o.connectionTTLSeconds
		p.Server.ConnectionOfferLeaseSeconds = o.connectionLeaseSeconds
		p.Server.ConnectionMaxPending = o.connectionMaxPending
		if !configure {
			if owner, conflict, err := configuredListenConflict(path, p.Server.Listen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("coordinator public port conflicts with configured listener %s", owner)
			}
			if owner, conflict, err := configuredListenConflict(path, p.Server.AdminListen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("coordinator admin port conflicts with configured listener %s", owner)
			}
			if err := checkListenAvailable(p.Server.Listen); err != nil {
				return fmt.Errorf("coordinator public port conflict at %s: %w", p.Server.Listen, err)
			}
			if err := checkListenAvailable(p.Server.AdminListen); err != nil {
				return fmt.Errorf("coordinator admin port conflict at %s: %w", p.Server.AdminListen, err)
			}
		}
		if p.Server.AdminToken == "" {
			p.Server.AdminToken, err = randomToken()
			if err != nil {
				return fmt.Errorf("generate coordinator admin token: %w", err)
			}
		}
		if p.Server.Certificate == "" {
			dir := filepath.Dir(path)
			p.Server.Certificate, p.Server.Key = filepath.Join(dir, "coordinator.crt"), filepath.Join(dir, "coordinator.key")
			pin, err := makeCertificate(p.Server.Certificate, p.Server.Key)
			if err != nil {
				return err
			}
			p.Server.PinnedSHA256 = pin
		}
		fmt.Printf("COORDINATOR_PIN=%s\n", p.Server.PinnedSHA256)
	}
	if o.rotateRelayToken && p.Role != "relay" {
		return errors.New("--rotate-relay-token requires a relay node")
	}
	if p.Role == "relay" {
		if configure && !o.set["transit-listen"] {
			o.transitListen = p.Relay.Listen
		}
		if configure && !o.set["transit-endpoint"] {
			o.transitEndpoint = p.Relay.Endpoint
		}
		if o.transitListen == "" || o.transitEndpoint == "" {
			return errors.New("--transit-listen and --transit-endpoint are required for a relay node")
		}
		if err := validateHostPort(o.transitListen); err != nil {
			return fmt.Errorf("invalid relay transit listen address: %w", err)
		}
		if err := validateHostPort(o.transitEndpoint); err != nil {
			return fmt.Errorf("invalid relay transit endpoint: %w", err)
		}
		p.Relay.Listen, p.Relay.Endpoint = o.transitListen, o.transitEndpoint
		if !configure || o.set["relay-priority"] {
			p.Relay.Priority = o.relayPriority
		}
		if p.Relay.Priority < 0 {
			return errors.New("--relay-priority cannot be negative")
		}
		if !configure {
			if owner, conflict, err := configuredListenConflict(path, p.Relay.Listen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("relay transit port conflicts with configured listener %s", owner)
			}
			if err := checkListenAvailable(p.Relay.Listen); err != nil {
				return fmt.Errorf("relay transit port conflict at %s: %w", p.Relay.Listen, err)
			}
		}
		if p.Relay.Certificate == "" {
			dir := filepath.Dir(path)
			p.Relay.Certificate, p.Relay.Key = filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
			pin, err := makeCertificate(p.Relay.Certificate, p.Relay.Key)
			if err != nil {
				return err
			}
			p.Relay.PinnedSHA256 = pin
		}
		if o.rotateRelayToken || p.Relay.AdmissionTokenHash == "" {
			generatedRelayToken, err = randomToken()
			if err != nil {
				return fmt.Errorf("generate relay admission token: %w", err)
			}
			p.Relay.AdmissionTokenHash = relayAdmissionTokenHash(generatedRelayToken)
		} else if !validRelayAdmissionTokenHash(p.Relay.AdmissionTokenHash) {
			return errors.New("relay admission token configuration is invalid")
		}
		fmt.Printf("RELAY_PIN=%s\n", p.Relay.PinnedSHA256)
	} else if configure && o.set["role"] {
		p.Relay = relayConfig{}
	}
	if p.Role == "subnode" {
		if configure && !o.set["upstream-relay-node"] {
			o.upstreamRelayNode = p.Subnode.RelayNodeID
		}
		if configure && !o.set["upstream-relay-endpoint"] {
			o.upstreamRelayEndpoint = p.Subnode.RelayEndpoint
		}
		if configure && !o.set["upstream-relay-pin"] {
			o.upstreamRelayPin = p.Subnode.RelayPinnedSHA256
		}
		if configure && !o.set["upstream-relay-token"] {
			o.upstreamRelayToken = p.Subnode.RelayToken
		}
		if o.upstreamRelayNode == "" || o.upstreamRelayEndpoint == "" || o.upstreamRelayPin == "" || o.upstreamRelayToken == "" {
			return errors.New("--upstream-relay-node, --upstream-relay-endpoint, --upstream-relay-pin, and --upstream-relay-token are required for a subnode")
		}
		if err := validateHostPort(o.upstreamRelayEndpoint); err != nil {
			return fmt.Errorf("invalid upstream relay endpoint: %w", err)
		}
		if !validSHA256Pin(o.upstreamRelayPin) {
			return errors.New("--upstream-relay-pin must be 64 hexadecimal characters")
		}
		p.Subnode = subnodeConfig{
			RelayNodeID: o.upstreamRelayNode, RelayEndpoint: o.upstreamRelayEndpoint,
			RelayPinnedSHA256: normalizePin(o.upstreamRelayPin), RelayToken: strings.TrimSpace(o.upstreamRelayToken),
		}
	} else if configure && o.set["role"] {
		p.Subnode = subnodeConfig{}
	}
	if o.set["coordinator"] || (!configure && o.coordinator != "") {
		if o.coordinator == "" {
			p.Coordinator = coordinatorClient{}
		} else {
			if o.coordinatorPin == "" {
				return errors.New("--coordinator-pin is required with --coordinator")
			}
			if err := validateCoordinatorURL(o.coordinator); err != nil {
				return err
			}
			origin, pin := strings.TrimRight(o.coordinator, "/"), normalizePin(o.coordinatorPin)
			needsEnrollment = p.Coordinator.URL != origin || p.Coordinator.PinnedSHA256 != pin || p.Coordinator.Credential == nil
			if p.Coordinator.URL != origin || p.Coordinator.PinnedSHA256 != pin {
				p.Coordinator = coordinatorClient{URL: origin, PinnedSHA256: pin}
			}
		}
	}
	if p.Role == "relay" && p.Coordinator.URL == "" {
		return errors.New("a relay node must configure --coordinator and --coordinator-pin")
	}
	if p.Role == "subnode" && p.Coordinator.URL == "" {
		return errors.New("a subnode must configure --coordinator and --coordinator-pin")
	}
	if err := saveProfile(path, p); err != nil {
		return err
	}
	if generatedRelayToken != "" {
		fmt.Printf("SUBNODE_RELAY_TOKEN=%s\n", generatedRelayToken)
	}
	if needsEnrollment {
		if err := requestEnrollment(context.Background(), path, &p); err != nil {
			return fmt.Errorf("create coordinator handshake: %w", err)
		}
	}
	if runtime.GOOS == "linux" && o.config == "" {
		if err := ensureManagerService(); err != nil {
			return err
		}
		fmt.Printf("node %s saved and enabled; run: mayoiga --action service-start\n", o.instance)
	} else {
		fmt.Printf("node %s saved\n", o.instance)
	}
	return nil
}

func addMapping(o options, path string) error {
	if o.name == "" || o.listen == "" {
		return errors.New("--name and --listen are required")
	}
	if o.kind != "pull" && o.kind != "publish" {
		return errors.New("--kind must be pull or publish; relay capability belongs to a relay node")
	}
	if o.kind == "publish" {
		if o.target == "" {
			return errors.New("--target is required for publish")
		}
		if err := validateHostPort(o.target); err != nil {
			return fmt.Errorf("invalid publish target address: %w", err)
		}
	} else if o.targetNode == "" || o.service == "" {
		return errors.New("--target-node and --service are required for pull")
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	if o.kind == "pull" && p.Coordinator.URL == "" {
		return errors.New("an automatic pull requires the node to be registered with a coordinator")
	}
	for _, x := range p.Mappings {
		if x.Name == o.name {
			return errors.New("mapping name already exists")
		}
		if sameListenAddress(x.Listen, o.listen) {
			return fmt.Errorf("--listen conflicts with mapping %q in node %q", x.Name, p.Instance)
		}
	}
	if err := validateHostPort(o.listen); err != nil {
		return fmt.Errorf("invalid mapping listen address: %w", err)
	}
	if owner, conflict, err := configuredListenConflict(path, o.listen); err != nil {
		return err
	} else if conflict {
		return fmt.Errorf("--listen conflicts with configured listener %s", owner)
	}
	if err := checkListenAvailable(o.listen); err != nil {
		return fmt.Errorf("mapping port conflict at %s: %w", o.listen, err)
	}
	m := mapping{
		Name: o.name, Kind: o.kind, Listen: o.listen, Target: o.target,
		TargetNode: o.targetNode, Service: o.service,
	}
	if o.kind == "publish" {
		m.UUID, err = randomUUID()
		if err != nil {
			return fmt.Errorf("generate publish UUID: %w", err)
		}
		dir := filepath.Dir(path)
		m.Certificate = filepath.Join(dir, o.name+".crt")
		m.Key = filepath.Join(dir, o.name+".key")
		pin, err := makeCertificate(m.Certificate, m.Key)
		if err != nil {
			return err
		}
		m.CertificateSHA256 = pin
		fmt.Printf("UUID=%s\nPIN_SHA256=%s\n", m.UUID, pin)
	}
	p.Mappings = append(p.Mappings, m)
	return saveProfile(path, p)
}

func removeMapping(name, path string) error {
	if name == "" {
		return errors.New("--name is required")
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	out := p.Mappings[:0]
	found := false
	for _, m := range p.Mappings {
		if m.Name == name {
			found = true
			continue
		}
		out = append(out, m)
	}
	if !found {
		return errors.New("mapping not found")
	}
	p.Mappings = out
	return saveProfile(path, p)
}

func renderFile(path, output string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	b, err := renderXray(p)
	if err != nil {
		return err
	}
	if output == "" {
		os.Stdout.Write(b)
		return nil
	}
	return os.WriteFile(output, b, 0600)
}
