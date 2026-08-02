package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateInstance(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"home", true},
		{"school_2", true},
		{"2nd-node", true},
		{"", false},
		{"Home", false},
		{"-home", false},
		{"home/node", false},
	}
	for _, tt := range tests {
		if got := validateInstance(tt.name) == nil; got != tt.ok {
			t.Errorf("validateInstance(%q) success = %v, want %v", tt.name, got, tt.ok)
		}
	}
}

func TestOldProfileIsRejectedWithoutMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(`{"version":3,"role":"client"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "unsupported profile version") {
		t.Fatalf("old profile was migrated or accepted: %v", err)
	}
}

func TestCoordinatorPortsAreExplicitAndCheckedAtCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "coordinator.json")
	base := options{
		instance: "control", role: "coordinator", network: "mesh", segment: "control",
		config: path, set: map[string]bool{},
	}
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "--listen is required") {
		t.Fatalf("missing public listener error=%v", err)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	base.listen = occupied.Addr().String()
	base.adminListen = freeAddress(t)
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "port conflict") {
		t.Fatalf("occupied public listener error=%v", err)
	}

	base.listen = freeAddress(t)
	base.adminListen = base.listen
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "different addresses") {
		t.Fatalf("overlapping listeners error=%v", err)
	}

	base.listen = freeAddress(t)
	base.adminListen = freeAddress(t)
	if err := install(base, path, false); err != nil {
		t.Fatalf("explicit free listeners rejected: %v", err)
	}
	p, err := loadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Server.Listen != base.listen || p.Server.AdminListen != base.adminListen {
		t.Fatalf("listeners not preserved: %#v", p.Server)
	}
}

func TestRelayPortsAndCoordinatorAreRequiredAtCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	base := options{
		instance: "relay", role: "relay", network: "mesh", segment: "home",
		config: path, set: map[string]bool{},
	}
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "--transit-listen") {
		t.Fatalf("missing relay listeners error=%v", err)
	}

	base.transitListen = freeAddress(t)
	base.transitEndpoint = "relay.example:29443"
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "must configure --coordinator") {
		t.Fatalf("missing coordinator error=%v", err)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	base.transitListen = occupied.Addr().String()
	base.coordinator = "https://coordinator.example:18443"
	base.coordinatorPin = strings.Repeat("a", 64)
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "port conflict") {
		t.Fatalf("occupied relay listener error=%v", err)
	}
}

func TestRelayCreationStoresAdmissionTokenHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	options := options{
		instance: "relay", role: "relay", network: "mesh", segment: "home", config: path,
		transitListen: freeAddress(t), transitEndpoint: "relay.example:29443",
		coordinator: "https://127.0.0.1:1", coordinatorPin: strings.Repeat("a", 64),
		set: map[string]bool{},
	}
	// Enrollment is attempted after the profile is atomically saved. The remote
	// example endpoint is intentionally unreachable; inspect the saved profile.
	_ = install(options, path, false)
	p, err := loadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !validRelayAdmissionTokenHash(p.Relay.AdmissionTokenHash) {
		t.Fatalf("relay admission token hash=%q", p.Relay.AdmissionTokenHash)
	}
}

func TestSubnodeRequiresExplicitUpstreamRelayAndCoordinator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subnode.json")
	base := options{
		instance: "offline", role: "subnode", network: "mesh", segment: "home",
		config: path, set: map[string]bool{},
	}
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "--upstream-relay-node") {
		t.Fatalf("missing upstream relay error=%v", err)
	}
	base.upstreamRelayNode = "relay-node-id"
	base.upstreamRelayEndpoint = "relay.example:29443"
	base.upstreamRelayPin = strings.Repeat("a", 64)
	base.upstreamRelayToken = "relay-admission-token"
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "must configure --coordinator") {
		t.Fatalf("missing coordinator error=%v", err)
	}
	base.upstreamRelayEndpoint = "relay.example"
	if err := install(base, path, false); err == nil || !strings.Contains(err.Error(), "upstream relay endpoint") {
		t.Fatalf("endpoint without explicit port error=%v", err)
	}
}

func TestAutomaticPullRequiresCoordinatorAndPersistsRoute(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	p := profile{
		Version: profileVersion, Instance: "client", Role: "client",
		VirtualNetwork: "mesh", Segment: "school", Node: nodeConfig{ID: "client"},
	}
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	o := options{
		name: "nas", kind: "pull", listen: freeAddress(t),
		targetNode: "home-node", service: "nas",
	}
	if err := addMapping(o, path); err == nil || !strings.Contains(err.Error(), "registered with a coordinator") {
		t.Fatalf("pull without coordinator error=%v", err)
	}

	p.Coordinator.URL = "https://coordinator.example:18443"
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	if err := addMapping(o, path); err != nil {
		t.Fatal(err)
	}
	got, err := loadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Mappings) != 1 || got.Mappings[0].TargetNode != "home-node" || got.Mappings[0].Service != "nas" {
		t.Fatalf("automatic route not persisted: %#v", got.Mappings)
	}
}

func TestPublishMappingDoesNotPersistDirectAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := saveProfile(path, profile{
		Version: profileVersion, Instance: "publisher", Role: "client",
		VirtualNetwork: "mesh", Segment: "school", Node: nodeConfig{ID: "publisher"},
	}); err != nil {
		t.Fatal(err)
	}
	o := options{
		name: "school-socks", kind: "publish", listen: freeAddress(t),
		target: "127.0.0.1:31080",
	}
	if err := addMapping(o, path); err != nil {
		t.Fatalf("publish without endpoint: %v", err)
	}
	got, err := loadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Mappings) != 1 || got.Mappings[0].Listen == "" {
		t.Fatalf("publish mapping was not persisted: %#v", got.Mappings)
	}
	body, err := json.Marshal(got.Mappings[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"endpoint"`) || strings.Contains(string(body), `"direct_candidates"`) {
		t.Fatalf("profile retained runtime direct-address state: %s", body)
	}
}

func TestMappingCreationDetectsConfiguredAndActivePortConflicts(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	reserved := freeAddress(t)
	firstPath, err := profilePathFor("", "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := saveProfile(firstPath, profile{
		Version: profileVersion, Instance: "first", Role: "client", VirtualNetwork: "mesh", Segment: "one",
		Node:     nodeConfig{ID: "first", Name: "first"},
		Mappings: []mapping{{Name: "reserved", Kind: "pull", Listen: reserved}},
	}); err != nil {
		t.Fatal(err)
	}
	secondPath := filepath.Join(t.TempDir(), "second.json")
	if err := saveProfile(secondPath, profile{
		Version: profileVersion, Instance: "second", Role: "client", VirtualNetwork: "mesh", Segment: "two",
		Node:        nodeConfig{ID: "second", Name: "second"},
		Coordinator: coordinatorClient{URL: "https://coordinator.test:443"},
	}); err != nil {
		t.Fatal(err)
	}
	base := options{
		instance: "second", config: secondPath, name: "mapping", kind: "pull",
		targetNode: "target", service: "service",
	}
	base.listen = reserved
	if err := addMapping(base, secondPath); err == nil || !strings.Contains(err.Error(), "configured listener") {
		t.Fatalf("configured conflict error=%v", err)
	}

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	base.listen = occupied.Addr().String()
	if err := addMapping(base, secondPath); err == nil || !strings.Contains(err.Error(), "port conflict") {
		t.Fatalf("active conflict error=%v", err)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestNodeCRUDWithIndependentProfiles(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")

	add := func(instance, path, role, name string) {
		t.Helper()
		o := options{
			instance: instance, role: role, nodeName: name,
			network: "family", segment: "home", config: path,
			set: map[string]bool{},
		}
		if err := install(o, path, false); err != nil {
			t.Fatalf("add %s: %v", instance, err)
		}
	}
	add("first", first, "client", "one")
	add("second", second, "gateway", "two")

	p1, err := loadProfile(first)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := loadProfile(second)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Instance != "first" || p2.Instance != "second" || p1.Node.ID == p2.Node.ID {
		t.Fatalf("profiles are not independent: %#v %#v", p1, p2)
	}

	change := options{
		instance: "first", nodeName: "renamed", config: first,
		set: map[string]bool{"node-name": true},
	}
	if err := install(change, first, true); err != nil {
		t.Fatal(err)
	}
	changed, err := loadProfile(first)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Node.Name != "renamed" || changed.Role != "client" || changed.Node.ID != p1.Node.ID {
		t.Fatalf("configure did not preserve identity and unspecified fields: %#v", changed)
	}

	if err := uninstall("first", first, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first); !os.IsNotExist(err) {
		t.Fatalf("first profile still exists: %v", err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("deleting first affected second: %v", err)
	}
}
