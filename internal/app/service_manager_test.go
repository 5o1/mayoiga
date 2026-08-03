package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedProfilesDiscoversValidNodes(t *testing.T) {
	configHome := t.TempDir()
	nodes := filepath.Join(configHome, "nodes")
	for _, instance := range []string{"second", "first"} {
		path := filepath.Join(nodes, instance, "profile.json")
		role := "client"
		if instance == "second" {
			role = "coordinator"
		}
		if err := saveProfile(path, profile{
			Version: profileVersion, Instance: instance, Role: role,
			Segment: "default", VirtualNetwork: "default",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(nodes, "Invalid"), 0700); err != nil {
		t.Fatal(err)
	}
	profiles, err := managedProfiles(configHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].instance != "second" || profiles[1].instance != "first" {
		t.Fatalf("unexpected profiles: %+v", profiles)
	}
	if profiles[0].signature == profiles[1].signature {
		t.Fatal("different profile contents produced the same signature")
	}
}

func TestManagedProfilesSignatureChangesWithConfiguration(t *testing.T) {
	configHome := t.TempDir()
	path := filepath.Join(configHome, "nodes", "node", "profile.json")
	p := profile{
		Version: profileVersion, Instance: "node", Role: "client",
		Segment: "default", VirtualNetwork: "default",
	}
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	before, err := managedProfiles(configHome)
	if err != nil {
		t.Fatal(err)
	}
	p.Segment = "changed"
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	after, err := managedProfiles(configHome)
	if err != nil {
		t.Fatal(err)
	}
	if before[0].signature == after[0].signature {
		t.Fatal("profile change was not detected")
	}
}

func TestSupervisorStopsOldWorkerBeforeStartingChangedProfile(t *testing.T) {
	configHome := t.TempDir()
	path := filepath.Join(configHome, "nodes", "node", "profile.json")
	p := managedTestProfile("node")
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	events, restore := managedTestRunner(t)
	defer restore()
	_, cancel, finished := startTestSupervisor(t, configHome)
	defer stopTestSupervisor(t, cancel, finished)
	first := waitManagedEvent(t, events)
	if first != "start" {
		t.Fatalf("first event=%q, want start", first)
	}
	p.Segment = "changed"
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	if event := waitManagedEvent(t, events); event != "stop" {
		t.Fatalf("configuration change event=%q, want old worker stop", event)
	}
	if event := waitManagedEvent(t, events); event != "start" {
		t.Fatalf("configuration change event=%q, want replacement start", event)
	}
}

func TestSupervisorKeepsLastValidWorkerForInvalidProfile(t *testing.T) {
	configHome := t.TempDir()
	path := filepath.Join(configHome, "nodes", "node", "profile.json")
	p := managedTestProfile("node")
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	events, restore := managedTestRunner(t)
	defer restore()
	_, cancel, finished := startTestSupervisor(t, configHome)
	defer stopTestSupervisor(t, cancel, finished)
	if event := waitManagedEvent(t, events); event != "start" {
		t.Fatalf("first event=%q, want start", event)
	}
	p.Role = "invalid"
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		t.Fatalf("invalid profile changed worker state: %q", event)
	case <-time.After(80 * time.Millisecond):
	}
	p.Role, p.Segment = "client", "recovered"
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	if event := waitManagedEvent(t, events); event != "stop" {
		t.Fatalf("recovered profile event=%q, want stop", event)
	}
	if event := waitManagedEvent(t, events); event != "start" {
		t.Fatalf("recovered profile event=%q, want start", event)
	}
}

func TestDisabledProfileStopsWorkerAndCanBeReenabled(t *testing.T) {
	configHome := t.TempDir()
	path := filepath.Join(configHome, "nodes", "node", "profile.json")
	p := managedTestProfile("node")
	p.Disabled = true
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	events, restore := managedTestRunner(t)
	defer restore()
	_, cancel, finished := startTestSupervisor(t, configHome)
	defer stopTestSupervisor(t, cancel, finished)
	select {
	case event := <-events:
		t.Fatalf("disabled profile started a worker: %q", event)
	case <-time.After(50 * time.Millisecond):
	}
	p.Disabled = false
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	if event := waitManagedEvent(t, events); event != "start" {
		t.Fatalf("reenabled profile event=%q, want start", event)
	}
	p.Disabled = true
	if err := saveProfile(path, p); err != nil {
		t.Fatal(err)
	}
	if event := waitManagedEvent(t, events); event != "stop" {
		t.Fatalf("disabled running profile event=%q, want stop", event)
	}
}

func TestSetNodeDisabledPersistsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := saveProfile(path, managedTestProfile("node")); err != nil {
		t.Fatal(err)
	}
	if err := setNodeDisabled(path, true); err != nil {
		t.Fatal(err)
	}
	got, err := loadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Disabled {
		t.Fatal("disabled state was not persisted")
	}
}

func managedTestProfile(instance string) profile {
	return profile{
		Version: profileVersion, Instance: instance, Role: "client",
		Segment: "default", VirtualNetwork: "default",
	}
}

func managedTestRunner(t *testing.T) (<-chan string, func()) {
	t.Helper()
	original := runManagedProfile
	events := make(chan string, 16)
	runManagedProfile = func(ctx context.Context, profile managedProfile) {
		events <- "start"
		<-ctx.Done()
		events <- "stop"
	}
	return events, func() { runManagedProfile = original }
}

func startTestSupervisor(t *testing.T, configHome string) (context.Context, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- superviseProfiles(ctx, configHome, 5*time.Millisecond) }()
	return ctx, cancel, finished
}

func stopTestSupervisor(t *testing.T, cancel context.CancelFunc, finished <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("supervisor returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop")
	}
}

func waitManagedEvent(t *testing.T, events <-chan string) string {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for manager event")
		return ""
	}
}
