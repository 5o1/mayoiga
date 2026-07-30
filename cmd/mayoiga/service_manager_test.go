package main

import (
	"os"
	"path/filepath"
	"testing"
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
