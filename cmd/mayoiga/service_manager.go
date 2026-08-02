package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const managerScanInterval = 5 * time.Second

const (
	managerGracefulStop = 10 * time.Second
	managerStopTimeout  = 15 * time.Second
)

type managedProfile struct {
	instance  string
	path      string
	role      string
	signature [sha256.Size]byte
	disabled  bool
	err       error
}

type managedWorker struct {
	profile managedProfile
	cancel  context.CancelFunc
	done    <-chan struct{}
}

func managedProfiles(dir string) ([]managedProfile, error) {
	if dir == "" {
		var err error
		dir, err = configDir()
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		dir, err = filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "nodes"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var profiles []managedProfile
	for _, entry := range entries {
		if !entry.IsDir() || validateInstance(entry.Name()) != nil {
			continue
		}
		path := filepath.Join(dir, "nodes", entry.Name(), "profile.json")
		body, readErr := os.ReadFile(path)
		candidate := managedProfile{
			instance: entry.Name(), path: path, signature: sha256.Sum256(body),
		}
		if readErr != nil {
			candidate.err = fmt.Errorf("read profile: %w", readErr)
			profiles = append(profiles, candidate)
			continue
		}
		profile, loadErr := loadProfile(path)
		if loadErr != nil {
			candidate.err = loadErr
			profiles = append(profiles, candidate)
			continue
		}
		candidate.role, candidate.disabled = profile.Role, profile.Disabled
		if profile.Instance != entry.Name() {
			candidate.err = fmt.Errorf("profile instance %q does not match directory", profile.Instance)
		} else {
			candidate.err = validateManagedProfile(profile)
		}
		profiles = append(profiles, candidate)
	}
	sort.Slice(profiles, func(i, j int) bool {
		left, right := serviceRoleOrder(profiles[i].role), serviceRoleOrder(profiles[j].role)
		if left != right {
			return left < right
		}
		return profiles[i].instance < profiles[j].instance
	})
	return profiles, nil
}

func validateManagedProfile(p profile) error {
	if p.Disabled {
		return nil
	}
	if err := validateInstance(p.Instance); err != nil {
		return err
	}
	switch p.Role {
	case "client", "gateway", "relay", "subnode", "coordinator":
	default:
		return fmt.Errorf("invalid node role %q", p.Role)
	}
	if strings.TrimSpace(p.VirtualNetwork) == "" || strings.TrimSpace(p.Segment) == "" {
		return errors.New("virtual network and segment are required")
	}
	if p.Coordinator.URL != "" {
		if err := validateCoordinatorURL(p.Coordinator.URL); err != nil {
			return err
		}
		if !validSHA256Pin(p.Coordinator.PinnedSHA256) {
			return errors.New("coordinator certificate pin is invalid")
		}
	}
	if err := validateManagedMappings(p); err != nil {
		return err
	}
	if err := validateManagedListenerConflicts(p); err != nil {
		return err
	}
	switch p.Role {
	case "coordinator":
		if err := validateHostPort(p.Server.Listen); err != nil {
			return fmt.Errorf("coordinator listen: %w", err)
		}
		if err := validateAdminListen(p.Server.AdminListen); err != nil {
			return err
		}
		if sameListenAddress(p.Server.Listen, p.Server.AdminListen) {
			return errors.New("coordinator public and admin listeners conflict")
		}
		if p.Server.AdminToken == "" || !validSHA256Pin(p.Server.PinnedSHA256) {
			return errors.New("coordinator credentials are incomplete")
		}
		if err := validateManagedFile("coordinator certificate", p.Server.Certificate); err != nil {
			return err
		}
		return validateManagedFile("coordinator key", p.Server.Key)
	case "relay":
		if p.Coordinator.URL == "" {
			return errors.New("relay requires a coordinator")
		}
		if err := validateHostPort(p.Relay.Listen); err != nil {
			return fmt.Errorf("relay listen: %w", err)
		}
		if err := validateHostPort(p.Relay.Endpoint); err != nil {
			return fmt.Errorf("relay endpoint: %w", err)
		}
		if p.Relay.Priority < 0 || !validSHA256Pin(p.Relay.PinnedSHA256) ||
			(p.Relay.AdmissionTokenHash != "" && !validRelayAdmissionTokenHash(p.Relay.AdmissionTokenHash)) {
			return errors.New("relay configuration is invalid")
		}
		if err := validateManagedFile("relay certificate", p.Relay.Certificate); err != nil {
			return err
		}
		return validateManagedFile("relay key", p.Relay.Key)
	case "subnode":
		if p.Coordinator.URL == "" || p.Subnode.RelayNodeID == "" || p.Subnode.RelayToken == "" {
			return errors.New("subnode requires a coordinator, upstream relay node, and relay admission token")
		}
		if err := validateHostPort(p.Subnode.RelayEndpoint); err != nil {
			return fmt.Errorf("subnode upstream relay endpoint: %w", err)
		}
		if !validSHA256Pin(p.Subnode.RelayPinnedSHA256) {
			return errors.New("subnode upstream relay pin is invalid")
		}
	}
	return nil
}

func validateManagedMappings(p profile) error {
	names := make(map[string]struct{}, len(p.Mappings))
	for _, m := range p.Mappings {
		if m.Name == "" {
			return errors.New("mapping name is required")
		}
		if _, exists := names[m.Name]; exists {
			return fmt.Errorf("mapping name %q is duplicated", m.Name)
		}
		names[m.Name] = struct{}{}
		if err := validateHostPort(m.Listen); err != nil {
			return fmt.Errorf("mapping %q listen: %w", m.Name, err)
		}
		switch m.Kind {
		case "publish":
			if err := validateHostPort(m.Target); err != nil {
				return fmt.Errorf("publish mapping %q target: %w", m.Name, err)
			}
			if m.UUID == "" || !validSHA256Pin(m.CertificateSHA256) {
				return fmt.Errorf("publish mapping %q credentials are incomplete", m.Name)
			}
			if err := validateManagedFile("publish certificate", m.Certificate); err != nil {
				return err
			}
			if err := validateManagedFile("publish key", m.Key); err != nil {
				return err
			}
		case "pull":
			if m.TargetNode != "" {
				if m.Service == "" {
					return fmt.Errorf("automatic pull mapping %q service is required", m.Name)
				}
				continue
			}
			if err := validateHostPort(m.Upstream); err != nil {
				return fmt.Errorf("pull mapping %q upstream: %w", m.Name, err)
			}
			if m.UUID == "" || !validSHA256Pin(m.PinnedSHA256) {
				return fmt.Errorf("pull mapping %q credentials are incomplete", m.Name)
			}
		default:
			return fmt.Errorf("mapping %q kind %q is invalid", m.Name, m.Kind)
		}
	}
	return nil
}

func validateManagedListenerConflicts(p profile) error {
	listeners := make([]string, 0, len(p.Mappings)+3)
	if p.Role == "coordinator" {
		listeners = append(listeners, p.Server.Listen, p.Server.AdminListen)
	}
	if p.Role == "relay" {
		listeners = append(listeners, p.Relay.Listen)
	}
	for _, mapping := range p.Mappings {
		listeners = append(listeners, mapping.Listen)
	}
	for i, left := range listeners {
		for _, right := range listeners[i+1:] {
			if left != "" && right != "" && sameListenAddress(left, right) {
				return fmt.Errorf("configured listeners %q and %q conflict", left, right)
			}
		}
	}
	return nil
}

func validateManagedFile(label, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required", label)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", label)
	}
	return nil
}

func serviceRoleOrder(role string) int {
	switch role {
	case "coordinator":
		return 0
	case "relay":
		return 1
	default:
		return 2
	}
}

func runManagerService(dir string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan os.Signal, 1)
	signalNotify(signals)
	go func() {
		<-signals
		cancel()
	}()
	return superviseProfiles(ctx, dir, managerScanInterval)
}

func superviseProfiles(ctx context.Context, dir string, interval time.Duration) error {
	workers := make(map[string]managedWorker)
	rejected := make(map[string][sha256.Size]byte)
	var wait sync.WaitGroup
	reconcile := func() error {
		profiles, err := managedProfiles(dir)
		if err != nil {
			return err
		}
		wanted := make(map[string]managedProfile, len(profiles))
		for _, profile := range profiles {
			wanted[profile.instance] = profile
		}
		for instance, worker := range workers {
			if _, exists := wanted[instance]; !exists {
				if stopManagedWorker(ctx, worker) {
					delete(workers, instance)
				}
			}
		}
		for _, profile := range profiles {
			current, exists := workers[profile.instance]
			if profile.err != nil {
				if previous, logged := rejected[profile.instance]; !logged || previous != profile.signature {
					fmt.Fprintf(os.Stderr, "mayoiga: service: retain %s with last valid configuration: %v\n", profile.instance, profile.err)
					rejected[profile.instance] = profile.signature
				}
				continue
			}
			delete(rejected, profile.instance)
			if profile.disabled {
				if exists && stopManagedWorker(ctx, current) {
					delete(workers, profile.instance)
				}
				continue
			}
			if exists && current.profile.signature == profile.signature && !managedWorkerDone(current) {
				continue
			}
			if exists && !stopManagedWorker(ctx, current) {
				continue
			}
			if exists {
				delete(workers, profile.instance)
			}
			workers[profile.instance] = startManagedWorker(ctx, profile, &wait)
			if profile.role == "coordinator" {
				// Give an on-host coordinator a brief opportunity to bind
				// before dependent relay and client processes begin dialing.
				if !waitContext(ctx, 500*time.Millisecond) {
					return nil
				}
			}
		}
		return nil
	}
	if err := reconcile(); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, worker := range workers {
				worker.cancel()
			}
			wait.Wait()
			return nil
		case <-ticker.C:
			if err := reconcile(); err != nil {
				fmt.Fprintln(os.Stderr, "mayoiga: service scan:", err)
			}
		}
	}
}

func managedWorkerDone(worker managedWorker) bool {
	select {
	case <-worker.done:
		return true
	default:
		return false
	}
}

func stopManagedWorker(ctx context.Context, worker managedWorker) bool {
	worker.cancel()
	timer := time.NewTimer(managerStopTimeout)
	defer timer.Stop()
	select {
	case <-worker.done:
		return true
	case <-ctx.Done():
		return false
	case <-timer.C:
		fmt.Fprintf(os.Stderr, "mayoiga: service: node %s did not stop within %s\n", worker.profile.instance, managerStopTimeout)
		return false
	}
}

var runManagedProfile = superviseProfile

func startManagedWorker(parent context.Context, profile managedProfile, wait *sync.WaitGroup) managedWorker {
	childContext, childCancel := context.WithCancel(parent)
	done := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		defer close(done)
		runManagedProfile(childContext, profile)
	}()
	return managedWorker{profile: profile, cancel: childCancel, done: done}
}

func superviseProfile(ctx context.Context, profile managedProfile) {
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		command := exec.CommandContext(ctx, executablePath(), "--action", "run",
			"--instance", profile.instance, "--config", profile.path)
		command.Cancel = func() error {
			return command.Process.Signal(os.Interrupt)
		}
		command.WaitDelay = managerGracefulStop
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		err := command.Run()
		if ctx.Err() != nil {
			return
		}
		fmt.Fprintf(os.Stderr, "mayoiga: service: node %s exited: %v; restart in %s\n",
			profile.instance, err, delay)
		if time.Since(started) >= time.Minute {
			delay = time.Second
		}
		if !waitContext(ctx, delay) {
			return
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

var executablePath = func() string {
	path, err := os.Executable()
	if err != nil {
		return "mayoiga"
	}
	return path
}

func stageManagedBinary() (string, error) {
	source, err := os.Open(executablePath())
	if err != nil {
		return "", err
	}
	defer source.Close()
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "bin", executableName())
	if err := os.MkdirAll(filepath.Dir(bin), 0700); err != nil {
		return "", err
	}
	staged := bin + ".new"
	target, err := os.OpenFile(staged, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil {
		_ = os.Remove(staged)
		return "", copyErr
	}
	if closeErr != nil {
		_ = os.Remove(staged)
		return "", closeErr
	}
	if err := os.Rename(staged, bin); err != nil {
		_ = os.Remove(staged)
		return "", err
	}
	return bin, nil
}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "mayoiga.exe"
	}
	return "mayoiga"
}
