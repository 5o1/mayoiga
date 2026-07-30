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
	"sync"
	"time"
)

const managerScanInterval = 5 * time.Second

type managedProfile struct {
	instance  string
	path      string
	role      string
	signature [sha256.Size]byte
}

type managedWorker struct {
	profile managedProfile
	cancel  context.CancelFunc
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
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		profile, err := loadProfile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mayoiga: service: skip %s: %v\n", entry.Name(), err)
			continue
		}
		profiles = append(profiles, managedProfile{
			instance: entry.Name(), path: path, role: profile.Role, signature: sha256.Sum256(body),
		})
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
	var wait sync.WaitGroup
	reconcile := func() error {
		profiles, err := managedProfiles(dir)
		if err != nil {
			return err
		}
		wanted := make(map[string]managedProfile, len(profiles))
		for _, profile := range profiles {
			wanted[profile.instance] = profile
			current, exists := workers[profile.instance]
			if exists && current.profile.signature == profile.signature {
				continue
			}
			if exists {
				current.cancel()
			}
			childContext, childCancel := context.WithCancel(ctx)
			workers[profile.instance] = managedWorker{profile: profile, cancel: childCancel}
			wait.Add(1)
			go func(profile managedProfile) {
				defer wait.Done()
				superviseProfile(childContext, profile)
			}(profile)
			if profile.role == "coordinator" {
				// Give an on-host coordinator a brief opportunity to bind
				// before dependent relay and client processes begin dialing.
				waitContext(ctx, 500*time.Millisecond)
			}
		}
		for instance, worker := range workers {
			if _, exists := wanted[instance]; !exists {
				worker.cancel()
				delete(workers, instance)
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

func superviseProfile(ctx context.Context, profile managedProfile) {
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		command := exec.CommandContext(ctx, executablePath(), "--action", "run",
			"--instance", profile.instance, "--config", profile.path)
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
