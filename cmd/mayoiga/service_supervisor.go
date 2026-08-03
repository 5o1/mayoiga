package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

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
