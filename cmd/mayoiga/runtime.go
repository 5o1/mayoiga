package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func runProfile(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	instances := make([]interface{ Close() error }, 0, len(p.Mappings))
	for _, m := range p.Mappings {
		var instance interface{ Close() error }
		if m.Kind == "pull" && m.TargetNode != "" {
			instance, err = startSmartPull(p, path, m)
		} else {
			instance, err = startMapping(m)
		}
		if err != nil {
			for _, running := range instances {
				_ = running.Close()
			}
			return err
		}
		instances = append(instances, instance)
	}
	defer func() {
		for _, instance := range instances {
			_ = instance.Close()
		}
	}()
	if p.Role == "relay" {
		relay, err := startRelayServer(p, path)
		if err != nil {
			return err
		}
		instances = append(instances, relay)
	}
	var coordinator *coordinatorRuntime
	var coordinatorErrors <-chan error
	if p.Role == "coordinator" {
		coordinator, coordinatorErrors, err = startCoordinator(path, p)
		if err != nil {
			return err
		}
		defer coordinator.Shutdown(context.Background())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if p.Coordinator.URL != "" {
		go runControlPlane(ctx, path)
	}
	ch := make(chan os.Signal, 1)
	signalNotify(ch)
	select {
	case <-ch:
		return nil
	case err := <-coordinatorErrors:
		return err
	}
}

func signalNotify(ch chan os.Signal) { signalNotifyPlatform(ch) }

func status(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	peers, _ := loadDiscovered(path)
	auth := "none"
	if p.Coordinator.Credential != nil {
		auth = "credential"
	} else if p.Coordinator.Enrollment != nil {
		auth = p.Coordinator.Enrollment.Status
		if auth == "" {
			auth = "pending"
		}
	}
	upstream := "-"
	if p.Role == "subnode" {
		upstream = p.Subnode.RelayNodeID + "@" + p.Subnode.RelayEndpoint
	}
	fmt.Printf("instance=%s role=%s network=%s segment=%s mappings=%d peers=%d coordinator=%s auth=%s upstream_relay=%s config=%s\n", p.Instance, p.Role, p.VirtualNetwork, p.Segment, len(p.Mappings), len(peers), p.Coordinator.URL, auth, upstream, path)
	if control, controlErr := loadControlStatus(path); controlErr == nil {
		fmt.Printf("heartbeat_last_ok=%s heartbeat_error=%q discovery_last_ok=%s discovery_revision=%d discovery_error=%q inbox_last_ok=%s inbox_cursor=%d inbox_waiting=%t inbox_error=%q\n",
			formatStatusTime(control.HeartbeatLastOK), control.HeartbeatError,
			formatStatusTime(control.DiscoveryLastOK), control.DiscoveryRevision, control.DiscoveryError,
			formatStatusTime(control.InboxLastOK), control.InboxCursor, control.InboxWaiting, control.InboxError)
	}
	return nil
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(time.RFC3339)
}
func start(instance, path string, managed bool) error {
	if !managed {
		return errors.New("--action start requires a managed node; use --action run for a foreground custom profile")
	}
	if err := setNodeDisabled(path, false); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return errors.New("start the rootless manager with --action service-run on this platform")
	}
	return controlManagerService("start")
}
func stop(path string, managed bool) error {
	if !managed {
		return errors.New("--action stop requires a managed node; stop a foreground custom profile from its invoking process")
	}
	return setNodeDisabled(path, true)
}

func setNodeDisabled(path string, disabled bool) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	if p.Disabled == disabled {
		return nil
	}
	p.Disabled = disabled
	return saveProfile(path, p)
}
func uninstall(instance, path string, managed bool) error {
	if managed {
		return os.RemoveAll(filepath.Dir(path))
	}
	return os.Remove(path)
}
