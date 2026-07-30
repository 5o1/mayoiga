package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func validateInstance(instance string) error {
	if instance == "" || len(instance) > 32 {
		return errors.New("--instance is required and must be at most 32 characters")
	}
	for i, r := range instance {
		valid := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || (i > 0 && (r == '-' || r == '_'))
		if !valid {
			return errors.New("--instance must start with a lowercase letter or digit and contain only lowercase letters, digits, '-' or '_'")
		}
	}
	return nil
}

func installNodeUnit(instance string) error {
	if err := validateInstance(instance); err != nil {
		return err
	}
	bin, err := stageManagedBinary()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	unitDir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0700); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=mayoiga node %i\nAfter=network-online.target\n\n[Service]\nExecStart=" + bin + " --action run --instance %i\nRestart=on-failure\nRestartSec=3\nNoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"
	if err := os.WriteFile(filepath.Join(unitDir, "mayoiga@.service"), []byte(unit), 0600); err != nil {
		return err
	}
	return exec.Command("systemctl", "--user", "daemon-reload").Run()
}

func listNodes() error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "nodes"))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no local nodes")
		return nil
	}
	if err != nil {
		return err
	}
	type item struct {
		instance, name, role, network, segment, auth, service string
		mappings                                              int
	}
	var items []item
	for _, entry := range entries {
		if !entry.IsDir() || validateInstance(entry.Name()) != nil {
			continue
		}
		path := filepath.Join(dir, "nodes", entry.Name(), "profile.json")
		p, err := loadProfile(path)
		if err != nil {
			continue
		}
		auth := "none"
		if p.Coordinator.Credential != nil {
			auth = "credential"
		} else if p.Coordinator.Enrollment != nil {
			auth = p.Coordinator.Enrollment.Status
			if auth == "" {
				auth = "pending"
			}
		}
		service := "manual"
		if runtime.GOOS == "linux" {
			if exec.Command("systemctl", "--user", "is-active", "--quiet", "mayoiga@"+entry.Name()+".service").Run() == nil {
				service = "active"
			} else {
				service = "inactive"
			}
		}
		items = append(items, item{entry.Name(), p.Node.Name, p.Role, p.VirtualNetwork, p.Segment, auth, service, len(p.Mappings)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].instance < items[j].instance })
	if len(items) == 0 {
		fmt.Println("no local nodes")
		return nil
	}
	fmt.Println("INSTANCE\tNAME\tROLE\tNETWORK\tSEGMENT\tAUTH\tSERVICE\tMAPPINGS")
	for _, item := range items {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\n", item.instance, item.name, item.role, item.network, item.segment, item.auth, item.service, item.mappings)
	}
	return nil
}

func configuredListenConflict(excludePath, address string) (string, bool, error) {
	dir, err := configDir()
	if err != nil {
		return "", false, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "nodes"))
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	excludePath, _ = filepath.Abs(excludePath)
	for _, entry := range entries {
		if !entry.IsDir() || validateInstance(entry.Name()) != nil {
			continue
		}
		path := filepath.Join(dir, "nodes", entry.Name(), "profile.json")
		absolute, _ := filepath.Abs(path)
		if absolute == excludePath {
			continue
		}
		p, err := loadProfile(path)
		if err != nil {
			continue
		}
		listeners := []struct {
			name    string
			address string
		}{
			{"coordinator-public", p.Server.Listen},
			{"coordinator-admin", p.Server.AdminListen},
			{"relay-transit", p.Relay.Listen},
		}
		for _, mapping := range p.Mappings {
			listeners = append(listeners, struct {
				name    string
				address string
			}{"mapping:" + mapping.Name, mapping.Listen})
		}
		for _, listener := range listeners {
			if listener.address != "" && sameListenAddress(listener.address, address) {
				return entry.Name() + "/" + listener.name, true, nil
			}
		}
	}
	return "", false, nil
}

func normalizeInstanceSuggestion(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-_")
}
