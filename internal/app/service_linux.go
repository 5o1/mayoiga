//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func ensureManagerService() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	unit := filepath.Join(home, ".config", "systemd", "user", "mayoiga.service")
	if _, err := os.Stat(unit); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return installManagerService()
}

func installManagerService() error {
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
	unit := "[Unit]\nDescription=mayoiga node manager\nAfter=network-online.target\n\n" +
		"[Service]\nExecStart=" + bin + " --action service-run\nRestart=always\nRestartSec=3\n" +
		"NoNewPrivileges=true\nPrivateTmp=true\n\n[Install]\nWantedBy=default.target\n"
	if err := os.WriteFile(filepath.Join(unitDir, "mayoiga.service"), []byte(unit), 0600); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("systemctl --user daemon-reload: %w", err)
	}
	return nil
}

func controlManagerService(action string) error {
	if action == "start" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		if err := retireLegacyNodeServices(filepath.Join(home, ".config", "systemd", "user")); err != nil {
			return err
		}
		if err := exec.Command("systemctl", "--user", "daemon-reload").Run(); err != nil {
			return fmt.Errorf("reload systemd after retiring legacy services: %w", err)
		}
	}
	args := []string{"--user"}
	if action == "start" {
		args = append(args, "enable", "--now", "mayoiga.service")
	} else {
		args = append(args, action, "mayoiga.service")
	}
	return exec.Command("systemctl", args...).Run()
}

func retireLegacyNodeServices(unitDir string) error {
	dir, err := configDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "nodes"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || validateInstance(entry.Name()) != nil {
			continue
		}
		unit := "mayoiga@" + entry.Name() + ".service"
		enabled := exec.Command("systemctl", "--user", "is-enabled", "--quiet", unit).Run() == nil
		active := exec.Command("systemctl", "--user", "is-active", "--quiet", unit).Run() == nil
		if enabled || active {
			if err := exec.Command("systemctl", "--user", "disable", "--now", unit).Run(); err != nil {
				return fmt.Errorf("disable legacy node service %s: %w", entry.Name(), err)
			}
		}
	}
	legacyTemplate := filepath.Join(unitDir, "mayoiga@.service")
	if err := os.Remove(legacyTemplate); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove legacy node service template: %w", err)
	}
	return nil
}

func uninstallManagerService() error {
	_ = exec.Command("systemctl", "--user", "disable", "--now", "mayoiga.service").Run()
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(home, ".config", "systemd", "user", "mayoiga.service")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return exec.Command("systemctl", "--user", "daemon-reload").Run()
}
