//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

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
	args := []string{"--user"}
	if action == "start" {
		args = append(args, "enable", "--now", "mayoiga.service")
	} else {
		args = append(args, action, "mayoiga.service")
	}
	return exec.Command("systemctl", args...).Run()
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
