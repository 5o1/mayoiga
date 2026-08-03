//go:build !linux

package app

import (
	"errors"
	"runtime"
)

func installManagerService() error {
	return errors.New("service installation is not yet supported on " + runtime.GOOS + "; run --action service-run")
}

func ensureManagerService() error {
	return installManagerService()
}

func controlManagerService(string) error {
	return errors.New("service control is not yet supported on " + runtime.GOOS + "; run --action service-run")
}

func uninstallManagerService() error {
	return errors.New("service installation is not yet supported on " + runtime.GOOS)
}
