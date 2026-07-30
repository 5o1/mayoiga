//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func signalNotifyPlatform(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}
