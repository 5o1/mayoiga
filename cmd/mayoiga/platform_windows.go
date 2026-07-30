//go:build windows

package main

import (
	"os"
	"os/signal"
)

func signalNotifyPlatform(ch chan os.Signal) {
	signal.Notify(ch, os.Interrupt)
}
