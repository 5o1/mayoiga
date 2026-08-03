package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

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
