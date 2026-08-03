package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type coordinatorRuntime struct {
	servers []*http.Server
}

func (c *coordinatorRuntime) Shutdown(ctx context.Context) {
	for _, server := range c.servers {
		_ = server.Shutdown(ctx)
	}
}

func validateAdminListen(address string) error {
	if err := validateHostPort(address); err != nil {
		return fmt.Errorf("invalid coordinator admin listen address: %w", err)
	}
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("coordinator admin listener must use a loopback address")
	}
	return nil
}

func validateHostPort(address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be an explicit number from 1 to 65535")
	}
	return nil
}

func sameListenAddress(first, second string) bool {
	firstHost, firstPort, firstErr := net.SplitHostPort(first)
	secondHost, secondPort, secondErr := net.SplitHostPort(second)
	if firstErr != nil || secondErr != nil || firstPort != secondPort {
		return false
	}
	normalize := func(host string) string {
		if host == "localhost" {
			return "127.0.0.1"
		}
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return strings.ToLower(host)
	}
	return normalize(firstHost) == normalize(secondHost) ||
		(firstHost == "" || firstHost == "0.0.0.0" || firstHost == "::") ||
		(secondHost == "" || secondHost == "0.0.0.0" || secondHost == "::")
}

func checkListenAvailable(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return listener.Close()
}

func startCoordinator(path string, p profile) (*coordinatorRuntime, <-chan error, error) {
	if p.Server.Listen == "" || p.Server.AdminListen == "" || p.Server.AdminToken == "" {
		return nil, nil, errors.New("coordinator server is not configured; use --action add-node or configure-node with --role coordinator")
	}
	if err := validateAdminListen(p.Server.AdminListen); err != nil {
		return nil, nil, err
	}
	r, err := newRegistry(filepath.Join(filepath.Dir(path), "coordinator-state.json"), p.Server.AdminToken, p.VirtualNetwork)
	if err != nil {
		return nil, nil, err
	}
	if p.Server.ConnectionWaitSeconds > 0 {
		r.connectionWait = time.Duration(p.Server.ConnectionWaitSeconds) * time.Second
	}
	if p.Server.ConnectionRequestTTLSeconds > 0 {
		r.connectionTTL = time.Duration(p.Server.ConnectionRequestTTLSeconds) * time.Second
	}
	if p.Server.ConnectionOfferLeaseSeconds > 0 {
		r.connectionLease = time.Duration(p.Server.ConnectionOfferLeaseSeconds) * time.Second
	}
	if p.Server.ConnectionMaxPending > 0 {
		r.connectionMax = p.Server.ConnectionMaxPending
	}
	publicServer := &http.Server{
		Addr: p.Server.Listen, Handler: r, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: r.connectionWait + 10*time.Second,
		IdleTimeout: r.connectionWait + 30*time.Second,
	}
	adminServer := &http.Server{
		Addr: p.Server.AdminListen, Handler: http.HandlerFunc(r.serveAdmin), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	errs := make(chan error, 2)
	runtime := &coordinatorRuntime{servers: []*http.Server{publicServer, adminServer}}
	for _, server := range runtime.servers {
		go func(server *http.Server) {
			err := server.ListenAndServeTLS(p.Server.Certificate, p.Server.Key)
			if !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}(server)
	}
	return runtime, errs, nil
}
