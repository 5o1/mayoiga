package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestListenConflictAndAdminAddressValidation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := checkListenAvailable(address); err == nil {
		t.Fatal("occupied port was accepted")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkListenAvailable(address); err != nil {
		t.Fatalf("released port was rejected: %v", err)
	}
	if err := validateAdminListen("0.0.0.0:12345"); err == nil {
		t.Fatal("non-loopback admin address was accepted")
	}
	if !sameListenAddress("0.0.0.0:12345", "127.0.0.1:12345") {
		t.Fatal("wildcard listener conflict was not detected")
	}
}

func TestCoordinatorStartsSeparatePublicAndAdminListeners(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "coordinator.crt")
	keyPath := filepath.Join(dir, "coordinator.key")
	pin, err := makeCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	p := profile{
		VirtualNetwork: "mesh",
		Server: coordinatorServer{
			Listen: freeAddress(t), AdminListen: freeAddress(t), AdminToken: "secret",
			Certificate: certPath, Key: keyPath, PinnedSHA256: pin,
		},
	}
	runtime, errorsChannel, err := startCoordinator(filepath.Join(dir, "profile.json"), p)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Shutdown(context.Background())
	client, err := coordinatorHTTPClient(pin)
	if err != nil {
		t.Fatal(err)
	}
	request := func(address, path string, admin bool) *http.Response {
		t.Helper()
		var response *http.Response
		for attempt := 0; attempt < 20; attempt++ {
			req, _ := http.NewRequest(http.MethodGet, "https://"+address+path, nil)
			if admin {
				req.Header.Set("Authorization", "Bearer secret")
			}
			response, err = client.Do(req)
			if err == nil {
				return response
			}
			select {
			case serverErr := <-errorsChannel:
				t.Fatalf("coordinator server failed: %v", serverErr)
			case <-time.After(10 * time.Millisecond):
			}
		}
		t.Fatalf("coordinator did not become ready: %v", err)
		return nil
	}
	publicResponse := request(p.Server.Listen, "/v1/admin/handshakes", true)
	publicResponse.Body.Close()
	if publicResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("public listener exposed admin API: %d", publicResponse.StatusCode)
	}
	adminResponse := request(p.Server.AdminListen, "/v1/admin/handshakes", true)
	adminResponse.Body.Close()
	if adminResponse.StatusCode != http.StatusOK {
		t.Fatalf("admin listener status=%d", adminResponse.StatusCode)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("random unavailable")
}

func TestRandomSourceErrorsAreReturned(t *testing.T) {
	old := secureRandomReader
	secureRandomReader = failingReader{}
	t.Cleanup(func() { secureRandomReader = old })
	if _, err := randomToken(); err == nil {
		t.Fatal("randomToken ignored random source failure")
	}
	if _, err := randomDeviceCode(); err == nil {
		t.Fatal("randomDeviceCode ignored random source failure")
	}
	if _, _, err := ed25519.GenerateKey(io.Reader(secureRandomReader)); err == nil {
		t.Fatal("credential generation ignored random source failure")
	}
}

func TestRandomIdentifierCollisionRetriesAreBounded(t *testing.T) {
	r, err := newRegistry(filepath.Join(t.TempDir(), "state.json"), "secret", "mesh")
	if err != nil {
		t.Fatal(err)
	}
	r.state.Pending["existing"] = pendingHandshake{DeviceCode: "AAAA-AAAA"}
	old := secureRandomReader
	t.Cleanup(func() { secureRandomReader = old })

	secureRandomReader = bytes.NewReader(make([]byte, deviceCodeAttempts*8))
	if _, err := r.allocateDeviceCodeLocked(); err == nil {
		t.Fatal("device-code collision retries were unbounded or accepted a duplicate")
	}

	zeroID := strings.Repeat("0", 64)
	r.state.History[zeroID] = handshakeHistory{RequestID: zeroID}
	secureRandomReader = bytes.NewReader(make([]byte, deviceCodeAttempts*32))
	if _, err := r.allocateRequestIDLocked(); err == nil {
		t.Fatal("request-id collision retries were unbounded or accepted a duplicate")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
