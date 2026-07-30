//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDantedPublishedAndPulledForLANClient(t *testing.T) {
	danted := os.Getenv("MAYOIGA_TEST_DANTED")
	if danted == "" {
		t.Skip("set MAYOIGA_TEST_DANTED to run the external danted integration test")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	danteAddress := freeAddress(t)
	_, dantePort, _ := net.SplitHostPort(danteAddress)
	config := fmt.Sprintf(`logoutput: stderr
internal: 127.0.0.1 port = %s
external: 127.0.0.1
socksmethod: none
clientmethod: none
user.privileged: %s
user.unprivileged: %s
client pass { from: 127.0.0.0/8 to: 0.0.0.0/0 }
socks pass { from: 127.0.0.0/8 to: 0.0.0.0/0 command: connect }
`, dantePort, current.Username, current.Username)
	configPath := filepath.Join(dir, "danted.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(danted, "-f", configPath, "-N", "1")
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Signal(os.Interrupt)
		_ = command.Wait()
	})
	waitForTCP(t, danteAddress)

	payload := "mayoiga-danted-download\n"
	seenRemote := make(chan string, 1)
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		seenRemote <- request.RemoteAddr
		_, _ = io.WriteString(w, payload)
	})}
	go server.Serve(httpListener)
	t.Cleanup(func() { _ = server.Close() })

	publishAddress := freeAddress(t)
	certificate := filepath.Join(dir, "publish.crt")
	key := filepath.Join(dir, "publish.key")
	pin, err := makeCertificate(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := startMapping(mapping{
		Name: "danted-publish", Kind: "publish", Listen: publishAddress,
		Target: danteAddress, UUID: id, Certificate: certificate, Key: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()

	pullPortAddress := freeAddress(t)
	_, pullPort, _ := net.SplitHostPort(pullPortAddress)
	pullAddress := net.JoinHostPort("0.0.0.0", pullPort)
	puller, err := startMapping(mapping{
		Name: "danted-pull", Kind: "pull", Listen: pullAddress,
		Upstream: publishAddress, UUID: id, PinnedSHA256: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer puller.Close()

	connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", pullPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(connection, response); err != nil || response[0] != 5 || response[1] != 0 {
		t.Fatalf("SOCKS5 negotiation response=%v err=%v", response, err)
	}
	host, portText, _ := net.SplitHostPort(httpListener.Addr().String())
	ip := net.ParseIP(host).To4()
	port, _ := net.LookupPort("tcp", portText)
	request := append([]byte{5, 1, 0, 1}, ip...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(connection, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS5 connect reply=%v err=%v", reply, err)
	}
	if _, err := fmt.Fprintf(connection, "GET /paper.pdf HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	httpResponse, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(httpResponse.Body)
	httpResponse.Body.Close()
	if err != nil || string(body) != payload {
		t.Fatalf("download body=%q err=%v", body, err)
	}
	select {
	case remote := <-seenRemote:
		if !strings.HasPrefix(remote, "127.0.0.1:") {
			t.Fatalf("destination saw unexpected proxy source %q", remote)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("destination did not observe proxied request")
	}
}

func waitForTCP(t *testing.T, address string) {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("service %s did not start", address)
}
