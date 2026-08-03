package app

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

func relayHandshakeMessage(handshake relayHandshake) []byte {
	fields := []string{
		strconv.Itoa(handshake.Version), handshake.Mode, handshake.Network, handshake.SourceNode,
		handshake.RelayNode, handshake.TargetNode, handshake.Service,
		strconv.FormatInt(handshake.Timestamp, 10), handshake.Nonce,
	}
	if handshake.Mode == "reverse" {
		fields = append(fields, handshake.RequestID)
	}
	return []byte(strings.Join(fields, "\n"))
}

func probePinnedTLS(endpoint, pin string) error {
	config, err := pinnedTLSConfig(pin)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: relayDialTimeout}
	connection, err := tls.DialWithDialer(dialer, "tcp", endpoint, config)
	if err == nil {
		err = connection.Close()
	}
	return err
}

func pinnedTLSConfig(pinText string) (*tls.Config, error) {
	pin, err := hex.DecodeString(normalizePin(pinText))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("certificate pin must be 64 hexadecimal characters")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec -- exact pin below.
		ClientSessionCache: relayClientSessions,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("peer sent no certificate")
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

func writeRelayError(writer io.Writer, code, message string) {
	_, _ = io.WriteString(writer, "ERR "+code+" "+message+"\n")
}

func relayResponseError(response string) error {
	response = strings.TrimSpace(response)
	parts := strings.SplitN(response, " ", 3)
	if len(parts) == 3 && parts[0] == "ERR" && strings.Contains(parts[1], "_") {
		return fmt.Errorf("relay %s: %s", parts[1], localizedError(parts[1], parts[2]))
	}
	return fmt.Errorf("relay request rejected: %s", response)
}

func bridge(left, right net.Conn) {
	defer right.Close()
	bridgeReaders(left, left, right)
}

func bridgeReaders(leftReader io.Reader, left net.Conn, right net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(right, leftReader)
		closeWrite(right)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(left, right)
		closeWrite(left)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(connection net.Conn) {
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

func (c *bufferedConn) CloseWrite() error {
	if halfCloser, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return halfCloser.CloseWrite()
	}
	return nil
}
