package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const profileVersion = 8

// mapping describes one locally managed TCP listener.
type mapping struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	Listen            string `json:"listen"`
	Target            string `json:"target,omitempty"`
	TargetNode        string `json:"target_node,omitempty"`
	Service           string `json:"service,omitempty"`
	Upstream          string `json:"upstream,omitempty"`
	UUID              string `json:"uuid"`
	UpstreamUUID      string `json:"upstream_uuid,omitempty"`
	Certificate       string `json:"certificate,omitempty"`
	Key               string `json:"key,omitempty"`
	PinnedSHA256      string `json:"pinned_sha256,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
}

// profile is the complete persistent configuration for one local node instance.
type profile struct {
	Version        int               `json:"version"`
	Instance       string            `json:"instance"`
	Disabled       bool              `json:"disabled,omitempty"`
	Role           string            `json:"role"`
	Segment        string            `json:"segment"`
	VirtualNetwork string            `json:"virtual_network"`
	Node           nodeConfig        `json:"node"`
	Coordinator    coordinatorClient `json:"coordinator,omitempty"`
	Server         coordinatorServer `json:"coordinator_server,omitempty"`
	Relay          relayConfig       `json:"relay,omitempty"`
	Subnode        subnodeConfig     `json:"subnode,omitempty"`
	Mappings       []mapping         `json:"mappings"`
}

type relayConfig struct {
	Listen             string `json:"listen"`
	Endpoint           string `json:"endpoint"`
	Priority           int    `json:"priority"`
	Certificate        string `json:"certificate"`
	Key                string `json:"key"`
	PinnedSHA256       string `json:"pinned_sha256"`
	AdmissionTokenHash string `json:"admission_token_hash,omitempty"`
}

type subnodeConfig struct {
	RelayNodeID       string `json:"relay_node_id"`
	RelayEndpoint     string `json:"relay_endpoint"`
	RelayPinnedSHA256 string `json:"relay_pinned_sha256"`
	RelayToken        string `json:"relay_token"`
}

func configDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "mayoiga"), nil
}

func profilePathFor(given, instance string) (string, error) {
	if err := validateInstance(instance); err != nil {
		return "", err
	}
	if given != "" {
		return filepath.Abs(given)
	}
	d, err := configDir()
	return filepath.Join(d, "nodes", instance, "profile.json"), err
}

func loadProfile(path string) (profile, error) {
	var p profile
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return profile{Version: profileVersion, Role: "client", Segment: "default", VirtualNetwork: "default"}, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if p.Version != profileVersion {
		return p, fmt.Errorf("unsupported profile version %d; delete and add the node again", p.Version)
	}
	return p, nil
}

func saveProfile(path string, p profile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func makeCertificate(certPath, keyPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("generate certificate serial: %w", err)
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "mayoiga"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"mayoiga"}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", err
	}
	h := x509CertHash(der)
	return hex.EncodeToString(h), nil
}

func x509CertHash(der []byte) []byte {
	h := sha256Sum(der)
	return h[:]
}

func splitAddress(s string) (string, int, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("%q must be host:port: %w", s, err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return host, number, nil
}
