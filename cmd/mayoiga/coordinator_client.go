package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func coordinatorHTTPClient(pinText string) (*http.Client, error) {
	pin, err := hex.DecodeString(normalizePin(pinText))
	if err != nil || len(pin) != sha256.Size {
		return nil, errors.New("coordinator pin must be 64 hexadecimal characters")
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec -- exact certificate pin is verified below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("coordinator sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return errors.New("coordinator certificate pin mismatch")
			}
			return nil
		},
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func coordinatorNodeHTTPClient(p profile) (*http.Client, error) {
	client, err := coordinatorHTTPClient(p.Coordinator.PinnedSHA256)
	if err != nil {
		return nil, err
	}
	if p.Role == "subnode" {
		transport := client.Transport.(*http.Transport)
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialCoordinatorViaRelay(ctx, p.VirtualNetwork, p.Node.ID, p.Subnode)
		}
	}
	return client, nil
}

func validSHA256Pin(pinText string) bool {
	pin, err := hex.DecodeString(normalizePin(pinText))
	return err == nil && len(pin) == sha256.Size
}

func requestEnrollment(ctx context.Context, path string, p *profile) error {
	if err := validateCoordinatorURL(p.Coordinator.URL); err != nil {
		return err
	}
	client, err := coordinatorNodeHTTPClient(*p)
	if err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(secureRandomReader)
	if err != nil {
		return fmt.Errorf("generate node credential: %w", err)
	}
	credential := &nodeCredential{
		PublicKey:  base64.RawStdEncoding.EncodeToString(publicKey),
		PrivateKey: base64.RawStdEncoding.EncodeToString(privateKey),
	}
	body, _ := json.Marshal(discoveryRequest{Node: localDiscoveredNode(*p), PublicKey: credential.PublicKey})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Coordinator.URL+"/v1/enroll/request", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return coordinatorResponseError(resp)
	}
	var enrollment enrollmentState
	if err := json.NewDecoder(resp.Body).Decode(&enrollment); err != nil {
		return err
	}
	p.Coordinator.Enrollment = &enrollment
	p.Coordinator.Enrollment.Status = "pending"
	p.Coordinator.Enrollment.Credential = credential
	p.Coordinator.Credential = nil
	if err := saveProfile(path, *p); err != nil {
		return err
	}
	fmt.Printf("DEVICE_CODE=%s\nHANDSHAKE_EXPIRES=%s\n", enrollment.DeviceCode, enrollment.ExpiresAt.Format(time.RFC3339))
	return nil
}

func pollEnrollment(ctx context.Context, path string, p *profile) (bool, error) {
	if p.Coordinator.Credential != nil {
		return true, nil
	}
	if p.Coordinator.Enrollment == nil {
		return false, errors.New("no pending handshake; use configure-node with --coordinator and --coordinator-pin")
	}
	client, err := coordinatorNodeHTTPClient(*p)
	if err != nil {
		return false, err
	}
	body, _ := json.Marshal(pollRequest{RequestID: p.Coordinator.Enrollment.RequestID, Secret: p.Coordinator.Enrollment.Secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Coordinator.URL+"/v1/enroll/poll", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, coordinatorResponseError(resp)
	}
	var output pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return false, err
	}
	if output.Status == "rejected" {
		p.Coordinator.Enrollment.Status = "rejected"
		_ = saveProfile(path, *p)
		reason := strings.TrimSpace(output.Reason)
		if reason == "" {
			reason = localizedError("enrollment_rejected", "upstream coordinator rejected the handshake")
		}
		return false, fmt.Errorf("enrollment_rejected: %s", reason)
	}
	if output.Status != "approved" {
		return false, nil
	}
	if p.Coordinator.Enrollment.Credential == nil {
		return false, errors.New("pending handshake has no local credential")
	}
	if err := validateCredential(p.Coordinator.Enrollment.Credential); err != nil {
		return false, err
	}
	p.Coordinator.Credential = p.Coordinator.Enrollment.Credential
	p.Coordinator.Enrollment = nil
	return true, saveProfile(path, *p)
}

func syncDiscovery(ctx context.Context, path string, p *profile) ([]discoveredNode, error) {
	if p.Coordinator.URL == "" {
		return nil, errors.New("no upstream coordinator configured")
	}
	if p.Coordinator.Credential == nil {
		approved, err := pollEnrollment(ctx, path, p)
		if err != nil || !approved {
			return nil, err
		}
	}
	revision, err := sendHeartbeat(ctx, *p)
	if err != nil {
		return nil, err
	}
	return fetchDiscovery(ctx, path, *p, 0, revision)
}

func sendHeartbeat(ctx context.Context, p profile) (uint64, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/nodes/heartbeat", discoveryRequest{Node: localDiscoveredNode(p)})
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, coordinatorResponseError(response)
	}
	var output heartbeatResponse
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		return 0, err
	}
	return output.Revision, nil
}

func fetchDiscovery(ctx context.Context, path string, p profile, afterRevision, expectedRevision uint64) ([]discoveredNode, error) {
	response, err := signedCoordinatorRequest(ctx, p, http.MethodPost, "/v1/nodes/discovery", discoverySyncRequest{AfterRevision: afterRevision})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, coordinatorResponseError(response)
	}
	var output discoveryResponse
	if err := json.NewDecoder(response.Body).Decode(&output); err != nil {
		return nil, err
	}
	if expectedRevision != 0 && output.Revision < expectedRevision {
		return nil, errors.New("coordinator discovery revision moved backwards")
	}
	if !output.Changed {
		return loadDiscovered(path)
	}
	if err := saveDiscovered(path, output.Nodes); err != nil {
		return nil, err
	}
	return output.Nodes, nil
}

func localDiscoveredNode(p profile) discoveredNode {
	n := discoveredNode{ID: p.Node.ID, Name: p.Node.Name, Role: p.Role, Segment: p.Segment, VirtualNetwork: p.VirtualNetwork}
	for _, m := range p.Mappings {
		if m.Kind == "publish" {
			n.Services = append(n.Services, publishedService{
				NodeID: p.Node.ID, Name: m.Name, Segment: p.Segment,
				DirectCandidates: localDirectCandidates(m.Listen),
				UUID:             m.UUID, PinnedSHA256: m.CertificateSHA256,
			})
		}
	}
	if p.Role == "relay" {
		n.Relay = &relayAdvertisement{Endpoint: p.Relay.Endpoint, PinnedSHA256: p.Relay.PinnedSHA256, Priority: p.Relay.Priority}
	}
	if p.Role == "subnode" {
		n.UpstreamRelay = p.Subnode.RelayNodeID
	}
	return n
}

func localDirectCandidates(listen string) []directCandidate {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	addresses := make([]string, 0, maxDirectCandidates)
	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		address := net.JoinHostPort(ip.String(), port)
		if validateDirectCandidate(address) == nil {
			addresses = append(addresses, address)
		}
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		interfaceAddresses, err := interfaceAddrs()
		if err != nil {
			return nil
		}
		for _, interfaceAddress := range interfaceAddresses {
			var ip net.IP
			switch value := interfaceAddress.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip != nil {
				add(ip)
			}
		}
	default:
		add(net.ParseIP(host))
	}
	sort.Strings(addresses)
	output := make([]directCandidate, 0, len(addresses))
	for _, address := range addresses {
		if len(output) == maxDirectCandidates || (len(output) > 0 && output[len(output)-1].Address == address) {
			continue
		}
		output = append(output, directCandidate{Address: address})
	}
	return output
}

func signRequest(req *http.Request, body []byte, nodeID, privateText string) error {
	privateKey, err := base64.RawStdEncoding.DecodeString(privateText)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid node private credential")
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomToken()
	if err != nil {
		return fmt.Errorf("generate request nonce: %w", err)
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), signedMessage(req.Method, req.URL.Path, timestamp, nonce, body))
	req.Header.Set("X-Mayoiga-Node", nodeID)
	req.Header.Set("X-Mayoiga-Time", timestamp)
	req.Header.Set("X-Mayoiga-Nonce", nonce)
	req.Header.Set("X-Mayoiga-Signature", base64.RawStdEncoding.EncodeToString(signature))
	return nil
}

func validateCredential(c *nodeCredential) error {
	pub, e1 := base64.RawStdEncoding.DecodeString(c.PublicKey)
	priv, e2 := base64.RawStdEncoding.DecodeString(c.PrivateKey)
	if e1 != nil || e2 != nil || len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize ||
		!bytes.Equal(pub, ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)) {
		return errors.New("invalid node credential")
	}
	return nil
}

func coordinatorAdminClient(path string) (*http.Client, string, profile, error) {
	p, err := loadProfile(path)
	if err != nil {
		return nil, "", p, err
	}
	if p.Role != "coordinator" || p.Server.AdminToken == "" {
		return nil, "", p, errors.New("this profile is not a coordinator")
	}
	client, err := coordinatorHTTPClient(p.Server.PinnedSHA256)
	if err != nil {
		return nil, "", p, err
	}
	host, port, err := net.SplitHostPort(p.Server.AdminListen)
	if err != nil {
		return nil, "", p, err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return client, "https://" + net.JoinHostPort(host, port), p, nil
}

func listPendingHandshakes(path string, statusCode int) error {
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	endpoint := origin + "/v1/admin/handshakes"
	if statusCode != 0 {
		endpoint += "?status=" + strconv.Itoa(statusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	var items []handshakeHistory
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no pending handshakes")
		return nil
	}
	for _, item := range items {
		fmt.Printf("%d\t%s\t%s\t%s\t%s\t%s\t%s\n", item.StatusCode, handshakeStatusText(item.StatusCode), item.DeviceCode, item.Node.Name, item.Node.Role, item.ExpiresAt.Format(time.RFC3339), item.Reason)
	}
	return nil
}

func listAuditEvents(path string) error {
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	req, _ := http.NewRequest(http.MethodGet, origin+"/v1/admin/audit", nil)
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	var items []auditEvent
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("no audit events")
		return nil
	}
	for _, item := range items {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", item.Time.Format(time.RFC3339), item.Action, item.NodeID, item.NodeName, item.Source)
	}
	return nil
}

func approveDeviceCode(path, code string, replace bool) error {
	return decideDeviceCode(path, code, "approve", replace, "")
}

func rejectDeviceCode(path, code, reason string) error {
	return decideDeviceCode(path, code, "reject", false, reason)
}

func decideDeviceCode(path, code, decision string, replace bool, reason string) error {
	if normalizeDeviceCode(code) == "" {
		return errors.New("--device-code is required")
	}
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(approveRequest{DeviceCode: code, Replace: replace, Reason: reason})
	req, _ := http.NewRequest(http.MethodPost, origin+"/v1/admin/"+decision, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	fmt.Println("handshake " + map[string]string{"approve": "approved", "reject": "rejected"}[decision])
	return nil
}

func revokeNodeID(path, nodeID string) error {
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("--node-id is required")
	}
	client, origin, p, err := coordinatorAdminClient(path)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(revokeRequest{NodeID: nodeID})
	req, _ := http.NewRequest(http.MethodPost, origin+"/v1/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+p.Server.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return coordinatorResponseError(resp)
	}
	fmt.Println("node revoked")
	return nil
}

func handshakeStatusText(code int) string {
	switch code {
	case 100:
		return "pending"
	case 200:
		return "approved"
	case 201:
		return "completed"
	case 403:
		return "rejected"
	case 410:
		return "expired"
	default:
		return "unknown"
	}
}

func saveDiscovered(profilePath string, nodes []discoveredNode) error {
	b, err := json.MarshalIndent(nodes, "", "  ")
	if err != nil {
		return err
	}
	path, tmp := filepath.Join(filepath.Dir(profilePath), "peers.json"), filepath.Join(filepath.Dir(profilePath), "peers.json.new")
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadDiscovered(profilePath string) ([]discoveredNode, error) {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(profilePath), "peers.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var nodes []discoveredNode
	return nodes, json.Unmarshal(b, &nodes)
}

func syncAndPrint(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	nodes, err := syncDiscovery(context.Background(), path, &p)
	if err != nil {
		return err
	}
	if p.Coordinator.Credential == nil {
		fmt.Println("handshake pending")
		return nil
	}
	return printNodes(nodes)
}

func printDiscovered(path string) error {
	nodes, err := loadDiscovered(path)
	if err != nil {
		return err
	}
	return printNodes(nodes)
}

func printNodes(nodes []discoveredNode) error {
	if len(nodes) == 0 {
		fmt.Println("no discovered nodes")
		return nil
	}
	fmt.Println("NODE_ID\tNAME\tROLE\tSEGMENT\tRELAY\tUPSTREAM_RELAY\tLAST_SEEN")
	for _, n := range nodes {
		relay := "-"
		if n.Relay != nil {
			relay = fmt.Sprintf("%s(priority=%d)", n.Relay.Endpoint, n.Relay.Priority)
		}
		upstream := n.UpstreamRelay
		if upstream == "" {
			upstream = "-"
		}
		fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.ID, n.Name, n.Role, n.Segment, relay, upstream, n.LastSeen.Format(time.RFC3339))
		for _, service := range n.Services {
			addresses := make([]string, 0, len(service.DirectCandidates))
			for _, candidate := range service.DirectCandidates {
				addresses = append(addresses, candidate.Address)
			}
			fmt.Printf("  service\t%s\tdirect=%s\n", service.Name, strings.Join(addresses, ","))
		}
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(secureRandomReader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomDeviceCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	random := make([]byte, 8)
	if _, err := io.ReadFull(secureRandomReader, random); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(random[i])%len(alphabet)]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}

func normalizeDeviceCode(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if len(s) != 8 {
		return ""
	}
	return s[:4] + "-" + s[4:]
}

func matchesHash(secret, expected string) bool {
	h := sha256.Sum256([]byte(secret))
	got := hex.EncodeToString(h[:])
	return len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func normalizePin(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func validateCoordinatorURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("coordinator must be an HTTPS origin URL without credentials, a path, query, or fragment")
	}
	if u.Hostname() == "" || u.Port() == "" {
		return errors.New("coordinator URL must include an explicit port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("coordinator URL port must be a number from 1 to 65535")
	}
	return nil
}
