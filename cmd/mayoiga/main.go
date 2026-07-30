package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed locales/*.json
var localeFiles embed.FS

var version = "dev"

const profileVersion = 7

type messages map[string]string

type mapping struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	Listen            string `json:"listen"`
	Target            string `json:"target,omitempty"`
	Endpoint          string `json:"endpoint,omitempty"`
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

type profile struct {
	Version        int               `json:"version"`
	Instance       string            `json:"instance"`
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
	Listen       string `json:"listen"`
	Endpoint     string `json:"endpoint"`
	Priority     int    `json:"priority"`
	Certificate  string `json:"certificate"`
	Key          string `json:"key"`
	PinnedSHA256 string `json:"pinned_sha256"`
}

type subnodeConfig struct {
	RelayNodeID       string `json:"relay_node_id"`
	RelayEndpoint     string `json:"relay_endpoint"`
	RelayPinnedSHA256 string `json:"relay_pinned_sha256"`
}

type options struct {
	lang, role, action, segment, name, kind                    string
	listen, adminListen, target, endpoint, targetNode, service string
	transitListen, transitEndpoint                             string
	upstreamRelayNode, upstreamRelayEndpoint, upstreamRelayPin string
	requestID, idempotencyKey                                  string
	config, output, coordinator, coordinatorPin, deviceCode    string
	managerDir                                                 string
	network, advertise, nodeName, nodeID, instance             string
	handshakeStatus                                            int
	relayPriority                                              int
	connectionWaitSeconds, connectionTTLSeconds                int
	connectionLeaseSeconds, connectionMaxPending               int
	set                                                        map[string]bool
	yes, replaceExisting, showVersion                          bool
}

func main() {
	var o options
	flag.StringVar(&o.lang, "lang", "", "locale: en or zh_CN")
	flag.StringVar(&o.role, "role", "", "client, gateway, relay, subnode, or coordinator")
	flag.StringVar(&o.action, "action", "", "node, mapping, coordinator, and connection control action")
	flag.StringVar(&o.instance, "instance", "", "local node instance name")
	flag.StringVar(&o.segment, "segment", "default", "logical network segment")
	flag.StringVar(&o.network, "network", "default", "virtual network name")
	flag.StringVar(&o.coordinator, "coordinator", "", "upstream coordinator HTTPS URL")
	flag.StringVar(&o.coordinatorPin, "coordinator-pin", "", "coordinator certificate SHA-256")
	flag.StringVar(&o.deviceCode, "device-code", "", "one-time enrollment device code")
	flag.IntVar(&o.handshakeStatus, "handshake-status", 0, "filter handshake history by status code")
	flag.StringVar(&o.advertise, "advertise", "", "comma-separated reachable node endpoints")
	flag.StringVar(&o.nodeName, "node-name", "", "node display name (default: hostname)")
	flag.StringVar(&o.nodeID, "node-id", "", "authorized node ID")
	flag.StringVar(&o.requestID, "request-id", "", "connection request ID")
	flag.StringVar(&o.idempotencyKey, "idempotency-key", "", "connection request idempotency key")
	flag.StringVar(&o.name, "name", "", "mapping name")
	flag.StringVar(&o.kind, "kind", "", "mapping kind: pull or publish")
	flag.StringVar(&o.listen, "listen", "", "listen address in host:port form")
	flag.StringVar(&o.adminListen, "admin-listen", "", "coordinator loopback-only admin listen address")
	flag.StringVar(&o.target, "target", "", "reachable target address for publish")
	flag.StringVar(&o.endpoint, "endpoint", "", "externally reachable encrypted publish endpoint")
	flag.StringVar(&o.targetNode, "target-node", "", "target node ID for an automatic pull")
	flag.StringVar(&o.service, "service", "", "published service name for an automatic pull")
	flag.StringVar(&o.transitListen, "transit-listen", "", "relay transit listen address")
	flag.StringVar(&o.transitEndpoint, "transit-endpoint", "", "reachable relay transit endpoint")
	flag.StringVar(&o.upstreamRelayNode, "upstream-relay-node", "", "upstream relay node ID for a subnode")
	flag.StringVar(&o.upstreamRelayEndpoint, "upstream-relay-endpoint", "", "reachable upstream relay endpoint for a subnode")
	flag.StringVar(&o.upstreamRelayPin, "upstream-relay-pin", "", "upstream relay certificate SHA-256 for a subnode")
	flag.IntVar(&o.relayPriority, "relay-priority", 100, "relay preference; lower values are tried first")
	flag.IntVar(&o.connectionWaitSeconds, "connection-wait-seconds", 25, "coordinator maximum long-poll wait")
	flag.IntVar(&o.connectionTTLSeconds, "connection-request-ttl-seconds", 120, "connection request lifetime")
	flag.IntVar(&o.connectionLeaseSeconds, "connection-offer-lease-seconds", 15, "connection offer lease")
	flag.IntVar(&o.connectionMaxPending, "connection-max-pending", 10000, "coordinator connection request capacity")
	flag.StringVar(&o.config, "config", "", "profile path (default: user config directory)")
	flag.StringVar(&o.managerDir, "manager-dir", "", "manager data directory containing nodes/ (default: user config directory)")
	flag.StringVar(&o.output, "output", "", "rendered Xray JSON output path")
	flag.BoolVar(&o.yes, "yes", false, "confirm node deletion")
	flag.BoolVar(&o.replaceExisting, "replace-existing", false, "approve replacing an existing node credential")
	flag.BoolVar(&o.showVersion, "version", false, "print version")
	flag.Parse()
	o.set = make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	if o.showVersion {
		fmt.Println(version)
		return
	}

	if o.lang == "" && o.action == "" {
		o.lang = chooseLanguage()
	}
	if o.lang == "" {
		o.lang = "en"
	}
	msg, _ := loadLocale(o.lang)
	if o.action == "" {
		if err := interactive(&o, msg); err != nil {
			fatal(err)
		}
	}
	if o.action == "quit" {
		return
	}
	if err := execute(o); err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "mayoiga:", err); os.Exit(1) }

func loadLocale(name string) (messages, error) {
	b, err := localeFiles.ReadFile("locales/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("unsupported locale %q", name)
	}
	var m messages
	return m, json.Unmarshal(b, &m)
}

func chooseLanguage() string {
	names := []string{"en", "zh_CN"}
	for i, name := range names {
		m, _ := loadLocale(name)
		fmt.Printf("%d) %s\n", i+1, m["language_name"])
	}
	fmt.Print("> ")
	var s string
	fmt.Scanln(&s)
	if s == "2" {
		return "zh_CN"
	}
	return "en"
}

func interactive(o *options, m messages) error {
	in := bufio.NewScanner(os.Stdin)
	fmt.Println(m["app.title"])
	fmt.Println(m["prompt.action"])
	fmt.Printf("1) %s\n2) %s\n3) %s\n4) %s\n5) %s\n6) %s\n7) %s\n8) %s\n9) %s\n10) %s\n11) %s\n12) %s\n13) %s\n14) %s\n15) %s\n16) %s\n17) %s\n18) %s\n19) %s\n20) %s\n21) %s\n22) %s\n23) %s\n24) %s\n25) %s\n26) %s\n27) %s\n28) %s\n29) %s\n30) %s\n",
		m["action.add_node"], m["action.list_nodes"], m["action.configure_node"], m["action.delete_node"], m["action.status"],
		m["action.start"], m["action.stop"], m["action.sync"], m["action.nodes"], m["action.add"], m["action.remove"],
		m["action.handshakes"], m["action.audit"], m["action.approve"], m["action.reject"], m["action.revoke"],
		m["action.request_connection"], m["action.wait_connection"], m["action.connection_status"], m["action.connection_inbox"],
		m["action.accept_connection"], m["action.reject_connection"], m["action.cancel_connection"],
		m["action.service_install"], m["action.service_run"], m["action.service_start"], m["action.service_stop"],
		m["action.service_status"], m["action.service_uninstall"], m["action.quit"])
	fmt.Print("> ")
	in.Scan()
	actions := map[string]string{
		"1": "add-node", "2": "list-nodes", "3": "configure-node", "4": "delete-node", "5": "status",
		"6": "start", "7": "stop", "8": "sync", "9": "nodes", "10": "add", "11": "remove",
		"12": "handshakes", "13": "audit", "14": "approve", "15": "reject", "16": "revoke",
		"17": "request-connection", "18": "wait-connection", "19": "connection-status", "20": "connection-inbox",
		"21": "accept-connection", "22": "reject-connection", "23": "cancel-connection",
		"24": "service-install", "25": "service-run", "26": "service-start", "27": "service-stop",
		"28": "service-status", "29": "service-uninstall", "30": "quit",
	}
	o.action = actions[in.Text()]
	if o.action == "" {
		return errors.New("invalid action")
	}
	if o.action == "list-nodes" || o.action == "quit" || strings.HasPrefix(o.action, "service-") {
		return nil
	}
	fmt.Print(m["prompt.instance"])
	in.Scan()
	o.instance = strings.TrimSpace(in.Text())
	if err := validateInstance(o.instance); err != nil {
		return err
	}
	if o.action == "add-node" || o.action == "configure-node" {
		configure := o.action == "configure-node"
		if configure {
			path, _ := profilePathFor("", o.instance)
			p, err := loadProfile(path)
			if err != nil {
				return fmt.Errorf("load node %q: %w", o.instance, err)
			}
			o.role, o.nodeName, o.network, o.segment = p.Role, p.Node.Name, p.VirtualNetwork, p.Segment
			o.advertise, o.coordinator, o.coordinatorPin, o.listen, o.adminListen = strings.Join(p.Node.Endpoints, ","), p.Coordinator.URL, p.Coordinator.PinnedSHA256, p.Server.Listen, p.Server.AdminListen
			o.transitListen, o.transitEndpoint, o.relayPriority = p.Relay.Listen, p.Relay.Endpoint, p.Relay.Priority
			o.upstreamRelayNode, o.upstreamRelayEndpoint, o.upstreamRelayPin =
				p.Subnode.RelayNodeID, p.Subnode.RelayEndpoint, p.Subnode.RelayPinnedSHA256
			o.connectionWaitSeconds, o.connectionTTLSeconds = p.Server.ConnectionWaitSeconds, p.Server.ConnectionRequestTTLSeconds
			o.connectionLeaseSeconds, o.connectionMaxPending = p.Server.ConnectionOfferLeaseSeconds, p.Server.ConnectionMaxPending
		}
		fmt.Println(m["prompt.role"])
		fmt.Printf("1) %s  2) %s  3) %s  4) %s  5) %s", m["role.client"], m["role.gateway"], m["role.relay"], m["role.subnode"], m["role.coordinator"])
		if configure {
			fmt.Printf(" [%s]", o.role)
		}
		fmt.Print("\n> ")
		in.Scan()
		roles := map[string]string{"1": "client", "2": "gateway", "3": "relay", "4": "subnode", "5": "coordinator"}
		if value := roles[strings.TrimSpace(in.Text())]; value != "" {
			o.role, o.set["role"] = value, true
		}
		if o.role == "" {
			return errors.New("invalid role")
		}
		askEdit(in, m["prompt.node_name"], &o.nodeName, "node-name", o.set, configure)
		askEdit(in, m["prompt.network"], &o.network, "network", o.set, configure)
		askEdit(in, m["prompt.segment"], &o.segment, "segment", o.set, configure)
		askEdit(in, m["prompt.advertise"], &o.advertise, "advertise", o.set, configure)
		if o.role == "coordinator" {
			askEdit(in, m["prompt.coordinator_listen"], &o.listen, "listen", o.set, configure)
			askEdit(in, m["prompt.admin_listen"], &o.adminListen, "admin-listen", o.set, configure)
			if err := askIntEdit(in, m["prompt.connection_wait"], &o.connectionWaitSeconds, "connection-wait-seconds", o.set, configure); err != nil {
				return err
			}
			if err := askIntEdit(in, m["prompt.connection_ttl"], &o.connectionTTLSeconds, "connection-request-ttl-seconds", o.set, configure); err != nil {
				return err
			}
			if err := askIntEdit(in, m["prompt.connection_lease"], &o.connectionLeaseSeconds, "connection-offer-lease-seconds", o.set, configure); err != nil {
				return err
			}
			if err := askIntEdit(in, m["prompt.connection_capacity"], &o.connectionMaxPending, "connection-max-pending", o.set, configure); err != nil {
				return err
			}
		} else {
			if o.role == "relay" {
				askEdit(in, m["prompt.transit_listen"], &o.transitListen, "transit-listen", o.set, configure)
				askEdit(in, m["prompt.transit_endpoint"], &o.transitEndpoint, "transit-endpoint", o.set, configure)
				if configure {
					fmt.Printf("%s[%d] ", m["prompt.relay_priority"], o.relayPriority)
				} else {
					fmt.Print(m["prompt.relay_priority"])
				}
				in.Scan()
				if value := strings.TrimSpace(in.Text()); value != "" {
					priority, err := strconv.Atoi(value)
					if err != nil {
						return errors.New("invalid relay priority")
					}
					o.relayPriority, o.set["relay-priority"] = priority, true
				}
			}
			if o.role == "subnode" {
				askEdit(in, m["prompt.upstream_relay_node"], &o.upstreamRelayNode, "upstream-relay-node", o.set, configure)
				askEdit(in, m["prompt.upstream_relay_endpoint"], &o.upstreamRelayEndpoint, "upstream-relay-endpoint", o.set, configure)
				askEdit(in, m["prompt.upstream_relay_pin"], &o.upstreamRelayPin, "upstream-relay-pin", o.set, configure)
			}
			askEdit(in, m["prompt.coordinator"], &o.coordinator, "coordinator", o.set, configure)
			if o.coordinator != "" {
				askEdit(in, m["prompt.coordinator_pin"], &o.coordinatorPin, "coordinator-pin", o.set, configure)
			}
		}
		return nil
	}
	if o.action == "approve" || o.action == "reject" {
		fmt.Print(m["prompt.device_code"])
		in.Scan()
		o.deviceCode = strings.TrimSpace(in.Text())
		if o.action == "approve" {
			fmt.Print(m["prompt.replace_existing"])
			in.Scan()
			o.replaceExisting = strings.EqualFold(strings.TrimSpace(in.Text()), "yes")
		}
	}
	if o.action == "revoke" {
		fmt.Print(m["prompt.node_id"])
		in.Scan()
		o.nodeID = strings.TrimSpace(in.Text())
	}
	if o.action == "add" {
		fmt.Print(m["prompt.kind"])
		in.Scan()
		o.kind = in.Text()
		fmt.Print(m["prompt.name"])
		in.Scan()
		o.name = in.Text()
		fmt.Print(m["prompt.listen"])
		in.Scan()
		o.listen = in.Text()
		if o.kind == "publish" {
			fmt.Print(m["prompt.target"])
			in.Scan()
			o.target = in.Text()
			fmt.Print(m["prompt.endpoint"])
			in.Scan()
			o.endpoint = in.Text()
		} else {
			fmt.Print(m["prompt.target_node"])
			in.Scan()
			o.targetNode = in.Text()
			fmt.Print(m["prompt.service"])
			in.Scan()
			o.service = in.Text()
		}
	}
	if o.action == "remove" {
		fmt.Print(m["prompt.name"])
		in.Scan()
		o.name = in.Text()
	}
	if o.action == "request-connection" {
		fmt.Print(m["prompt.target_node"])
		in.Scan()
		o.targetNode = strings.TrimSpace(in.Text())
		fmt.Print(m["prompt.service"])
		in.Scan()
		o.service = strings.TrimSpace(in.Text())
	}
	if o.action == "wait-connection" || o.action == "connection-status" ||
		o.action == "accept-connection" || o.action == "reject-connection" || o.action == "cancel-connection" {
		fmt.Print(m["prompt.request_id"])
		in.Scan()
		o.requestID = strings.TrimSpace(in.Text())
	}
	if o.action == "delete-node" {
		fmt.Print(m["prompt.confirm"])
		in.Scan()
		o.yes = in.Text() == "yes"
	}
	return nil
}

func askEdit(in *bufio.Scanner, prompt string, target *string, flagName string, set map[string]bool, preserve bool) {
	if preserve && *target != "" {
		fmt.Printf("%s[%s] ", prompt, *target)
	} else {
		fmt.Print(prompt)
	}
	in.Scan()
	value := strings.TrimSpace(in.Text())
	if value != "" {
		if value == "-" {
			value = ""
		}
		*target, set[flagName] = value, true
	}
}

func askIntEdit(in *bufio.Scanner, prompt string, target *int, flagName string, set map[string]bool, preserve bool) error {
	if preserve {
		fmt.Printf("%s[%d] ", prompt, *target)
	} else {
		fmt.Printf("%s[%d] ", prompt, *target)
	}
	in.Scan()
	value := strings.TrimSpace(in.Text())
	if value == "" {
		return nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%s must be an integer", flagName)
	}
	*target, set[flagName] = parsed, true
	return nil
}

func execute(o options) error {
	switch o.action {
	case "list-nodes":
		return listNodes()
	case "service-install":
		return installManagerService()
	case "service-run":
		return runManagerService(o.managerDir)
	case "service-start":
		return controlManagerService("start")
	case "service-stop":
		return controlManagerService("stop")
	case "service-status":
		return controlManagerService("status")
	case "service-uninstall":
		return uninstallManagerService()
	}
	path, err := profilePathFor(o.config, o.instance)
	if err != nil {
		return err
	}
	switch o.action {
	case "add-node":
		return install(o, path, false)
	case "configure-node":
		return install(o, path, true)
	case "status":
		return status(path)
	case "start":
		return start(o.instance, path, o.config == "")
	case "stop":
		return stop(o.instance, o.config == "")
	case "delete-node":
		if !o.yes {
			return errors.New("--yes is required")
		}
		return uninstall(o.instance, path, o.config == "")
	case "add":
		return addMapping(o, path)
	case "remove":
		return removeMapping(o.name, path)
	case "render":
		return renderFile(path, o.output)
	case "nodes":
		return printDiscovered(path)
	case "handshakes":
		return listPendingHandshakes(path, o.handshakeStatus)
	case "audit":
		return listAuditEvents(path)
	case "approve":
		return approveDeviceCode(path, o.deviceCode, o.replaceExisting)
	case "reject":
		return rejectDeviceCode(path, o.deviceCode)
	case "revoke":
		return revokeNodeID(path, o.nodeID)
	case "sync":
		return syncAndPrint(path)
	case "request-connection":
		return requestConnectionCLI(path, o)
	case "wait-connection":
		return connectionStatusCLI(path, o.requestID, true)
	case "connection-status":
		return connectionStatusCLI(path, o.requestID, false)
	case "connection-inbox":
		return printConnectionInbox(path)
	case "accept-connection":
		return decideConnectionCLI(path, o.requestID, "accept")
	case "reject-connection":
		return decideConnectionCLI(path, o.requestID, "reject")
	case "cancel-connection":
		return decideConnectionCLI(path, o.requestID, "cancel")
	case "run":
		return runProfile(path)
	default:
		return fmt.Errorf("unknown action %q", o.action)
	}
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
	err = json.Unmarshal(b, &p)
	if err != nil {
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

func install(o options, path string, configure bool) error {
	if configure {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("node instance %q does not exist", o.instance)
		}
	} else if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("node instance %q already exists; use configure-node", o.instance)
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	p.Instance = o.instance
	if !configure || o.set["role"] {
		p.Role = o.role
	}
	if p.Role == "" {
		return errors.New("--role is required")
	}
	switch p.Role {
	case "client", "gateway", "relay", "subnode", "coordinator":
	default:
		return errors.New("--role must be client, gateway, relay, subnode, or coordinator")
	}
	if !configure || o.set["segment"] {
		p.Segment = o.segment
	}
	if !configure || o.set["network"] {
		p.VirtualNetwork = o.network
	}
	if strings.TrimSpace(p.VirtualNetwork) == "" || strings.TrimSpace(p.Segment) == "" {
		return errors.New("--network and --segment cannot be empty")
	}
	if p.Node.ID == "" {
		p.Node.ID, err = randomUUID()
		if err != nil {
			return fmt.Errorf("generate node id: %w", err)
		}
	}
	if !configure || o.set["node-name"] {
		p.Node.Name = o.nodeName
		if p.Node.Name == "" {
			p.Node.Name, _ = os.Hostname()
		}
	}
	if !configure || o.set["advertise"] {
		p.Node.Endpoints = splitList(o.advertise)
		for _, endpoint := range p.Node.Endpoints {
			if err := validateHostPort(endpoint); err != nil {
				return fmt.Errorf("invalid advertised endpoint %q: %w", endpoint, err)
			}
		}
	}

	needsEnrollment := false
	if p.Role == "coordinator" && (!configure || o.set["listen"] || o.set["admin-listen"] ||
		o.set["connection-wait-seconds"] || o.set["connection-request-ttl-seconds"] ||
		o.set["connection-offer-lease-seconds"] || o.set["connection-max-pending"] ||
		p.Server.AdminToken == "") {
		if configure && !o.set["listen"] {
			o.listen = p.Server.Listen
		}
		if o.listen == "" {
			return errors.New("--listen is required for a coordinator")
		}
		if err := validateHostPort(o.listen); err != nil {
			return fmt.Errorf("invalid coordinator public listen address: %w", err)
		}
		p.Server.Listen = o.listen
		if !configure || o.set["admin-listen"] || p.Server.AdminListen == "" {
			p.Server.AdminListen = o.adminListen
			if p.Server.AdminListen == "" {
				return errors.New("--admin-listen is required for a coordinator")
			}
			if err := validateAdminListen(p.Server.AdminListen); err != nil {
				return err
			}
		}
		if sameListenAddress(p.Server.Listen, p.Server.AdminListen) {
			return errors.New("--listen and --admin-listen must use different addresses")
		}
		if configure && !o.set["connection-wait-seconds"] {
			o.connectionWaitSeconds = p.Server.ConnectionWaitSeconds
		}
		if configure && !o.set["connection-request-ttl-seconds"] {
			o.connectionTTLSeconds = p.Server.ConnectionRequestTTLSeconds
		}
		if configure && !o.set["connection-offer-lease-seconds"] {
			o.connectionLeaseSeconds = p.Server.ConnectionOfferLeaseSeconds
		}
		if configure && !o.set["connection-max-pending"] {
			o.connectionMaxPending = p.Server.ConnectionMaxPending
		}
		if o.connectionWaitSeconds == 0 {
			o.connectionWaitSeconds = int(connectionWaitMaximum / time.Second)
		}
		if o.connectionTTLSeconds == 0 {
			o.connectionTTLSeconds = int(connectionRequestLifetime / time.Second)
		}
		if o.connectionLeaseSeconds == 0 {
			o.connectionLeaseSeconds = int(connectionOfferLease / time.Second)
		}
		if o.connectionMaxPending == 0 {
			o.connectionMaxPending = maxConnectionRequests
		}
		if o.connectionWaitSeconds < 1 || o.connectionWaitSeconds > 120 ||
			o.connectionTTLSeconds < 10 || o.connectionTTLSeconds > 3600 ||
			o.connectionLeaseSeconds < 1 || o.connectionLeaseSeconds >= o.connectionTTLSeconds ||
			o.connectionMaxPending < 1 || o.connectionMaxPending > 100000 {
			return errors.New("invalid connection control limits")
		}
		p.Server.ConnectionWaitSeconds = o.connectionWaitSeconds
		p.Server.ConnectionRequestTTLSeconds = o.connectionTTLSeconds
		p.Server.ConnectionOfferLeaseSeconds = o.connectionLeaseSeconds
		p.Server.ConnectionMaxPending = o.connectionMaxPending
		if !configure {
			if owner, conflict, err := configuredListenConflict(path, p.Server.Listen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("coordinator public port conflicts with configured listener %s", owner)
			}
			if owner, conflict, err := configuredListenConflict(path, p.Server.AdminListen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("coordinator admin port conflicts with configured listener %s", owner)
			}
			if err := checkListenAvailable(p.Server.Listen); err != nil {
				return fmt.Errorf("coordinator public port conflict at %s: %w", p.Server.Listen, err)
			}
			if err := checkListenAvailable(p.Server.AdminListen); err != nil {
				return fmt.Errorf("coordinator admin port conflict at %s: %w", p.Server.AdminListen, err)
			}
		}
		if p.Server.AdminToken == "" {
			p.Server.AdminToken, err = randomToken()
			if err != nil {
				return fmt.Errorf("generate coordinator admin token: %w", err)
			}
		}
		if p.Server.Certificate == "" {
			dir := filepath.Dir(path)
			p.Server.Certificate, p.Server.Key = filepath.Join(dir, "coordinator.crt"), filepath.Join(dir, "coordinator.key")
			pin, err := makeCertificate(p.Server.Certificate, p.Server.Key)
			if err != nil {
				return err
			}
			p.Server.PinnedSHA256 = pin
		}
		fmt.Printf("COORDINATOR_PIN=%s\n", p.Server.PinnedSHA256)
	}
	if p.Role == "relay" {
		if configure && !o.set["transit-listen"] {
			o.transitListen = p.Relay.Listen
		}
		if configure && !o.set["transit-endpoint"] {
			o.transitEndpoint = p.Relay.Endpoint
		}
		if o.transitListen == "" || o.transitEndpoint == "" {
			return errors.New("--transit-listen and --transit-endpoint are required for a relay node")
		}
		if err := validateHostPort(o.transitListen); err != nil {
			return fmt.Errorf("invalid relay transit listen address: %w", err)
		}
		if err := validateHostPort(o.transitEndpoint); err != nil {
			return fmt.Errorf("invalid relay transit endpoint: %w", err)
		}
		p.Relay.Listen, p.Relay.Endpoint = o.transitListen, o.transitEndpoint
		if !configure || o.set["relay-priority"] {
			p.Relay.Priority = o.relayPriority
		}
		if p.Relay.Priority < 0 {
			return errors.New("--relay-priority cannot be negative")
		}
		if !configure {
			if owner, conflict, err := configuredListenConflict(path, p.Relay.Listen); err != nil {
				return err
			} else if conflict {
				return fmt.Errorf("relay transit port conflicts with configured listener %s", owner)
			}
			if err := checkListenAvailable(p.Relay.Listen); err != nil {
				return fmt.Errorf("relay transit port conflict at %s: %w", p.Relay.Listen, err)
			}
		}
		if p.Relay.Certificate == "" {
			dir := filepath.Dir(path)
			p.Relay.Certificate, p.Relay.Key = filepath.Join(dir, "relay.crt"), filepath.Join(dir, "relay.key")
			pin, err := makeCertificate(p.Relay.Certificate, p.Relay.Key)
			if err != nil {
				return err
			}
			p.Relay.PinnedSHA256 = pin
		}
		fmt.Printf("RELAY_PIN=%s\n", p.Relay.PinnedSHA256)
	} else if configure && o.set["role"] {
		p.Relay = relayConfig{}
	}
	if p.Role == "subnode" {
		if configure && !o.set["upstream-relay-node"] {
			o.upstreamRelayNode = p.Subnode.RelayNodeID
		}
		if configure && !o.set["upstream-relay-endpoint"] {
			o.upstreamRelayEndpoint = p.Subnode.RelayEndpoint
		}
		if configure && !o.set["upstream-relay-pin"] {
			o.upstreamRelayPin = p.Subnode.RelayPinnedSHA256
		}
		if o.upstreamRelayNode == "" || o.upstreamRelayEndpoint == "" || o.upstreamRelayPin == "" {
			return errors.New("--upstream-relay-node, --upstream-relay-endpoint, and --upstream-relay-pin are required for a subnode")
		}
		if err := validateHostPort(o.upstreamRelayEndpoint); err != nil {
			return fmt.Errorf("invalid upstream relay endpoint: %w", err)
		}
		if !validSHA256Pin(o.upstreamRelayPin) {
			return errors.New("--upstream-relay-pin must be 64 hexadecimal characters")
		}
		p.Subnode = subnodeConfig{
			RelayNodeID: o.upstreamRelayNode, RelayEndpoint: o.upstreamRelayEndpoint,
			RelayPinnedSHA256: normalizePin(o.upstreamRelayPin),
		}
	} else if configure && o.set["role"] {
		p.Subnode = subnodeConfig{}
	}
	if o.set["coordinator"] || (!configure && o.coordinator != "") {
		if o.coordinator == "" {
			p.Coordinator = coordinatorClient{}
		} else {
			if o.coordinatorPin == "" {
				return errors.New("--coordinator-pin is required with --coordinator")
			}
			if err := validateCoordinatorURL(o.coordinator); err != nil {
				return err
			}
			origin, pin := strings.TrimRight(o.coordinator, "/"), normalizePin(o.coordinatorPin)
			needsEnrollment = p.Coordinator.URL != origin || p.Coordinator.PinnedSHA256 != pin || p.Coordinator.Credential == nil
			if p.Coordinator.URL != origin || p.Coordinator.PinnedSHA256 != pin {
				p.Coordinator = coordinatorClient{URL: origin, PinnedSHA256: pin}
			}
		}
	}
	if p.Role == "relay" && p.Coordinator.URL == "" {
		return errors.New("a relay node must configure --coordinator and --coordinator-pin")
	}
	if p.Role == "subnode" && p.Coordinator.URL == "" {
		return errors.New("a subnode must configure --coordinator and --coordinator-pin")
	}
	if err := saveProfile(path, p); err != nil {
		return err
	}
	if needsEnrollment {
		if err := requestEnrollment(context.Background(), path, &p); err != nil {
			return fmt.Errorf("create coordinator handshake: %w", err)
		}
	}
	if runtime.GOOS == "linux" && o.config == "" {
		if err := installNodeUnit(o.instance); err != nil {
			return err
		}
		fmt.Printf("node %s saved; run: mayoiga --instance %s --action start\n", o.instance, o.instance)
	} else {
		fmt.Printf("node %s saved\n", o.instance)
	}
	return nil
}

func addMapping(o options, path string) error {
	if o.name == "" || o.listen == "" {
		return errors.New("--name and --listen are required")
	}
	if o.kind != "pull" && o.kind != "publish" {
		return errors.New("--kind must be pull or publish; relay capability belongs to a relay node")
	}
	if o.kind == "publish" {
		if o.target == "" || o.endpoint == "" {
			return errors.New("--target and --endpoint are required for publish")
		}
		if err := validateHostPort(o.target); err != nil {
			return fmt.Errorf("invalid publish target address: %w", err)
		}
		if err := validateHostPort(o.endpoint); err != nil {
			return fmt.Errorf("invalid publish endpoint: %w", err)
		}
	} else if o.targetNode == "" || o.service == "" {
		return errors.New("--target-node and --service are required for pull")
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	if o.kind == "pull" && p.Coordinator.URL == "" {
		return errors.New("an automatic pull requires the node to be registered with a coordinator")
	}
	for _, x := range p.Mappings {
		if x.Name == o.name {
			return errors.New("mapping name already exists")
		}
		if sameListenAddress(x.Listen, o.listen) {
			return fmt.Errorf("--listen conflicts with mapping %q in node %q", x.Name, p.Instance)
		}
	}
	if err := validateHostPort(o.listen); err != nil {
		return fmt.Errorf("invalid mapping listen address: %w", err)
	}
	if owner, conflict, err := configuredListenConflict(path, o.listen); err != nil {
		return err
	} else if conflict {
		return fmt.Errorf("--listen conflicts with configured listener %s", owner)
	}
	if err := checkListenAvailable(o.listen); err != nil {
		return fmt.Errorf("mapping port conflict at %s: %w", o.listen, err)
	}
	m := mapping{
		Name: o.name, Kind: o.kind, Listen: o.listen, Target: o.target, Endpoint: o.endpoint,
		TargetNode: o.targetNode, Service: o.service,
	}
	if o.kind == "publish" {
		m.UUID, err = randomUUID()
		if err != nil {
			return fmt.Errorf("generate publish UUID: %w", err)
		}
		dir := filepath.Dir(path)
		m.Certificate = filepath.Join(dir, o.name+".crt")
		m.Key = filepath.Join(dir, o.name+".key")
		pin, err := makeCertificate(m.Certificate, m.Key)
		if err != nil {
			return err
		}
		m.CertificateSHA256 = pin
		fmt.Printf("UUID=%s\nPIN_SHA256=%s\n", m.UUID, pin)
	}
	p.Mappings = append(p.Mappings, m)
	return saveProfile(path, p)
}

func removeMapping(name, path string) error {
	if name == "" {
		return errors.New("--name is required")
	}
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	out := p.Mappings[:0]
	found := false
	for _, m := range p.Mappings {
		if m.Name == name {
			found = true
			continue
		}
		out = append(out, m)
	}
	if !found {
		return errors.New("mapping not found")
	}
	p.Mappings = out
	return saveProfile(path, p)
}

func renderFile(path, output string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	b, err := renderXray(p)
	if err != nil {
		return err
	}
	if output == "" {
		os.Stdout.Write(b)
		return nil
	}
	return os.WriteFile(output, b, 0600)
}

func runProfile(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	instances := make([]interface{ Close() error }, 0, len(p.Mappings))
	for _, m := range p.Mappings {
		var instance interface{ Close() error }
		if m.Kind == "pull" && m.TargetNode != "" {
			instance, err = startSmartPull(p, path, m)
		} else {
			instance, err = startMapping(m)
		}
		if err != nil {
			for _, running := range instances {
				_ = running.Close()
			}
			return err
		}
		instances = append(instances, instance)
	}
	defer func() {
		for _, instance := range instances {
			_ = instance.Close()
		}
	}()
	if p.Role == "relay" {
		relay, err := startRelayServer(p, path)
		if err != nil {
			return err
		}
		instances = append(instances, relay)
	}
	var coordinator *coordinatorRuntime
	var coordinatorErrors <-chan error
	if p.Role == "coordinator" {
		coordinator, coordinatorErrors, err = startCoordinator(path, p)
		if err != nil {
			return err
		}
		defer coordinator.Shutdown(context.Background())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if p.Coordinator.URL != "" {
		go runControlPlane(ctx, path)
	}
	ch := make(chan os.Signal, 1)
	signalNotify(ch)
	select {
	case <-ch:
		return nil
	case err := <-coordinatorErrors:
		return err
	}
}

func signalNotify(ch chan os.Signal) { signalNotifyPlatform(ch) }

func status(path string) error {
	p, err := loadProfile(path)
	if err != nil {
		return err
	}
	peers, _ := loadDiscovered(path)
	auth := "none"
	if p.Coordinator.Credential != nil {
		auth = "credential"
	} else if p.Coordinator.Enrollment != nil {
		auth = p.Coordinator.Enrollment.Status
		if auth == "" {
			auth = "pending"
		}
	}
	upstream := "-"
	if p.Role == "subnode" {
		upstream = p.Subnode.RelayNodeID + "@" + p.Subnode.RelayEndpoint
	}
	fmt.Printf("instance=%s role=%s network=%s segment=%s mappings=%d peers=%d coordinator=%s auth=%s upstream_relay=%s config=%s\n", p.Instance, p.Role, p.VirtualNetwork, p.Segment, len(p.Mappings), len(peers), p.Coordinator.URL, auth, upstream, path)
	if control, controlErr := loadControlStatus(path); controlErr == nil {
		fmt.Printf("heartbeat_last_ok=%s heartbeat_error=%q discovery_last_ok=%s discovery_revision=%d discovery_error=%q inbox_last_ok=%s inbox_cursor=%d inbox_waiting=%t inbox_error=%q\n",
			formatStatusTime(control.HeartbeatLastOK), control.HeartbeatError,
			formatStatusTime(control.DiscoveryLastOK), control.DiscoveryRevision, control.DiscoveryError,
			formatStatusTime(control.InboxLastOK), control.InboxCursor, control.InboxWaiting, control.InboxError)
	}
	return nil
}

func formatStatusTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(time.RFC3339)
}
func start(instance, path string, managed bool) error {
	if runtime.GOOS == "linux" && managed {
		unit := "mayoiga@" + instance + ".service"
		if exec.Command("systemctl", "--user", "is-active", "--quiet", unit).Run() == nil {
			c := exec.Command("systemctl", "--user", "restart", unit)
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			return c.Run()
		}
		c := exec.Command("systemctl", "--user", "enable", "--now", unit)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}
	return runProfile(path)
}
func stop(instance string, managed bool) error {
	if runtime.GOOS != "linux" || !managed {
		return errors.New("stop is managed by the invoking process on this platform")
	}
	c := exec.Command("systemctl", "--user", "disable", "--now", "mayoiga@"+instance+".service")
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
func uninstall(instance, path string, managed bool) error {
	if runtime.GOOS == "linux" && managed {
		_ = stop(instance, true)
	}
	if managed {
		return os.RemoveAll(filepath.Dir(path))
	}
	return os.Remove(path)
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
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "mayoiga"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"mayoiga"}}
	der, err := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", err
	}
	sum := x509.SHA256WithRSA // retain explicit algorithm intent
	_ = sum
	h := x509CertHash(der)
	return hex.EncodeToString(h), nil
}
func x509CertHash(der []byte) []byte { h := sha256Sum(der); return h[:] }

func splitAddress(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("%q must be host:port: %w", s, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, errors.New("invalid port")
	}
	return h, n, nil
}
