package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

var version = "dev"

type options struct {
	lang, role, action, segment, name, kind                    string
	listen, adminListen, target, targetNode, service           string
	transitListen, transitEndpoint                             string
	upstreamRelayNode, upstreamRelayEndpoint, upstreamRelayPin string
	upstreamRelayToken                                         string
	requestID, idempotencyKey                                  string
	reason                                                     string
	config, output, coordinator, coordinatorPin, deviceCode    string
	managerDir                                                 string
	network, nodeName, nodeID, instance                        string
	handshakeStatus                                            int
	relayPriority                                              int
	connectionWaitSeconds, connectionTTLSeconds                int
	connectionLeaseSeconds, connectionMaxPending               int
	set                                                        map[string]bool
	yes, replaceExisting, rotateRelayToken, showVersion        bool
}

func Run() {
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
	flag.StringVar(&o.nodeName, "node-name", "", "node display name (default: hostname)")
	flag.StringVar(&o.nodeID, "node-id", "", "authorized node ID")
	flag.StringVar(&o.requestID, "request-id", "", "connection request ID")
	flag.StringVar(&o.idempotencyKey, "idempotency-key", "", "connection request idempotency key")
	flag.StringVar(&o.reason, "reason", "", "human-readable connection decision reason")
	flag.StringVar(&o.name, "name", "", "mapping name")
	flag.StringVar(&o.kind, "kind", "", "mapping kind: pull or publish")
	flag.StringVar(&o.listen, "listen", "", "listen address in host:port form")
	flag.StringVar(&o.adminListen, "admin-listen", "", "coordinator loopback-only admin listen address")
	flag.StringVar(&o.target, "target", "", "reachable target address for publish")
	flag.StringVar(&o.targetNode, "target-node", "", "target node ID for an automatic pull")
	flag.StringVar(&o.service, "service", "", "published service name for an automatic pull")
	flag.StringVar(&o.transitListen, "transit-listen", "", "relay transit listen address")
	flag.StringVar(&o.transitEndpoint, "transit-endpoint", "", "reachable relay transit endpoint")
	flag.StringVar(&o.upstreamRelayNode, "upstream-relay-node", "", "upstream relay node ID for a subnode")
	flag.StringVar(&o.upstreamRelayEndpoint, "upstream-relay-endpoint", "", "reachable upstream relay endpoint for a subnode")
	flag.StringVar(&o.upstreamRelayPin, "upstream-relay-pin", "", "upstream relay certificate SHA-256 for a subnode")
	flag.StringVar(&o.upstreamRelayToken, "upstream-relay-token", "", "relay admission token for a subnode")
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
	flag.BoolVar(&o.rotateRelayToken, "rotate-relay-token", false, "replace a relay's subnode admission token")
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
	activeMessages = msg
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
		return stop(path, o.config == "")
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
		return rejectDeviceCode(path, o.deviceCode, o.reason)
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
		return decideConnectionCLI(path, o.requestID, "accept", o.reason)
	case "reject-connection":
		return decideConnectionCLI(path, o.requestID, "reject", o.reason)
	case "cancel-connection":
		return decideConnectionCLI(path, o.requestID, "cancel", o.reason)
	case "run":
		return runProfile(path)
	default:
		return fmt.Errorf("unknown action %q", o.action)
	}
}
