package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
			o.coordinator, o.coordinatorPin, o.listen, o.adminListen = p.Coordinator.URL, p.Coordinator.PinnedSHA256, p.Server.Listen, p.Server.AdminListen
			o.transitListen, o.transitEndpoint, o.relayPriority = p.Relay.Listen, p.Relay.Endpoint, p.Relay.Priority
			o.upstreamRelayNode, o.upstreamRelayEndpoint, o.upstreamRelayPin =
				p.Subnode.RelayNodeID, p.Subnode.RelayEndpoint, p.Subnode.RelayPinnedSHA256
			o.upstreamRelayToken = p.Subnode.RelayToken
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
				askSecretEdit(in, m["prompt.upstream_relay_token"], &o.upstreamRelayToken, "upstream-relay-token", o.set, configure)
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
		if o.action == "reject" {
			fmt.Print(m["prompt.reason"])
			in.Scan()
			o.reason = strings.TrimSpace(in.Text())
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
	if o.action == "reject-connection" || o.action == "cancel-connection" {
		fmt.Print(m["prompt.reason"])
		in.Scan()
		o.reason = strings.TrimSpace(in.Text())
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

func askSecretEdit(in *bufio.Scanner, prompt string, target *string, flagName string, set map[string]bool, preserve bool) {
	if preserve && *target != "" {
		fmt.Printf("%s[configured] ", prompt)
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
	fmt.Printf("%s[%d] ", prompt, *target)
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
