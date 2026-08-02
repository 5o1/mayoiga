"""Installation and operation."""


def operations():
    """# Operations

    Build and verify with `make build` and `make test`. `go.mod` defines the
    module. The executable is implemented by `cmd/mayoiga/main.go`,
    `cmd/mayoiga/node_manager.go`, `cmd/mayoiga/relay.go`,
    `cmd/mayoiga/render.go`, `cmd/mayoiga/xraycore.go`, and
    `cmd/mayoiga/hash.go`. Coordination and discovery are implemented in
    `cmd/mayoiga/coordinator.go` and tested by
    `cmd/mayoiga/coordinator_test.go`; platform signals are in
    `cmd/mayoiga/platform.go` and `cmd/mayoiga/platform_windows.go`. Tests
    live in `cmd/mayoiga/xraycore_test.go` and
    `cmd/mayoiga/node_manager_test.go`, `cmd/mayoiga/relay_test.go`, and the
    optional external `cmd/mayoiga/danted_integration_linux_test.go`.
    Long-poll connection control is implemented in
    `cmd/mayoiga/connections.go` and tested by
    `cmd/mayoiga/connections_test.go`. The
    multi-node supervisor is implemented in
    `cmd/mayoiga/service_manager.go`, with Linux integration in
    `cmd/mayoiga/service_linux.go`, portable fallbacks in
    `cmd/mayoiga/service_other.go`, and coverage in
    `cmd/mayoiga/service_manager_test.go`. The
    release binary embeds the
    separately maintained `cmd/mayoiga/locales/en.json` and
    `cmd/mayoiga/locales/zh_CN.json` resources.

    Create and register the destination, then publish a named service:

    ```bash
    ./mayoiga --instance home --action add --kind publish --name nas \
      --listen 0.0.0.0:28443 \
      --target 192.168.1.20:5000
    ```

    The coordinator distributes the service's generated UUID and certificate
    pin to authenticated nodes. Consumers use `--target-node NODE_ID
    --service nas`; no credentials are copied manually. A relay is configured
    at node creation and serves registered services in its own segment.
    A subnode additionally names one registered same-segment relay as its
    fixed control- and data-plane gateway. Relay creation prints a
    `SUBNODE_RELAY_TOKEN` once; keep it private and pass it to every allowed
    subnode with `--upstream-relay-token`.
    Rotate a leaked token with `configure-node --rotate-relay-token`, then
    update every affected subnode before restarting it.

    Profiles live in `~/.config/mayoiga/nodes/<instance>/profile.json`. Use
    `--action list-nodes`, or target a node with `--instance NAME --action
    configure-node|status|start|stop|delete-node`; deletion also requires
    `--yes`. There is one rootless supervisor for all standard profiles:
    Linux `--action service-install` creates
    `~/.config/systemd/user/mayoiga.service`, then `--action service-start`
    starts every enabled node. `--action start` enables one node and starts
    that manager; `--action stop` disables one node. Do not run a separate
    per-instance systemd unit. Containers and Windows run `--action
    service-run` as their foreground command. A bind-mounted data directory is
    selected with `--manager-dir /data/mayoiga`; it must contain `nodes/`.
    The manager scans every five seconds. It starts added/enabled nodes, stops
    disabled/deleted nodes, and fully restarts a changed profile only after its
    old process exits. It performs static validation first and retains the
    last valid worker if a changed profile is invalid. Existing TCP sessions
    end during a successful configuration restart. Failed node processes are
    retried with exponential backoff capped at 30 seconds. The manager does
    not manage Docker restart policy, SSH, DDNS, or published applications.
    No legacy profile migration exists.
    Coordinator and relay listener addresses require explicit `host:port`
    values with numeric ports from 1 to 65535; port zero is invalid. A
    published service does not accept an external endpoint or advertised node
    address. On every heartbeat, mayoiga derives private-LAN candidates from
    the publish listener and active local interfaces. The coordinator grants
    each candidate a 90-second lease and distributes it only inside that
    segment. Use `0.0.0.0:PORT` for a publish listener when same-LAN direct
    access is wanted; use a loopback listener to require relay access. Creation
    checks live port occupancy and declarations in other local node profiles,
    including stopped nodes, before saving.

    The coordinator's connection queue is configured explicitly with
    `--connection-wait-seconds`, `--connection-request-ttl-seconds`,
    `--connection-offer-lease-seconds`, and `--connection-max-pending`.
    Use `request-connection`, `wait-connection`, `connection-status`, and
    `cancel-connection` at the source; use `connection-inbox`,
    `accept-connection`, or `reject-connection` at the target. Reuse
    `--idempotency-key` only when retrying the same logical request.
    Delivery is at least once: the client writes `connection-inbox.json`
    before ACK, and an unhandled offer is redelivered after its lease.
    `status` exposes heartbeat, discovery, and inbox errors independently.
    Coordinator failures use a JSON response with a stable `code` and safe
    human-readable `message`; the CLI displays the code and localizes known
    failures. Relay failures use the same stable code in their TLS handshake
    response. Use `--reason TEXT` with `reject`, `reject-connection`, or
    `cancel-connection` to persist an explanation for the other node.
    A pull hosted by a relay automatically uses an on-demand reverse
    connection when no current coordinator candidate is usable. The publisher
    initiates the encrypted data stream to the relay; it must keep its node
    process and inbox worker running, but no permanent data tunnel, fixed
    publisher endpoint, or inbound target port is required.

    `.github/workflows/release.yml` builds Linux and Windows amd64 archives.
    """
    from docs.troubleshooting import troubleshooting
    troubleshooting()
