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
      --listen 0.0.0.0:28443 --endpoint home.example:28443 \
      --target 192.168.1.20:5000
    ```

    The coordinator distributes the service's generated UUID and certificate
    pin to authenticated nodes. Consumers use `--target-node NODE_ID
    --service nas`; no credentials are copied manually. A relay is configured
    at node creation and serves registered services in its own segment.
    A subnode additionally names one registered same-segment relay as its
    fixed control- and data-plane gateway.

    Profiles live in `~/.config/mayoiga/nodes/<instance>/profile.json`. Use
    `--action list-nodes`, or target a node with `--instance NAME --action
    configure-node|status|start|stop|delete-node`; deletion also requires
    `--yes`. Linux can create the rootless template
    `~/.config/systemd/user/mayoiga@.service`, with one service per instance.
    For unattended multi-node hosts, use `--action service-install` followed
    by `--action service-start`. Containers run `--action service-run` as
    their foreground command. A bind-mounted data directory is selected with
    `--manager-dir /data/mayoiga`; it must contain `nodes/`. The manager scans
    `nodes/` every five seconds:
    it starts added nodes, restarts changed nodes, stops deleted nodes, and
    restarts failures with exponential backoff capped at 30 seconds. It does
    not manage Docker restart policy, SSH, DDNS, or published applications.
    Windows currently uses `--action service-run`; OS service installation is
    not yet available. No legacy migration exists.
    Coordinator URLs and all endpoints require explicit `host:port` values
    with numeric ports from 1 to 65535; port zero is invalid. Creation checks
    live port occupancy and declarations in other local node profiles,
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
    A pull hosted by a relay automatically uses an on-demand reverse
    connection after ordinary relay/direct paths fail. The target must keep
    its node process and inbox worker running, but no permanent data tunnel or
    inbound target port is required.

    `.github/workflows/release.yml` builds Linux and Windows amd64 archives.
    """
    from docs.troubleshooting import troubleshooting
    troubleshooting()
