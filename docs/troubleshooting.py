"""Troubleshooting."""


def troubleshooting():
    """# Troubleshooting

    Run `./mayoiga --instance NAME --action status` and inspect
    `journalctl --user -u mayoiga@NAME`. Use `--action render` with the same
    instance to inspect generated Xray JSON without starting listeners.

    Connection failures usually mean a published or transit listener is
    firewalled, router forwarding is missing, or its advertised `--endpoint`
    is wrong. Run `--action nodes` to verify the target node ID, service, relay
    priority, and last heartbeat. A successful encrypted connection followed
    by refusal means the publisher cannot reach its configured `--target`.

    Ports below 1024 normally cannot be bound rootlessly on Linux. Prefer a
    high external port such as 18443 and forward public port 443 at the router
    if required.

    If `--action sync` reports a certificate mismatch, compare the configured
    coordinator pin with `COORDINATOR_PIN`. A pending node needs its displayed
    device code approved before the ten-minute deadline. A rejected node
    reports `upstream coordinator rejected the handshake`; use
    `--action configure-node` with corrected coordinator options to create a
    new request. HTTP 401 after enrollment
    means the saved signing credential is unknown or invalid. `--action nodes`
    reads the last successful `peers.json` cache.

    For a subnode, first verify that `--upstream-relay-endpoint` is reachable
    on the local segment and that `--upstream-relay-pin` and
    `--upstream-relay-node` identify that exact relay. The relay must be active,
    registered to the same coordinator, and currently advertising the same
    virtual network and segment. A subnode never falls back to direct WAN
    coordinator or service access.

    `status` reports heartbeat, discovery, and connection-inbox health
    separately. An empty inbox response after the configured wait interval is
    normal; it is not a heartbeat failure. Use `connection-inbox` to inspect
    locally persisted offers. If a target crashes after receiving an offer but
    before deciding it, the coordinator redelivers it with a new cursor after
    the offer lease. Reusing the original idempotency key returns the original
    request rather than creating another one.
    """
