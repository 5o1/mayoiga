"""Role entry points for mayoiga nodes."""


def client():
    """# Client

    A client publishes named services and opens local pull ports. Routing is
    direct in the same segment and uses target-segment relays when needed:

    ```bash
    ./mayoiga --instance school --role client --segment school --action add-node
    ./mayoiga --instance school --action add --kind pull --name nas \
      --listen 127.0.0.1:9000 --target-node NODE_ID --service nas
    ./mayoiga --instance school --action start
    ```

    Applications connect to `127.0.0.1:9000`. The mapping is TCP only.
    Add `--coordinator`, `--coordinator-pin`, and `--network` during
    installation. The node prints a one-time device code; after coordinator
    approval it saves an Ed25519 credential and joins discovery automatically.
    `--action nodes` displays active peers learned by heartbeat.
    """
    from docs.architecture import architecture
    from docs.operations import operations
    from docs.security import security
    architecture(); operations(); security()


def gateway():
    """# Gateway

    Gateway remains a descriptive client role. Transit capability belongs to
    the `relay` role; no source-side gateway is required. A gateway can still
    publish services and create automatic pulls like any client.
    """
    from docs.architecture import architecture
    from docs.operations import operations
    architecture(); operations()


def relay():
    """# Relay

    Relay is a strict superset of client capability: it can publish and consume
    services and also accepts signed TLS 1.3 transit requests. Configure
    `--transit-listen`, `--transit-endpoint`, and `--relay-priority` while
    joining a coordinator. Cross-segment access to services published by the
    relay itself also enters this transit listener, so those publish endpoints
    may remain local; same-segment access remains direct. Normal transit
    terminates at registered services in its own segment. When serving as a
    subnode's declared upstream it may
    continue through the normal target-side route. Multiple target-segment
    relays are attempted by priority; direct target access is the final
    fallback. Ordinary clients do not require a source-side relay.
    """
    from docs.architecture import architecture
    from docs.security import security
    architecture(); security()


def subnode():
    """# Subnode

    A subnode is a client without direct WAN access. It specifies exactly one
    same-segment relay using `--upstream-relay-node`,
    `--upstream-relay-endpoint`, and `--upstream-relay-pin`. Enrollment,
    polling, discovery, and outgoing mappings use that relay; the coordinator
    TLS session remains end-to-end pinned inside the relay tunnel.

    The upstream relay must already be active and registered. The coordinator
    verifies that it is a relay in the subnode's segment. Other nodes also
    reach a published subnode service through that fixed relay, without direct
    fallback. This affects mayoiga traffic only and does not install a default
    operating-system route.
    """
    from docs.architecture import architecture
    from docs.security import security
    architecture(); security()


def coordinator():
    """# Coordinator

    The coordinator runs an HTTPS registration and discovery API. Install it:

    ```bash
    ./mayoiga --role coordinator --node-name control --network family \
      --instance control --listen 0.0.0.0:18443 \
      --admin-listen 127.0.0.1:19443 --action add-node
    ./mayoiga --instance control --action start
    ```

    Installation prints its TLS certificate pin. A joining node submits a
    ten-minute handshake and displays a device code. Review and decide locally:

    ```bash
    ./mayoiga --instance control --action handshakes
    ./mayoiga --instance control --action approve --device-code ABCD-EFGH
    ./mayoiga --instance control --action reject --device-code ABCD-EFGH
    ```

    Filter history with `--handshake-status 100|200|201|403|410`. The node
    generates its Ed25519 key pair locally and submits only the public key.
    Use `--replace-existing` only for an intentional credential replacement,
    or `--action revoke --node-id ID` to remove access. `--action audit`
    displays bounded persistent security events. `--admin-listen` must be
    loopback-only. No port has an implicit default; creation rejects
    occupied or overlapping ports. Registry and audit state is stored in
    `coordinator-state.json`; mapped application traffic stays outside it.
    """
    from docs.operations import operations
    from docs.security import security
    operations(); security()
