"""Architecture documentation."""


def architecture():
    """# Architecture

    mayoiga is an application-level TCP socket mapper, not an IP VPN.
    Its single Go binary embeds selected Xray-core components and deliberately
    does not register WireGuard. Each encrypted hop is VLESS over TLS 1.3 and
    TCP, authenticated by UUID and a pinned self-signed certificate.

    `publish` registers a named encrypted service. `pull` names a target node
    and service and chooses its path for every new TCP connection. A relay is
    a client with an additional TLS 1.3 transit capability. Therefore:

    - same segment: connect directly to `publish`;
    - cross-segment relay target: enter that target's own transit listener,
      which then connects to its local `publish`;
    - ordinary cross-segment target: try relays in the target segment;
    - unusable/no target-segment relay: fall back to direct `publish`.
    - subnode source: always enter its configured upstream relay first;
    - subnode target: always use the target's registered upstream relay and
      never fall back to a direct connection.

    Relay candidates are ordered by configured priority and node ID. A failed
    candidate is cooled for 30 seconds. Failover occurs during the signed
    transit handshake, before application bytes are sent. The relay request
    identifies a registered node/service, never an arbitrary socket.

    The optional coordinator is a separate HTTPS control plane. Nodes specify
    its URL, certificate pin, and virtual-network name. Initial enrollment uses
    a ten-minute device code. The node generates its Ed25519 key pair locally;
    after approval it stores the credential and signs subsequent
    requests using a timestamp, nonce, and body hash. Heartbeat, revision-based
    discovery, and connection-request inbox polling are independent workers:
    a stalled inbox cannot suppress liveness, and unchanged topology does not
    rewrite `peers.json`. Nodes cache discovery in `peers.json`, inbox offers
    in `connection-inbox.json`, and worker health in `control-status.json`.
    The coordinator persists public keys, registrations, status-coded
    handshake history, connection requests, cursors, acknowledgements, and
    offer leases in `coordinator-state.json`. Discovery exchanges names,
    roles, segments, advertised endpoints, and published-service connection
    credentials with authorized members of that virtual network, but never
    node private keys.

    The signed inbox long poll carries connection intent only. Requests pass
    through queued, offered, and a terminal accepted, rejected, canceled, or
    expired state. If a pull running on a relay cannot reach an ordinary
    target directly, it registers an expectation and names itself as the
    return relay. The target long-poll worker connects outward to that relay,
    authenticates a request-bound reverse transit handshake, and bridges its
    local publish. Application bytes never pass through the coordinator.

    A subnode has no direct WAN control-plane route. Its HTTP transport first
    opens a pinned TLS tunnel to its fixed same-segment relay. The relay permits
    that tunnel to reach only its own configured coordinator. The subnode then
    creates and pins the normal coordinator TLS connection inside the tunnel.

    Listeners and targets remain explicit per mapping, so a multi-user workstation only
    exposes ports bound in its profile. Discovery does not route an entire LAN.
    """
