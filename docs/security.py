"""Security guidance."""


def security():
    """# Security

    Keep `profile.json` and generated `.key` files private. Published-service
    UUIDs and certificate pins are shared by the coordinator only with
    authorized members of the same virtual network. Bind pull listeners to
    `127.0.0.1` on shared machines. Publishers
    should expose only their chosen encrypted listener; targets remain
    reachable solely from the publisher.

    TLS 1.3 protects every hop and certificate pinning prevents silent
    interception with an unrelated certificate. VLESS supplies authentication,
    not encryption by itself. Relay operators can observe endpoints and
    traffic timing. This design does not attempt to guarantee protocol
    indistinguishability or bypass network policy; obtain authorization before
    deploying it on managed networks.

    Coordinator enrollment uses TLS 1.3 certificate pinning, a random
    single-use device code, and a separate high-entropy polling secret. Codes
    expire after ten minutes. The node generates its Ed25519 credential
    locally and sends only the public key; the coordinator never receives the
    private key. Requests include timestamps and nonces to resist replay.
    Public requests are rate-limited, pending requests and history are bounded,
    and management uses a separate loopback-only listener. Existing node IDs
    require explicit replacement approval, credentials can be revoked, and
    `--action audit` reports persistent security events.
    Protect
    `profile.json`, because the node private credential is stored there with
    mode 0600. Handshake history never retains private keys or polling secrets.

    Relay transit uses TLS 1.3 certificate pinning plus the source node's
    Ed25519 signature. The signed request binds the virtual network, source,
    selected relay, target node, service, timestamp, and nonce. A relay only
    resolves only coordinator-registered services. Normal transit terminates
    in its own segment; a registered subnode may use its declared upstream
    relay to continue through the normal target-side routing rules. It cannot
    request an arbitrary LAN socket. Failover completes before application
    bytes are sent.

    A subnode's pre-enrollment relay tunnel is not yet node-signed, because no
    approved credential exists. It is restricted to the relay's configured
    coordinator and remains protected by both the pinned outer relay TLS
    connection and the independently pinned inner coordinator TLS connection.
    After approval, discovery and service requests retain the node's normal
    Ed25519 signatures. Possession of a relay pin does not grant coordinator
    approval.

    Connection requests are signed, rate-limited, bounded globally and per
    target, and limited to an active target's registered service in the same
    virtual network. Idempotency keys prevent duplicate creation; monotonic
    cursors, persisted acknowledgements, offer leases, expiry, cancellation,
    and terminal decisions make retries recoverable across restarts. Inbox
    polling is separate from heartbeat and transports metadata, not
    application bytes. An on-demand reverse connection is accepted only by
    the named source relay while it holds a matching request expectation for
    the target node and registered service. The target signs the reverse
    handshake, uses the relay's pinned TLS certificate, and connects only to
    its own local publish. Application bytes then use that separate
    authenticated transit connection.
    """
