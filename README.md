# mayoiga

mayoiga is designed for university students who need to access a home NAS,
Minecraft server, or self-hosted service from campus. It maps individual TCP
ports end to end: it does not publish applications directly to the public
Internet and does not route all device traffic. This reduces exposure and
avoids conflicts with other networking software.

## Deployment Topologies

Replace the example hosts, pins, node IDs, and ports with your own values.
Every node joining a coordinator displays a one-time device code that must be
approved on the coordinator.

### Minimum: coordinator and clients

The minimum control plane is one coordinator and one or more clients. The
coordinator only authenticates nodes and distributes discovery information; it
is not in the application data path. A usable end-to-end mapping needs a
second client (or relay) to publish the target service.

#### Coordinator

```bash
mayoiga --instance control --role coordinator --network family \
  --listen 0.0.0.0:18443 --admin-listen 127.0.0.1:19443 \
  --action add-node
mayoiga --instance control --action start
# Enter the device code printed when a client is added.
mayoiga --instance control --action approve --device-code ABCD-EFGH
```

#### Client

```bash
mayoiga --instance school --role client --network family --segment campus \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
mayoiga --instance school --action add --kind pull --name home-nas \
  --listen 127.0.0.1:9000 --target-node <HOME_NODE_ID> --service nas
mayoiga --instance school --action start
```

### NAT-restricted clients: add a relay

When two clients cannot make a direct connection because they are both behind
restrictive NATs, add a reachable relay. Each endpoint uses the relay's
encrypted connection path, so either side can publish a service and the other
can pull it. Direct private-LAN access remains preferred when it is available.

```bash
mayoiga --instance home-relay --role relay --network family --segment home \
  --transit-listen 0.0.0.0:29443 \
  --transit-endpoint home.example:29443 --relay-priority 10 \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
mayoiga --instance home-relay --action start
```

The relay is also a client: it may publish services itself, for example a NAS
on its reachable LAN:

```bash
mayoiga --instance home-relay --action add --kind publish --name nas \
  --listen 0.0.0.0:28443 \
  --target 192.168.1.20:5000
```

### LAN-only machines: use a subnode

A client on a LAN-only machine with no wide-area network access is a
**subnode**. It needs a directly reachable relay in the same segment. That
relay forwards its coordinator registration, discovery, and service traffic;
the subnode does not need a public endpoint or its own Internet route.

```bash
mayoiga --instance offline-node --role subnode --network family --segment home \
  --upstream-relay-node <RELAY_NODE_ID> \
  --upstream-relay-endpoint 192.168.1.10:29443 \
  --upstream-relay-pin <RELAY_PIN> \
  --upstream-relay-token <SUBNODE_RELAY_TOKEN> \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
```

When a relay is created, it prints `SUBNODE_RELAY_TOKEN` once. Store it as a
secret and provide it only to subnodes that may use that relay for coordinator
access. An existing relay receives its first token when you run `configure-node`.
To revoke the previous token, run `mayoiga --instance home-relay --action
configure-node --rotate-relay-token`; update every permitted subnode with the
new token.

## Licenses

mayoiga is released under the [MIT License](LICENSE), copyright 2026
[5o1](https://github.com/5o1).

mayoiga embeds selected components from
[XTLS/Xray-core](https://github.com/XTLS/Xray-core), licensed under the
[Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
The Go toolchain and standard library are distributed under the
[Go license](https://go.dev/LICENSE). Transitive Go modules listed in
`go.mod` retain their respective upstream copyright notices and licenses.
