# mayoiga

mayoiga is designed for university students who need to access a home NAS,
Minecraft server, or self-hosted service from campus. It maps individual TCP
ports end to end: it does not publish applications directly to the public
Internet and does not route all device traffic. This reduces exposure and
avoids conflicts with other networking software.

## Role Configuration Examples

Replace the example hosts, pins, node IDs, and ports with your own values.
Every node joining a coordinator displays a one-time device code that must be
approved on the coordinator.

### Coordinator

```bash
mayoiga --instance control --role coordinator --network family \
  --listen 0.0.0.0:18443 --admin-listen 127.0.0.1:19443 \
  --action add-node
mayoiga --instance control --action start
mayoiga --instance control --action approve --device-code ABCD-EFGH
```

### Client

```bash
mayoiga --instance school --role client --network family --segment campus \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
mayoiga --instance school --action add --kind pull --name home-nas \
  --listen 127.0.0.1:9000 --target-node <HOME_NODE_ID> --service nas
mayoiga --instance school --action start
```

### Gateway

A gateway is a descriptive client role and can publish or pull services:

```bash
mayoiga --instance lan-gateway --role gateway --network family --segment home \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
```

### Relay

```bash
mayoiga --instance home-relay --role relay --network family --segment home \
  --transit-listen 0.0.0.0:29443 \
  --transit-endpoint home.example:29443 --relay-priority 10 \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
mayoiga --instance home-relay --action add --kind publish --name nas \
  --listen 127.0.0.1:28443 --endpoint 127.0.0.1:28443 \
  --target 192.168.1.20:5000
mayoiga --instance home-relay --action start
```

### Subnode

```bash
mayoiga --instance offline-node --role subnode --network family --segment home \
  --upstream-relay-node <RELAY_NODE_ID> \
  --upstream-relay-endpoint 192.168.1.10:29443 \
  --upstream-relay-pin <RELAY_PIN> \
  --coordinator https://home.example:18443 --coordinator-pin <PIN> \
  --action add-node
```

## Licenses

mayoiga is released under the [MIT License](LICENSE), copyright 2026
[5o1](https://github.com/5o1).

mayoiga embeds selected components from
[XTLS/Xray-core](https://github.com/XTLS/Xray-core), licensed under the
[Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
The Go toolchain and standard library are distributed under the
[Go license](https://go.dev/LICENSE). Transitive Go modules listed in
`go.mod` retain their respective upstream copyright notices and licenses.
