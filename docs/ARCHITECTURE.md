# GANJ VPS architecture

## Control plane

The GANJ central service issues one-time enrollment tokens, registers managed nodes, stores only hashes of per-node secrets, records heartbeat state, publishes desired state, and queues a small whitelist of node actions.

Node API authentication uses a unique bearer secret plus node ID. Arbitrary remote shell execution is deliberately not part of the protocol.

## Data plane

Each managed node creates its own WireGuard keypair. Only the public key is sent to the central service. The central peer manager assigns a private address and applies the peer to the gateway interface.

The node receives routes only for the GANJ private gateway network.

## Panel adapters

Supported adapters:

- Sanaei 3x-ui
- PasarGuard

Panel credentials are stored locally under /etc/ganj-vps with root-only permissions. The central service never receives those credentials.

Location installation follows backup -> generate -> apply -> verify semantics and uses GANJ-owned prefixes so unrelated panel objects are not intentionally modified.

## Location routing

The central gateway publishes a curated 30-location catalog. Each country has a stable private SOCKS port. Panel adapters create local country inbounds and route them to the corresponding private gateway port over WireGuard.

## Central commands

The command protocol is allow-list based. Supported actions are limited to:

- sync
- panel_status
- locations_install
- locations_remove
- diagnostics
- wg_restart

There is no arbitrary command or shell endpoint.
