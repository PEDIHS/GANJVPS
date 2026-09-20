# GANJ VPS

GANJ VPS is the clean-room node installer and managed-node control agent for the GANJ gateway platform. Current agent version: **0.4.0**.

It is designed for servers running supported Xray panels such as Sanaei 3x-ui and PasarGuard, and connects them to a GANJ central gateway through a managed WireGuard control/data plane.

## Design goals

- One-command installer for Ubuntu servers
- Automatic or manual panel detection and connection
- Secure one-time node enrollment
- Per-node credentials; no shared master secret
- WireGuard peer provisioning
- 30 curated gateway locations with stable ports
- Central health, heartbeat and desired-state control
- WireGuard DNS endpoint refresh and local tunnel self-heal
- Multi-gateway ranking, Best-Ping selection and automatic failover
- Automatic desired-state reconciliation for newly available locations
- Live RX/TX Mbps, active inbound connections and per-location SOCKS latency
- Hourly safe auto-update checks with deferred self-restart
- Interactive core/inbound selection for Sanaei 3x-ui and PasarGuard\n- Collision-aware automatic local port allocation\n- Automatic PasarGuard Host cloning with selectable port policy
- Safe GANJ-owned location generation with backups and isolated tags
- One-time enrollment tokens with license duration and optional traffic quota
- Per-node WireGuard usage accounting and entitlement enforcement
- Whitelisted central command queue (no arbitrary remote shell)
- Live status, diagnostics, update and uninstall commands

## Clean-room notice

GANJ VPS is an independent implementation. Other public projects may be reviewed only to understand externally visible product behavior and interoperability expectations. Their source code, branding, assets, text and implementation details are not copied into this repository.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh)"
```

The installer asks for the GANJ Central URL and a one-time enrollment token. After enrollment it can optionally guide the operator through local panel configuration and location installation.

## CLI

```bash
ganj-vps
ganj-vps status
ganj-vps diagnostics
ganj-vps panel-configure
ganj-vps panel-status
ganj-vps locations-list
ganj-vps locations-install
ganj-vps locations-remove
ganj-vps gateways
ganj-vps gateway-add <host:port> --name <name>
ganj-vps gateway-switch best
ganj-vps gateway-remove <id|name|endpoint>
ganj-vps reconcile --force
ganj-vps update
ganj-vps uninstall
```

## Security

Node secrets and panel credentials are stored only on the node under `/etc/ganj-vps/` with root-only permissions. The central service stores a hash of each node secret rather than the plaintext secret. Customer panel credentials are never sent to the GANJ control plane.

Central actions are restricted to an allow-list such as diagnostics, panel status, location sync/removal and WireGuard restart. GANJ VPS intentionally has no arbitrary remote-shell command endpoint.

See `docs/ARCHITECTURE.md` and `docs/CLEAN_ROOM.md` for the architecture and development policy.

Copyright © 2026 GANJ VPS. All rights reserved.
