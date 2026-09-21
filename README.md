# GANJ VPS

GANJ VPS is the clean-room node installer and managed-node control agent for the GANJ gateway platform. Current agent version: **0.5.0**.

It is designed for servers running supported Xray panels such as Sanaei 3x-ui and PasarGuard, and connects them to a GANJ central gateway through a managed WireGuard control/data plane.

## Design goals

- One-command installer for Ubuntu servers
- Automatic or manual panel detection and connection
- Secure one-time node enrollment
- Per-node credentials; no shared master secret
- WireGuard peer provisioning
- 40 curated gateway locations with stable ports
- Central health, heartbeat and desired-state control
- WireGuard DNS endpoint refresh and local tunnel self-heal
- Multi-gateway ranking, best-ping selection and automatic failover
- Automatic desired-state reconciliation for locations
- Live throughput, active-connection and per-location latency status
- Hourly safe update checks with in-process handoff
- Source-controlled Central control plane and Representatives dashboard
- Multi-gateway ranking, Best-Ping selection and automatic failover
- Automatic desired-state reconciliation for newly available locations
- Live RX/TX Mbps, active inbound connections and per-location SOCKS latency
- Hourly safe auto-update checks with deferred self-restart
- Emerald/Gold CLI installer and controller UI
- Central endpoint hidden from the operator during installation
- Automatic local PasarGuard endpoint discovery; only admin credentials are requested for connection
- Explicit manual Core, template Inbound and Host selection
- Selected PasarGuard Host keeps all connection settings; only id, inbound linkage, per-location port and display remark change
- Host remark is set to the location flag + country + capital/city; domain/address, SNI, path, security, transport and other Host settings are preserved
- PasarGuard objects use a strict `ganj-XX` namespace so legacy/operator country Hosts are never claimed or deleted
- Core is saved first without restart; Hosts are verified; then one final Core/Node restart is issued
- Installer auto mode never auto-selects a production Core, Inbound or Host template
- Collision-aware automatic local port allocation
- PasarGuard Host cloning from the operator-selected template
- Safe GANJ-owned location generation with backups and isolated tags
- One-time enrollment tokens with license duration and optional traffic quota
- Per-node WireGuard usage accounting and entitlement enforcement
- Whitelisted central command queue (no arbitrary remote shell)
- Smooth cached live status with ONLINE / DEGRADED / OFFLINE / NO UPSTREAM states, diagnostics, update and uninstall commands

## Clean-room notice

GANJ VPS is an independent implementation. Other public projects may be reviewed only to understand externally visible product behavior and interoperability expectations. Their source code, branding, assets, text and implementation details are not copied into this repository.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh)"
```

The installer asks for the one-time enrollment token; the GANJ Central endpoint is not exposed as an installer question. The supported local panel is detected automatically when unambiguous. For PasarGuard, its local API URL is discovered automatically and the operator enters only the admin username/password for the connection. Core, template Inbound, Host and Host port policy are deliberately selected manually before any cloning or location sync.

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

- PasarGuard localhost/PROXY-protocol templates are automatically published through validated HAProxy frontends on ports 6000–6039

- PasarGuard Host templates must belong to the selected Inbound; incompatible Host/Inbound pairs are rejected before installation.


## Representative Web Panel

GANJ VPS includes a local representative dashboard bound to `127.0.0.1:9877`.
It is intentionally not exposed directly to the Internet. Publish it only through
an authenticated HTTPS reverse proxy on the representative server.

The mobile-first Emerald/Gold UI mirrors the node CLI capabilities:

- License traffic used/limit, live RX/TX, active connections and server CPU/RAM/disk
- 40-location health with ONLINE / DEGRADED / OFFLINE / NO UPSTREAM states
- PasarGuard status, Core/Inbound/Host template selection and local credential reconnect
- Location plan/sync/rebuild/remove
- Gateway ranking, Best Ping switch, add/remove local gateways
- WireGuard and HAProxy health
- Central sync, reconcile, diagnostics, agent logs, update and uninstall

Security boundaries:

- Web backend listens on loopback only
- Passwords use Argon2id and are stored only in `/etc/ganj-vps/web-auth.json`
- Secure + HttpOnly + SameSite session cookies
- CSRF protection for all modifying actions
- Login rate limiting and audit log at `/var/log/ganj-vps/web-audit.jsonl`
- No arbitrary shell endpoint; maintenance operations are allow-listed
- Central control-plane URL, WireGuard endpoint and managed gateway endpoints are hidden
  from representative-facing APIs and logs

Configure a local web login with:

```bash
ganj-vps web-user --username representative
```

The service can be checked with:

```bash
ganj-vps web-status
systemctl status ganj-vps-web
```
