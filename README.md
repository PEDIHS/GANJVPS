# GANJ VPS

GANJ VPS is the clean-room node installer and control agent for the GANJ gateway platform.

It is designed for servers running supported Xray panels such as Sanaei 3x-ui and PasarGuard, and connects them to a GANJ central gateway through a managed WireGuard control/data plane.

## Design goals

- One-command installer for Ubuntu servers
- Automatic panel detection
- Secure one-time node enrollment
- Per-node credentials; no shared master secret
- WireGuard peer provisioning
- 30 curated gateway locations with stable ports
- Central health, heartbeat, desired-state and failover control
- Local panel adapters for Sanaei 3x-ui and PasarGuard
- Safe backup / validate / apply / rollback workflow
- Live status, diagnostics, update and uninstall commands

## Clean-room notice

GANJ VPS is an independent implementation. Other public projects may be reviewed only to understand externally visible product behavior and interoperability expectations. Their source code, branding, assets, text and implementation details are not copied into this repository.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh)"
```

The installer asks for the GANJ Central URL and a one-time enrollment token.

## CLI

```bash
ganj-vps
ganj-vps status
ganj-vps diagnostics
ganj-vps update
ganj-vps uninstall
```

## Security

Node secrets and panel credentials are stored only on the node under `/etc/ganj-vps/` with root-only permissions. The central service stores a hash of each node secret rather than the plaintext secret.

Copyright © 2026 GANJ VPS. All rights reserved.
