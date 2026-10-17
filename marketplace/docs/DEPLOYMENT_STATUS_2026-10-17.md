# GANJ VPS Marketplace — deployment record (2026-10-17)

Status: **safe-mode web/API deployed**, not yet a live sellable node provisioning product.

## Running on the authorized server

- Domain: `https://vps.pedramhs.ir`
- GitHub repository: `PEDIHS/GANJVPS`
- Deployed code at record time: `546d759` (main)
- Isolated unit: `ganj-vps-marketplace.service`, enabled, running as unprivileged Linux user `ganjmarket`
- HTTP application: FastAPI/Uvicorn at `127.0.0.1:8800` (not bound publicly)
- Database: PostgreSQL 16, dedicated `ganj_marketplace` DB, Unix-socket peer auth
- Dedicated Nginx domain virtual host behind existing HAProxy SNI TCP frontend on port 443, Nginx loopback TLS on `127.0.0.1:9444`
- Independent Let's Encrypt certificate for `vps.pedramhs.ir`, expires 2027-01-14; email configured in Certbot (not a secret)
- Certbot timer active, deploy hook for VPS certificate nginx reload. Certificate `certonly --dry-run --webroot` **succeeded**.
- Encrypted database backups in `/var/backups/ganj-vps-marketplace`, timer `ganj-vps-db-backup.timer` active, 03:40 and 15:40 server time with randomized delay; first encrypted backup and decrypt/pg_restore-list validation **succeeded**. Key is root-only under `/etc/ganj-vps-marketplace/backup.passphrase`. Off-host backup / independent key custody still pending.
- Environment file: `/etc/ganj-vps-marketplace/marketplace.env`, file restricted to root and application service group. Generated random session, webhook and back-office key; **do not print or commit**.

## Verified checks

- `https://vps.pedramhs.ir/`: HTTP 200, TLS verify 0
- `http://vps.pedramhs.ir/`: HTTP 301 to HTTPS
- `https://vps.pedramhs.ir/healthz`: HTTP 200, app is healthy
- `/api/v1/admin/summary` without authentication: HTTP 401
- Existing `https://trade.pedramhs.ir/`: HTTP 200, TLS verify 0, unchanged routing
- Marketplace tests on live host: **11 passed**, one dependency deprecation warning
- GitHub workflows: both existing CI and dedicated Marketplace CI passed on the wallet serialization PR

## Safety locks / remaining work

- The previously pasted Telegram bot token is exposed and MUST be revoked via BotFather. **Do not reuse it.**
- `TELEGRAM_BOT_TOKEN` intentionally remains empty. Telegram webhook NOT registered. Mini App authentication cannot be used until a freshly rotated token is loaded securely.
- `DRY_RUN=true` and `ENABLE_HOST_OPERATIONS=false`: no host power, restart, IP change, or node execution can run through the marketplace.
- Provisioning jobs remain `awaiting_connector`. No PasarGuard/Rebecca/Marzban real-world runtime installer or customer secret handoff has been validated.
- Catalog is currently empty (no inventory fabricated).
- Real payment settlement, full admin UX/RBAC, migrations, off-site encrypted backup, provider API permissions/rollback, and load/security testing remain before real customer launch.
- Marketplace is intentionally separate from the original GANJ managed-node agent and does not reuse network/agent credentials.

## Operations

```bash
systemctl status ganj-vps-marketplace
systemctl status ganj-vps-db-backup.timer
systemctl status certbot.timer
curl -fsS https://vps.pedramhs.ir/healthz
```

For safe rollback: stop only `ganj-vps-marketplace.service`, and restore the newest **VPS-only** Nginx config backup under `/etc/nginx/sites-available/vps.pedramhs.ir.backup-*`, test Nginx and reload. Do not alter the HAProxy reality or trade virtual host.

Never print `marketplace.env`, token files, private keys, or the backup passphrase in chat/logs.
