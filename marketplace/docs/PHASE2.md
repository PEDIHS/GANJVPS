# GANJ VPS Marketplace — Phase 2 design and bot update

This patch targets the **existing** `PEDIHS/GANJVPS` repository after baseline `d386bc8`.

## Included code changes

- **Telegram bot:** polished emerald/gold-aligned copy, colored action buttons (where supported), mini-app, account/wallet history, lightweight support tickets, all 4 shared-host operation requests (approval still required), IP copy button, callback navigation edits, callback acknowledgments.
- **Web app:** full responsive RTL emerald/gold redesign; desktop sidebar, mobile bottom bar, catalog cards, custom purchase modal (no raw `prompt` or `confirm`), owned nodes, wallet ledger, votes, tickets and owner console.
- **API:** additional authenticated wallet-transaction endpoint and read-only admin summaries for users, orders, tickets, finance and audit.
- **Tests:** extended API access control, ledger and bot tests, plus retained concurrency regression coverage. Existing infrastructure-agent files are not changed.

## Security and deployment

No Telegram bot token, webhook secret, admin key, SSH key, server password or API credential is included.

Do not extract this patch blindly over a production working tree: review and commit changes to a separate Git branch, run existing CI, and only then update the dedicated `ganj-vps-marketplace.service`.

The previously shared Telegram token is considered compromised; its user-requested reuse cannot be considered a secure long-term deployment. Keep it server-only if temporarily used for testing; rotate it before enabling real customers and financial actions.

Example testing command from the repository root:

```
cd marketplace
PYTHONPATH=. pytest -q tests
node --check /tmp/extracted-inline-script.js  # the HTML inline JS may be extracted to a temp JS file
```

Production readiness: **not** a live marketplace launch. PasarGuard / Rebecca / Marzban provisioning, actual provider reboot/power/IP operations, receipts/payment reconciliation and administrator workflows beyond current APIs remain unimplemented or unvalidated. Existing flags `DRY_RUN=true` and `ENABLE_HOST_OPERATIONS=false` must remain unchanged.

For safety, existing `.env` files, database schema/records, HTTPS, HAProxy and node-agent code are not part of this patch.
