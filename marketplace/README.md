# GANJ VPS Marketplace — Phase 1

Standalone **marketplace subsystem inside the existing `PEDIHS/GANJVPS` repository**. It does not replace or mutate the current GANJ VPS agent, representative dashboard or existing tunnel/network code.

## Implemented

- Telegram Mini App HMAC authentication, short-lived signed session, CSRF for cookie-based writes.
- Telegram Bot API webhook with shared-secret validation, private-chat-only commands, basic shopping, balance, owned nodes, sensitive-operation voting and vote rejection reasons.
- Admin-controlled two/three-slot hosts and purchasable plans, inventory/availability.
- Atomic wallet ledger and idempotent wallet purchase; no charge without settled funds.
- Purchased service starts `provisioning`, **not** `active`, and a job stays `awaiting_connector`; no false delivery.
- Host operation requests require unanimous consent from current active/provisioning owners; rejection closes request, no response is not consent.
- Tickets, a starter Emerald/Gold panel, and admin endpoints for plans, hosts and audit-ready manual wallet adjustments.
- All actual provider power/restart/IP changes are **disabled**. PasarGuard/Rebecca/Marzban adapters are pending validated isolated staging.

## Run locally

```bash
cd marketplace
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set random SESSION_SECRET, new bot token, webhook secret, owner ID.
python -m uvicorn app.main:app --host 127.0.0.1 --port 8800
pytest -q
```

SQLite is intended only for local development. In production use PostgreSQL and keep all secrets outside Git. `create_all` is an initial bootstrap only; schema migration management (Alembic) is required before live data evolution.

### Connect Telegram

Register `https://vps.pedramhs.ir/telegram/webhook` as webhook after configuring a **fresh** BotFather token and random webhook secret. Telegram webhook **must** pass `X-Telegram-Bot-Api-Secret-Token`. Only HTTPS is supported for Mini App authentication. Open the bot's private chat, tap *پنل پیشرفته*; normal browser sessions without Telegram initData are intentionally denied.

### Finance and permissions

The direct wallet credit endpoint is **restricted to authorized admins**. Never count a card-to-card screenshot as settled payment without approved reconciliation. Real Telegram digital-service payments must follow Telegram's platform payment rules. Any online payment integration needs provider signature verification and replay protection.

`ADMIN_API_KEY` is optional for **back-office automation only**; do not put it in browser code or logs. Owner identity is derived from validated Telegram login, not user-provided request fields.

### Production blockers

1. Rotate the exposed old Telegram token (it is deliberately absent from this repository).
2. Obtain authorized SSH/server deployment mechanism for `206.1.97.167`; verify SSL email spelling.
3. Validate host provider APIs, IP inventory and rollback path; no power/IP operations until this is proven.
4. Build and test separately isolated PasarGuard, Rebecca and Marzban runtime adapters and resource caps on a staging VPS.
5. Add migrations, backup/restore, a robust Telegram outgoing message outbox and end-to-end payment settlement.

The existing `GANJVPS` agent is for GANJ network/location management, not directly a multitenant node installer. Do not reuse its agent enrollment credentials or grant arbitrary shell access to marketplace users.
