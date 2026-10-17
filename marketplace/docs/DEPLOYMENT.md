# Production deployment checklist — GANJ VPS marketplace

**State:** pre-release. Existing GANJ agent/services must not be replaced.

- [ ] Rotate BotFather token published in chat. Store new value in runtime secrets only.
- [ ] Confirm authorized access and backup on `206.1.97.167`; check whether ports 80/443 are already used by a reverse proxy.
- [ ] Confirm TLS contact email spelling and issue SSL for `vps.pedramhs.ir` with existing reverse proxy; don't replace active certificates or routes blindly.
- [ ] Provision isolated PostgreSQL database/user. Deny public DB access.
- [ ] Generate SESSION_SECRET (>=32 random chars), random TELEGRAM_WEBHOOK_SECRET and set owner ID.
- [ ] Run smoke tests with Telegram Mini App login, creation of host and plan, wallet credit reference, purchase and replays, votes, ticket flow.
- [ ] Configure backup+restore, uptime monitoring, structured logs without tokens, and rate limiting at reverse proxy.
- [ ] Keep `ENABLE_HOST_OPERATIONS=false` and `DRY_RUN=true` until provider-specific adapter, staging and rollback are certified.
- [ ] Implement idempotent provider-specific node provisioning in sandbox: PasarGuard, Rebecca, Marzban separately, then combined.
- [ ] Do not sell `active` product until actual node handshake verification succeeds and deliverable connection information can be produced.
- [ ] Validate Telegram Stars for digital services sold inside the bot. Bank transfer receipt flows must obey actual platform/legal restrictions.
- [ ] Add migration management and transactional outgoing message outbox before taking production traffic.

## Reverse proxy example (adapt to existing setup)

```
# Only after checking existing routing; do NOT overwrite production configs.
vps.pedramhs.ir {
  encode gzip zstd
  reverse_proxy 127.0.0.1:8800
}
```

The existing repository installer (`install.sh`) provisions the GANJ **node/agent**, not this marketplace service. Marketplace deployment has its own service lifecycle.
