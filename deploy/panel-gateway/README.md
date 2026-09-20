# Production PANEL Gateway integration

This directory tracks the production-side integration between `PEDIHS/GANJVPS`
and the existing PANEL Gateway control plane.

`ganj-panel-gateway-0.4.0.patch` is the exact diff deployed on the Türkiye
gateway on 2026-09-20. It keeps the legacy `/nodes` API for compatibility and
adds the operator-facing Representatives model.

The deployed patch adds:

- one-time enrollment token to managed-panel linkage
- strict binding to one public IP + server fingerprint + WireGuard public key
- persistent `ip_mismatch` / `identity_mismatch` lock requiring operator rotation
- data-plane WireGuard peer removal when the observed endpoint IP changes
- token rotation that burns the old token, revokes the old panel and preserves representative quota/expiry/used traffic
- pending-token revoke from the admin panel
- `/admin/ganj/representatives`
- `/admin/ganj/enrollment-tokens`
- token status, issue/use/expiry information
- representative panel online/offline state
- license expiry, traffic used and traffic quota
- pending representatives before Agent enrollment
- GANJVPS 0.4 heartbeat runtime/gateway fields
- best-ping gateway candidate publication
- new allow-listed 0.4 central commands
- Persian Representatives UI replacing the Node Manager label

Production smoke checks performed after deployment:

- API service active
- peer manager active
- Nginx active
- WireGuard active
- representatives API returns 200
- pending representative create/list/cleanup round trip passes
- same-IP authenticated heartbeat succeeds
- changed-IP heartbeat is rejected with HTTP 403 and persists `ip_mismatch`
- old token reuse after rotation is rejected
- replacement token enrolls on a new server/IP under the same representative ID
- used traffic, traffic limit and license expiry survive server/IP rotation
- representative list remains one row after multiple token/server generations
- `ip_mismatch` peer is removed from the live WireGuard interface
- pending token revoke is irreversible and prevents enrollment
- panel inline JavaScript passes `node --check`
- unauthenticated desired-state endpoint remains 401
- existing `/nodes` route remains available for backward compatibility

Do not store raw enrollment tokens in source control. They are shown once to the
operator and only their hash is retained by the production database.

## WireGuard SOCKS firewall

Production SOCKS listeners bind to `10.60.0.1` and are intentionally reachable
only through the WireGuard interface. Run:

```bash
sudo deploy/panel-gateway/sync-wg-firewall.sh
```

The script persists UFW rules for TCP/UDP `1080:1238` on `wg0` only. This
fixes the failure mode where only the original Germany port `1082` was
allowed and every other location timed out from representative nodes.

## Central runtime stability patch

`ganj-central-runtime-stability-20260920.patch` tracks the live production fixes that prevent Xray restart churn from latency/quality telemetry, keep a selected route through transient `suspect` health until the configured failure threshold, debounce real runtime configuration changes, and use `geoiplookup6` for IPv6 egress classification.
