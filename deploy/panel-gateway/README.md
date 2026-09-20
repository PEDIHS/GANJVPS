# Production PANEL Gateway integration

This directory tracks the production-side integration between `PEDIHS/GANJVPS`
and the existing PANEL Gateway control plane.

`ganj-panel-gateway-0.4.0.patch` is the exact diff deployed on the Türkiye
gateway on 2026-09-20. It keeps the legacy `/nodes` API for compatibility and
adds the operator-facing Representatives model.

The deployed patch adds:

- one-time enrollment token to managed-panel linkage
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
- panel inline JavaScript passes `node --check`
- unauthenticated desired-state endpoint remains 401
- existing `/nodes` route remains available for backward compatibility

Do not store raw enrollment tokens in source control. They are shown once to the
operator and only their hash is retained by the production database.
