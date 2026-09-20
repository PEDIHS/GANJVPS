# GANJ Central Control Plane

This directory contains the source-controlled control plane used by GANJ VPS.

## Admin terminology

The dashboard intentionally uses **Representatives / نمایندگان** as the primary customer entity.
A representative receives a one-time enrollment token. When the token is consumed, the representative's panel becomes a registered managed panel; the representative's license, quota and expiry continue independently from the one-time token.

The dashboard shows, per representative:

- connected/offline panel status
- enrollment-token status, issue time, expiry and use time
- license status and expiry
- traffic used and traffic limit
- connected panel count
- agent version and last heartbeat

Raw enrollment tokens are returned only once. The database stores SHA-256 hashes.

## Server and IP binding

Each successful enrollment is permanently bound to the representative panel's
public source IP, server fingerprint, and WireGuard public key. The same
enrollment token cannot be reused on a second server.

If the public IP or server identity changes, use **Rotate / Change server-IP**
from the representatives panel. Rotation:

- revokes the currently connected panel and removes its WireGuard peer
- marks all previous pending/used tokens as revoked
- issues one new one-time token for the same representative
- preserves representative traffic usage, traffic limit, and license expiry

An unexpected IP or fingerprint change is locked as `ip_mismatch` or
`identity_mismatch` and requires operator rotation. Copying Agent files or a
node secret to another server therefore does not transfer access.

## Required environment

Create `/etc/ganj-central/central.env`:

```bash
GANJ_ADMIN_TOKEN=<strong-random-admin-token>
GANJ_CENTRAL_DB=/var/lib/ganj-central/central.db
GANJ_WG_INTERFACE=ganj-gateway
GANJ_WG_ENDPOINT=your-gateway.example.com:51820
GANJ_WG_SERVER_PUBLIC_KEY=<wireguard-server-public-key>
GANJ_WG_ALLOWED_IPS=10.60.0.0/16
GANJ_WG_MTU=1380
```

Optional multi-gateway discovery can be published to agents with:

```bash
GANJ_GATEWAYS_JSON='[
  {"id":"tr-1","name":"Türkiye 1","endpoint":"tr1.example.com:51820","priority":10},
  {"id":"nl-1","name":"Netherlands 1","endpoint":"nl1.example.com:51820","priority":20}
]'
```

Location SOCKS endpoints can be published with `GANJ_LOCATIONS_JSON`.

## Run

```bash
uvicorn central.app:app --host 127.0.0.1 --port 8787 --proxy-headers
```

Put the service behind HTTPS reverse proxy. The admin UI is available at `/admin`.

## Security model

- operator access uses a separate admin credential and an HttpOnly signed session cookie
- node authentication uses per-node secrets
- enrollment tokens are one-time and hashed at rest
- enrollments are bound to one public IP + server fingerprint + WireGuard key
- IP/identity mismatch locks require explicit operator rotation
- raw upstream credentials are never returned by this service
- node commands remain allow-listed by the agent
- quota/expiry state is evaluated separately from enrollment-token state
