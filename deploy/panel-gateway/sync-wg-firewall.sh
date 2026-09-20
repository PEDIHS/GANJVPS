#!/usr/bin/env bash
set -Eeuo pipefail

WG_IF="${GANJ_WG_INTERFACE:-wg0}"
WG_ADDR="${GANJ_WG_ADDRESS:-10.60.0.1}"
SOCKS_RANGE="${GANJ_SOCKS_PORT_RANGE:-1080:1238}"

command -v ufw >/dev/null 2>&1 || {
  echo "ufw is required" >&2
  exit 1
}

ensure_rule() {
  local proto="$1"
  local comment="$2"
  if ufw status | grep -Fq "${WG_ADDR} ${SOCKS_RANGE}/${proto} on ${WG_IF}"; then
    return 0
  fi
  ufw allow in on "$WG_IF" to "$WG_ADDR" port "$SOCKS_RANGE" proto "$proto" comment "$comment" >/dev/null
}

ensure_rule tcp "GANJ SOCKS over WireGuard"
ensure_rule udp "GANJ SOCKS UDP over WireGuard"

echo "GANJ WireGuard SOCKS firewall ready: ${WG_IF} ${WG_ADDR}:${SOCKS_RANGE} tcp/udp"
