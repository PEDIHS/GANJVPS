#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "Run as root."; exit 1; }
ROOT="/opt/ganj-vps"
ENV_DIR="/etc/ganj-central"
STATE_DIR="/var/lib/ganj-central"
UNIT="/etc/systemd/system/ganj-central.service"

[[ -f "$ROOT/central/app.py" ]] || { echo "Install GANJ VPS source in $ROOT first."; exit 1; }
mkdir -p "$ENV_DIR" "$STATE_DIR"
chmod 0700 "$ENV_DIR" "$STATE_DIR"

"$ROOT/venv/bin/pip" install --disable-pip-version-check -q -r "$ROOT/central/requirements.txt"
install -m 0644 "$ROOT/central/ganj-central.service" "$UNIT"

if [[ ! -f "$ENV_DIR/central.env" ]]; then
  cat > "$ENV_DIR/central.env.example" <<'EOF'
GANJ_ADMIN_TOKEN=replace-with-strong-random-token
GANJ_CENTRAL_DB=/var/lib/ganj-central/central.db
GANJ_WG_INTERFACE=ganj-gateway
GANJ_WG_ENDPOINT=gateway.example.com:51820
GANJ_WG_SERVER_PUBLIC_KEY=replace-me
GANJ_WG_ALLOWED_IPS=10.60.0.0/16
EOF
  chmod 0600 "$ENV_DIR/central.env.example"
  echo "Create $ENV_DIR/central.env from central.env.example, then rerun this installer."
  exit 2
fi

chmod 0600 "$ENV_DIR/central.env"
systemctl daemon-reload
systemctl enable --now ganj-central.service
systemctl --no-pager --full status ganj-central.service || true
