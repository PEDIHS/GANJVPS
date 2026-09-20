#!/usr/bin/env bash
set -Eeuo pipefail

APP="GANJ VPS"
VERSION="0.4.4"
REPO="PEDIHS/GANJVPS"
INSTALL_DIR="/opt/ganj-vps"
ETC_DIR="/etc/ganj-vps"
STATE_DIR="/var/lib/ganj-vps"
RUN_DIR="/run/ganj-vps"
SERVICE="ganj-vps-agent.service"
DEFAULT_CENTRAL="https://turkey.ufo-tuning.ir/ganj-agent"

if [[ -t 1 ]]; then
  c_reset=$'\033[0m'; c_bold=$'\033[1m'; c_dim=$'\033[2m'
  c_emerald=$'\033[38;2;16;185;129m'; c_emerald2=$'\033[38;2;52;211;153m'
  c_gold=$'\033[38;2;245;190;64m'; c_gold2=$'\033[38;2;255;215;96m'
  c_red=$'\033[38;2;248;113;113m'; c_white=$'\033[38;2;236;253;245m'
else
  c_reset=''; c_bold=''; c_dim=''; c_emerald=''; c_emerald2=''; c_gold=''; c_gold2=''; c_red=''; c_white=''
fi

say(){ printf "%b\n" "$*"; }
ok(){ say "${c_emerald2}  ◆${c_reset} $*"; }
step(){ say "${c_gold}  ◇${c_reset} $*"; }
warn(){ say "${c_gold2}  !${c_reset} $*"; }
die(){ say "${c_red}  ✕${c_reset} $*"; exit 1; }
rule(){ say "${c_dim}  ─────────────────────────────────────────────────────${c_reset}"; }
banner(){
  clear 2>/dev/null || true
  say
  say "${c_gold}${c_bold}        ╔══════════════════════════════════════╗${c_reset}"
  say "${c_gold2}${c_bold}        ║              GANJ VPS                ║${c_reset}"
  say "${c_emerald}${c_bold}        ║       SECURE NODE INSTALLER          ║${c_reset}"
  say "${c_emerald2}${c_bold}        ╚══════════════════════════════════════╝${c_reset}"
  say "       ${c_dim}v${VERSION}${c_reset}  ${c_gold}◆${c_reset}  ${c_dim}Emerald / Gold Edition${c_reset}"
  rule
}

cleanup(){ rm -rf "${TMP_DIR:-}" 2>/dev/null || true; }
trap cleanup EXIT

[[ "${EUID}" -eq 0 ]] || die "Run as root."

command -v apt-get >/dev/null 2>&1 || die "Ubuntu/Debian with apt is required."

banner
step "Preparing system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y ca-certificates curl python3 python3-venv wireguard wireguard-tools iproute2 iputils-ping >/dev/null
ok "System dependencies ready"

TMP_DIR="$(mktemp -d)"
ARCHIVE="$TMP_DIR/ganj-vps.tar.gz"
step "Fetching GANJ VPS ${VERSION}"
curl -fsSL --retry 3 --connect-timeout 10 "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" -o "$ARCHIVE"
mkdir -p "$TMP_DIR/src"
tar -xzf "$ARCHIVE" -C "$TMP_DIR/src" --strip-components=1
ok "Official source downloaded"

if [[ -d "$INSTALL_DIR" ]]; then
  stamp="$(date +%Y%m%d-%H%M%S)"
  cp -a "$INSTALL_DIR" "${INSTALL_DIR}.bak-${stamp}"
  # Keep only the three newest application backups to avoid silent disk growth.
  mapfile -t old_backups < <(find "$(dirname "$INSTALL_DIR")" -maxdepth 1 -mindepth 1 -type d -name "$(basename "$INSTALL_DIR").bak-*" -printf '%T@ %p\n' 2>/dev/null | sort -rn | awk 'NR>3{sub(/^[^ ]+ /,""); print}')
  for old_backup in "${old_backups[@]:-}"; do
    [[ -n "$old_backup" ]] && rm -rf -- "$old_backup"
  done
fi

mkdir -p "$INSTALL_DIR" "$ETC_DIR" "$STATE_DIR" "$RUN_DIR"
cp -a "$TMP_DIR/src/." "$INSTALL_DIR/"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --disable-pip-version-check -q -r "$INSTALL_DIR/requirements.txt"

install -m 0644 "$INSTALL_DIR/systemd/ganj-vps-agent.service" "/etc/systemd/system/$SERVICE"
cat > /usr/local/bin/ganj-vps <<'EOF'
#!/usr/bin/env bash
exec /opt/ganj-vps/venv/bin/python /opt/ganj-vps/ganj_vps.py "$@"
EOF
chmod 0755 /usr/local/bin/ganj-vps
chmod 0700 "$ETC_DIR" "$STATE_DIR"
systemctl daemon-reload

CENTRAL_URL="${GANJ_CENTRAL_URL:-$DEFAULT_CENTRAL}"
ENROLL_TOKEN="${GANJ_ENROLL_TOKEN:-}"
SKIP_ENROLL="${GANJ_SKIP_ENROLL:-0}"
DEFER_RESTART="${GANJ_DEFER_RESTART:-0}"

if [[ "$SKIP_ENROLL" == "1" ]]; then
  if [[ "$DEFER_RESTART" != "1" ]]; then
    systemctl try-restart "$SERVICE" >/dev/null 2>&1 || true
  fi
  ok "GANJ VPS files updated"
  exit 0
fi

if [[ -z "$ENROLL_TOKEN" && -r /dev/tty ]]; then
  say
  say "${c_gold}${c_bold}  Enrollment${c_reset}"
  rule
  printf "%b" "${c_emerald}  Enrollment token › ${c_reset}" >/dev/tty
  IFS= read -rs ENROLL_TOKEN </dev/tty || true
  printf "\n" >/dev/tty
fi

if [[ -n "$ENROLL_TOKEN" ]]; then
  step "Registering this server with GANJ Control"
  if /usr/local/bin/ganj-vps enroll --central "$CENTRAL_URL" --token "$ENROLL_TOKEN"; then
    systemctl enable --now "$SERVICE" >/dev/null
    ok "Server registered and secure agent started"

    if [[ -r /dev/tty ]]; then
      step "Connecting to detected panel"
      if /usr/local/bin/ganj-vps panel-configure --auto </dev/tty >/dev/tty 2>/dev/tty; then
        ok "Panel connection verified"
        step "Creating and synchronizing GANJ locations"
        if /usr/local/bin/ganj-vps locations-install --yes </dev/tty >/dev/tty 2>/dev/tty; then
          ok "Locations synchronized"
        else
          warn "Panel is configured, but location sync needs attention. Run: ganj-vps locations-install"
        fi
      else
        warn "Panel setup was not completed. Run: ganj-vps panel-configure"
      fi
    fi
  else
    die "Enrollment failed. Verify the one-time token and try again."
  fi
else
  warn "No enrollment token supplied; runtime installed without activation."
  say "  ${c_dim}Run the installer again with a fresh token from the Representatives panel.${c_reset}"
fi

say
rule
say "  ${c_emerald2}${c_bold}✓ GANJ VPS ${VERSION} is ready${c_reset}"
say "  ${c_dim}CLI${c_reset}       ${c_gold}ganj-vps${c_reset}"
say "  ${c_dim}Live${c_reset}      ganj-vps status --watch"
say "  ${c_dim}Health${c_reset}    ganj-vps diagnostics"
rule
say
