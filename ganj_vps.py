#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from panel_sync import adapter_from_profile, detect_sanaei_local

APP_NAME = "GANJ VPS"
APP_VERSION = "0.2.0"

ETC_DIR = Path("/etc/ganj-vps")
STATE_DIR = Path("/var/lib/ganj-vps")
RUN_DIR = Path("/run/ganj-vps")
CONFIG_FILE = ETC_DIR / "agent.json"
SECRET_FILE = ETC_DIR / "node.secret"
WG_PRIVATE_FILE = ETC_DIR / "wg.private"
WG_PUBLIC_FILE = ETC_DIR / "wg.public"
WG_CONF = Path("/etc/wireguard/ganj-vps.conf")
PANEL_SECRET_FILE = ETC_DIR / "panel.json"
STATE_FILE = STATE_DIR / "state.json"

DEFAULT_CENTRAL = "https://turkey.ufo-tuning.ir/ganj-agent"
HEARTBEAT_INTERVAL = 15
HTTP_TIMEOUT = 15

TOP_LOCATIONS = [
    "DE","NL","FR","GB","TR","FI","SE","CH","AT","BE",
    "PL","IT","ES","RO","BG","CZ","NO","DK","IE","LT",
    "LV","EE","US","CA","AE","RU","SG","JP","KR","AU",
]

def run(cmd: list[str], timeout: int = 20, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)

def atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass

def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {} if default is None else default

def save_json(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n", mode)


def panel_profile() -> dict[str, Any]:
    data = load_json(PANEL_SECRET_FILE, {})
    if not isinstance(data, dict) or not data.get("type"):
        raise RuntimeError("panel_not_configured")
    return data

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default

def _detect_pasarguard_local_url() -> str:
    for path in (Path("/opt/pasarguard/.env"), Path("/opt/PasarGuard/.env"), Path("/etc/pasarguard/.env"), Path("/etc/PasarGuard/.env")):
        if not path.is_file():
            continue
        try:
            vals: dict[str, str] = {}
            for line in path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                vals[k.strip()] = v.strip().strip('"').strip("'")
            host = vals.get("UVICORN_HOST") or "127.0.0.1"
            if host in {"0.0.0.0", "::", ""}:
                host = "127.0.0.1"
            port = vals.get("UVICORN_PORT") or "8000"
            scheme = "https" if vals.get("UVICORN_SSL_CERTFILE") else "http"
            return f"{scheme}://{host}:{port}"
        except Exception:
            continue
    return "http://127.0.0.1:8000"

def _yes_no(prompt: str, default: bool = True) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _choose_index(prompt: str, rows: list[dict[str, Any]], key: str = "index", default_index: int | None = None) -> dict[str, Any]:
    if not rows:
        raise RuntimeError("no_items_available")
    while True:
        suffix = f" [{default_index}]" if default_index else ""
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw and default_index:
            raw = str(default_index)
        try:
            n = int(raw)
        except ValueError:
            print("[-] Enter a valid list number.")
            continue
        for row in rows:
            if int(row.get(key) or 0) == n:
                return row
        print("[-] Selection not found.")


def _print_inbounds(kind: str, rows: list[dict[str, Any]]) -> None:
    print("\nAvailable inbounds:")
    print("  #   ID/Tag                 Protocol   Port    Listen   Name")
    print("  --  ---------------------  ---------  ------  -------  ------------------------------")
    for row in rows:
        ident = str(row.get("id") or row.get("tag") or "—")
        name = str(row.get("remark") or row.get("tag") or "")
        enabled = "" if row.get("enable", True) else " [disabled]"
        print(
            f"  {int(row.get('index') or 0):<2}  {ident[:21]:<21}  "
            f"{str(row.get('protocol') or 'unknown')[:9]:<9}  "
            f"{str(row.get('port') or '—'):<6}  {str(row.get('listen') or '*')[:7]:<7}  "
            f"{name[:30]}{enabled}"
        )


def _print_hosts(rows: list[dict[str, Any]], selected_tag: str = "") -> None:
    print("\nAvailable PasarGuard hosts:")
    print("  #   ID     Inbound Tag             Port    Remark")
    print("  --  -----  ----------------------  ------  ------------------------------")
    for row in rows:
        marker = "*" if selected_tag and row.get("inbound_tag") == selected_tag else " "
        print(
            f"{marker} {int(row.get('index') or 0):<2}  {int(row.get('id') or 0):<5}  "
            f"{str(row.get('inbound_tag') or '—')[:22]:<22}  "
            f"{str(row.get('port') if row.get('port') is not None else 'auto'):<6}  "
            f"{str(row.get('remark') or '')[:30]}"
        )


def _panel_connection_profile(kind: str, detected: bool) -> dict[str, Any]:
    if kind == "sanaei":
        if detected:
            auto = detect_sanaei_local()
            if auto and _yes_no("Use automatically detected local 3x-ui API", True):
                return dict(auto)
        return {
            "type": "sanaei",
            "url": _ask("3x-ui URL", "http://127.0.0.1:2053"),
            "username": _ask("Admin username"),
            "password": getpass.getpass("Admin password: "),
            "verify_tls": _yes_no("Verify panel TLS certificate", False),
        }

    if kind == "pasarguard":
        return {
            "type": "pasarguard",
            "url": _ask("PasarGuard URL", _detect_pasarguard_local_url()),
            "username": _ask("Admin username"),
            "password": getpass.getpass("Admin password: "),
            "core_id": int(_ask("Core ID", "1")),
            "verify_tls": _yes_no("Verify panel TLS certificate", False),
        }
    raise RuntimeError("unsupported_panel")


def configure_panel(force_manual: bool = False) -> int:
    found = detect_panels()
    print("\nGANJ VPS · Panel Setup")
    print("────────────────────────────────────────────────────────")
    if found:
        for i, item in enumerate(found, 1):
            ver = f" · {item.get('version')}" if item.get("version") else ""
            print(f"  [{i}] {item['name']}{ver}  ✓ detected")
    else:
        print("  No supported panel was detected automatically.")

    kind = ""
    detected = False
    if not force_manual and len(found) == 1:
        if _yes_no(f"Use detected {found[0]['name']}", True):
            kind = str(found[0]["type"])
            detected = True
    elif not force_manual and len(found) > 1:
        print("  [M] Manual panel connection")
        raw = input("Select panel: ").strip().lower()
        if raw.isdigit() and 1 <= int(raw) <= len(found):
            kind = str(found[int(raw) - 1]["type"])
            detected = True

    if not kind:
        print("\nManual panel selection:")
        print("  [1] Sanaei 3x-ui")
        print("  [2] PasarGuard")
        raw = input("Select panel [1/2]: ").strip()
        kind = "sanaei" if raw == "1" else "pasarguard" if raw == "2" else ""
        if not kind:
            raise RuntimeError("unsupported_panel")

    profile = _panel_connection_profile(kind, detected)
    adapter = adapter_from_profile(profile)
    discovery = adapter.discover()
    inbounds = discovery.get("inbounds") or []
    _print_inbounds(kind, inbounds)

    if kind == "sanaei":
        print("\nChoose the inbound whose protocol/settings must be cloned for GANJ locations.")
        selected = _choose_index("Inbound list number", inbounds)
        profile["template_inbound_id"] = int(selected.get("id") or 0)
        if not profile["template_inbound_id"]:
            raise RuntimeError("invalid_template_inbound")
    else:
        print("\nChoose the inbound tag whose protocol/settings must be cloned for GANJ locations.")
        selected = _choose_index("Inbound list number", inbounds)
        profile["template_inbound_tag"] = str(selected.get("tag") or "")
        if not profile["template_inbound_tag"]:
            raise RuntimeError("invalid_template_inbound")

        hosts = discovery.get("hosts") or []
        if hosts:
            _print_hosts(hosts, profile["template_inbound_tag"])
            matching = next((x for x in hosts if x.get("inbound_tag") == profile["template_inbound_tag"]), None)
            default_host = int(matching.get("index")) if matching else None
            raw = input(
                f"Host list number to clone (0 = no host){f' [{default_host}]' if default_host else ''}: "
            ).strip()
            if not raw and default_host:
                raw = str(default_host)
            if raw in {"", "0"}:
                profile["template_host_id"] = 0
            else:
                try:
                    idx = int(raw)
                except ValueError as exc:
                    raise RuntimeError("invalid_host_selection") from exc
                host = next((x for x in hosts if int(x.get("index") or 0) == idx), None)
                if not host:
                    raise RuntimeError("invalid_host_selection")
                profile["template_host_id"] = int(host.get("id") or 0)
        else:
            profile["template_host_id"] = 0
            print("[!] No PasarGuard hosts were found; only core inbounds will be created.")

        if profile["template_host_id"]:
            print("\nHost port policy:")
            print("  [1] Keep the template Host port (recommended for reverse proxy / shared :443)")
            print("  [2] Set each Host port to its generated inbound port")
            print("  [3] Leave Host port empty and let PasarGuard resolve it")
            hp = input("Select [1]: ").strip() or "1"
            profile["host_port_mode"] = {"1": "template", "2": "inbound", "3": "none"}.get(hp, "template")

    print("\nLocal inbound port allocation:")
    print("  [1] Automatic collision-free block (recommended)")
    print("  [2] Start near a custom port and skip collisions")
    mode = input("Select [1]: ").strip() or "1"
    if mode == "2":
        profile["base_port"] = int(_ask("Preferred first local port", "20000"))
        profile["port_mode"] = "custom"
    else:
        profile["base_port"] = 20000
        profile["port_mode"] = "auto"

    # Verify again using the final profile before persisting credentials.
    adapter = adapter_from_profile(profile)
    verified = adapter.status()
    save_json(PANEL_SECRET_FILE, profile, 0o600)

    print("\n[+] Panel connection verified.")
    print(f"    Type:       {verified.get('type')}")
    print(f"    Inbounds:   {verified.get('inbounds', 0)}")
    print(f"    GANJ:       {verified.get('managed_inbounds', 0)} managed inbound(s)")
    if kind == "pasarguard":
        print(f"    Hosts:      {verified.get('hosts', 0)}")
        print(f"    Host clone: {profile.get('template_host_id') or 'disabled'}")
    print(f"    Port mode:  {profile.get('port_mode')} · base {profile.get('base_port')}")

    if CONFIG_FILE.exists() and SECRET_FILE.exists():
        try:
            plan = adapter.plan_locations(central_locations())
            items = plan.get("items") or []
            if items:
                print("\nInstall preview:")
                for item in items[:8]:
                    print(
                        f"    {item.get('country_code')}  local :{item.get('local_port')} "
                        f"→ gateway :{item.get('gateway_port')}"
                    )
                if len(items) > 8:
                    print(f"    ... +{len(items)-8} more")
                print(f"    Total: {len(items)} locations")
        except Exception as exc:
            print(f"[!] Preview unavailable: {type(exc).__name__}")
    return 0

def panel_status() -> int:
    profile = panel_profile()
    result = adapter_from_profile(profile).status()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

def central_locations() -> list[dict[str, Any]]:
    cfg = AgentConfig.load()
    data = CentralClient(cfg).desired()
    license_info = data.get("license") or {}
    if license_info and not license_info.get("active", False):
        raise RuntimeError(str(license_info.get("reason") or "license_inactive"))
    locations = ((data.get("gateway") or {}).get("locations") or [])
    return [x for x in locations if x.get("enabled") and str(x.get("country_code") or "") in TOP_LOCATIONS]

def locations_list() -> int:
    rows = central_locations()
    for x in rows:
        print(f"{x.get('country_code','--'):>2}  :{x.get('port','—'):<5}  {x.get('name','')}")
    print(f"\n{len(rows)} locations")
    return 0

def locations_install(assume_yes: bool = False) -> int:
    if not gateway_tunnel_ok():
        raise RuntimeError("wireguard_gateway_unreachable")
    profile = panel_profile()
    rows = central_locations()
    if not rows:
        raise RuntimeError("no_enabled_locations")
    if not assume_yes:
        answer = input(f"Install/update {len(rows)} GANJ locations in the panel? [y/N] ").strip().lower()
        if answer != "y":
            return 0
    adapter = adapter_from_profile(profile)
    result = adapter.install_locations(rows)
    cfg = AgentConfig.load()
    CentralClient(cfg).report({
        "status": "online",
        "data": {"operation": "locations_install", "installed": len(result.get("installed") or [])},
    })
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

def locations_remove(assume_yes: bool = False) -> int:
    profile = panel_profile()
    if not assume_yes:
        answer = input("Remove only GANJ-managed locations from the panel? [y/N] ").strip().lower()
        if answer != "y":
            return 0
    result = adapter_from_profile(profile).remove_locations()
    try:
        cfg = AgentConfig.load()
        CentralClient(cfg).report({"status": "online", "data": {"operation": "locations_remove"}})
    except Exception:
        pass
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

def machine_fingerprint() -> str:
    pieces = [socket.gethostname(), platform.machine()]
    for p in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            pieces.append(p.read_text().strip())
            break
        except Exception:
            pass
    return hashlib.sha256("|".join(pieces).encode()).hexdigest()

def os_summary() -> str:
    try:
        data = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
        return f"{data.get('PRETTY_NAME','Linux')} / {platform.release()}"
    except Exception:
        return f"{platform.system()} / {platform.release()}"

def detect_panels() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if Path("/usr/local/x-ui/x-ui").exists() or Path("/etc/x-ui/x-ui.db").exists():
        version = None
        try:
            p = run(["/usr/local/x-ui/x-ui", "version"], timeout=6)
            rows = (p.stdout or p.stderr).strip().splitlines()
            version = rows[0][:120] if rows else None
        except Exception:
            pass
        found.append({"type": "sanaei", "name": "Sanaei 3x-ui", "version": version, "detected": True})
    pg_paths = [Path("/opt/pasarguard"), Path("/opt/PasarGuard"), Path("/etc/pasarguard"), Path("/etc/PasarGuard")]
    if any(p.exists() for p in pg_paths):
        found.append({"type": "pasarguard", "name": "PasarGuard", "version": None, "detected": True})
    return found

def detect_panel() -> dict[str, Any]:
    configured = load_json(PANEL_SECRET_FILE, {})
    if isinstance(configured, dict) and configured.get("type"):
        for item in detect_panels():
            if item.get("type") == configured.get("type"):
                return {**item, "configured": True}
    found = detect_panels()
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        return {"type": "multiple", "name": "Multiple panels", "version": None, "detected": True, "candidates": found}
    return {"type": "unknown", "name": "Unknown", "version": None, "detected": False}
def ensure_wg_keys() -> tuple[str, str]:
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    if WG_PRIVATE_FILE.exists() and WG_PUBLIC_FILE.exists():
        return WG_PRIVATE_FILE.read_text().strip(), WG_PUBLIC_FILE.read_text().strip()
    if not shutil.which("wg"):
        raise RuntimeError("wireguard_tools_missing")
    priv = run(["wg", "genkey"], timeout=5, check=True).stdout.strip()
    p = subprocess.run(["wg", "pubkey"], input=priv + "\n", text=True, capture_output=True, timeout=5, check=True)
    pub = p.stdout.strip()
    atomic_write(WG_PRIVATE_FILE, priv + "\n", 0o600)
    atomic_write(WG_PUBLIC_FILE, pub + "\n", 0o644)
    return priv, pub

def write_wireguard_config(wg: dict[str, Any]) -> None:
    priv, _ = ensure_wg_keys()
    required = ["address", "server_public_key", "endpoint"]
    for key in required:
        if not wg.get(key):
            raise RuntimeError(f"missing_wireguard_{key}")
    allowed = wg.get("allowed_ips") or "10.60.0.0/16"
    keepalive = int(wg.get("persistent_keepalive") or 25)
    mtu = int(wg.get("mtu") or 1380)
    conf = (
        "[Interface]\n"
        f"Address = {wg['address']}\n"
        f"PrivateKey = {priv}\n"
        f"MTU = {mtu}\n\n"
        "[Peer]\n"
        f"PublicKey = {wg['server_public_key']}\n"
        f"Endpoint = {wg['endpoint']}\n"
        f"AllowedIPs = {allowed}\n"
        f"PersistentKeepalive = {keepalive}\n"
    )
    atomic_write(WG_CONF, conf, 0o600)
    run(["systemctl", "enable", "wg-quick@ganj-vps"], timeout=15)
    p = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
    if p.returncode != 0:
        raise RuntimeError("wireguard_start_failed")

@dataclass
class AgentConfig:
    central: str
    node_id: str

    @classmethod
    def load(cls) -> "AgentConfig":
        data = load_json(CONFIG_FILE, {})
        if not data.get("central") or not data.get("node_id"):
            raise RuntimeError("node_not_enrolled")
        return cls(str(data["central"]).rstrip("/"), str(data["node_id"]))

def node_secret() -> str:
    value = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else ""
    if not value:
        raise RuntimeError("node_secret_missing")
    return value

class CentralClient:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"GANJ-VPS-Agent/{APP_VERSION}",
            "Authorization": f"Bearer {node_secret()}",
            "X-Ganj-Node-ID": cfg.node_id,
            "Accept": "application/json",
        })

    def url(self, path: str) -> str:
        return f"{self.cfg.central}/{path.lstrip('/')}"

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        r = self.session.post(self.url("/v1/heartbeat"), json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def desired(self) -> dict[str, Any]:
        r = self.session.get(self.url("/v1/desired"), timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    def report(self, payload: dict[str, Any]) -> None:
        r = self.session.post(self.url("/v1/report"), json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()

    def next_command(self) -> dict[str, Any] | None:
        r = self.session.get(self.url("/v1/commands/next"), timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json().get("command")

    def command_result(self, command_id: int, ok: bool, data: dict[str, Any] | None = None, error: str | None = None) -> None:
        payload = {"ok": bool(ok), "data": data or {}, "error": error}
        r = self.session.post(self.url(f"/v1/commands/{int(command_id)}/result"), json=payload, timeout=HTTP_TIMEOUT)
        r.raise_for_status()

def wg_status() -> dict[str, Any]:
    if not shutil.which("wg"):
        return {"installed": False, "up": False}
    p = run(["wg", "show", "ganj-vps"], timeout=5)
    if p.returncode != 0:
        return {"installed": True, "up": False}
    endpoint = ""
    handshake = ""
    transfer = ""
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.startswith("endpoint:"):
            endpoint = s.split(":", 1)[1].strip()
        elif s.startswith("latest handshake:"):
            handshake = s.split(":", 1)[1].strip()
        elif s.startswith("transfer:"):
            transfer = s.split(":", 1)[1].strip()
    return {"installed": True, "up": True, "endpoint": endpoint, "handshake": handshake, "transfer": transfer}

def gateway_tunnel_ok() -> bool:
    if not wg_status().get("up"):
        return False
    try:
        p = run(["ping", "-c", "1", "-W", "2", "10.60.0.1"], timeout=4)
        if p.returncode == 0:
            return True
    except Exception:
        pass
    try:
        p = run(["wg", "show", "ganj-vps", "latest-handshakes"], timeout=5)
        now = int(time.time())
        for line in p.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ts = int(parts[-1])
                if ts > 0 and now - ts <= 180:
                    return True
    except Exception:
        pass
    return False

def panel_runtime_status(panel: dict[str, Any]) -> dict[str, Any]:
    if panel["type"] == "sanaei":
        p = run(["systemctl", "is-active", "x-ui"], timeout=5)
        return {"service": "x-ui", "active": p.returncode == 0 and p.stdout.strip() == "active"}
    if panel["type"] == "pasarguard":
        names = ["pasarguard", "pasarguard.service"]
        for name in names:
            p = run(["systemctl", "is-active", name], timeout=5)
            if p.returncode == 0:
                return {"service": name, "active": p.stdout.strip() == "active"}
        return {"service": "pasarguard", "active": False}
    return {"service": None, "active": False}

def heartbeat_payload() -> dict[str, Any]:
    panel = detect_panel()
    return {
        "agent_version": APP_VERSION,
        "hostname": socket.gethostname(),
        "fingerprint": machine_fingerprint(),
        "os": os_summary(),
        "panel": panel,
        "panel_runtime": panel_runtime_status(panel),
        "wireguard": {**wg_status(), "gateway_reachable": gateway_tunnel_ok()},
        "capabilities": {
            "wireguard": bool(shutil.which("wg")),
            "panel_sanaei": panel["type"] == "sanaei",
            "panel_pasarguard": panel["type"] == "pasarguard",
            "locations": TOP_LOCATIONS,
        },
    }

def enroll(central: str, token: str) -> None:
    central = central.rstrip("/")
    panel = detect_panel()
    _, wg_pub = ensure_wg_keys()
    payload = {
        "token": token,
        "node_name": socket.gethostname(),
        "hostname": socket.gethostname(),
        "fingerprint": machine_fingerprint(),
        "agent_version": APP_VERSION,
        "os": os_summary(),
        "panel": panel,
        "wg_public_key": wg_pub,
        "capabilities": {
            "wireguard": True,
            "locations": TOP_LOCATIONS,
            "panel_type": panel["type"],
        },
    }
    r = requests.post(f"{central}/v1/enroll", json=payload, timeout=20)
    if r.status_code != 200:
        try:
            message = r.json().get("detail") or r.json().get("error")
        except Exception:
            message = r.text[:160]
        raise RuntimeError(f"enrollment_failed: {message or r.status_code}")
    data = r.json()
    if not data.get("node_id") or not data.get("node_secret") or not data.get("wireguard"):
        raise RuntimeError("invalid_enrollment_response")
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ETC_DIR, 0o700)
    atomic_write(SECRET_FILE, str(data["node_secret"]).strip() + "\n", 0o600)
    save_json(CONFIG_FILE, {"central": central, "node_id": data["node_id"], "enrolled_at": int(time.time())}, 0o600)
    write_wireguard_config(data["wireguard"])
    save_json(STATE_FILE, {"last_enroll": int(time.time()), "desired_revision": None})
    print(f"[+] Enrolled node: {data['node_id']}")
    print("[+] WireGuard peer configured.")

def sync_once() -> dict[str, Any]:
    cfg = AgentConfig.load()
    client = CentralClient(cfg)
    hb = client.heartbeat(heartbeat_payload())
    desired = client.desired()
    state = load_json(STATE_FILE, {})
    state.update({
        "last_heartbeat": int(time.time()),
        "desired_revision": desired.get("revision"),
        "desired": desired,
    })
    save_json(STATE_FILE, state)
    return {"heartbeat": hb, "desired": desired}

def execute_central_command(action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    payload = payload if isinstance(payload, dict) else {}
    if action == "sync":
        cfg = AgentConfig.load()
        desired = CentralClient(cfg).desired()
        return {"revision": desired.get("revision"), "location": desired.get("location")}
    if action == "panel_status":
        return adapter_from_profile(panel_profile()).status()
    if action == "locations_install":
        if not gateway_tunnel_ok():
            raise RuntimeError("wireguard_gateway_unreachable")
        rows = central_locations()
        result = adapter_from_profile(panel_profile()).install_locations(rows)
        return {"installed": len(result.get("installed") or []), "locations": [x.get("country_code") for x in result.get("installed") or []]}
    if action == "locations_remove":
        result = adapter_from_profile(panel_profile()).remove_locations()
        return {k: v for k, v in result.items() if k != "backup"}
    if action == "diagnostics":
        panel = detect_panel()
        return {
            "panel": panel,
            "panel_runtime": panel_runtime_status(panel),
            "wireguard": wg_status(),
            "agent_version": APP_VERSION,
            "os": os_summary(),
        }
    if action == "wg_restart":
        p = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
        if p.returncode != 0:
            raise RuntimeError("wireguard_restart_failed")
        return {"wireguard": wg_status()}
    raise RuntimeError("unsupported_central_command")

def process_one_command(client: CentralClient) -> bool:
    command = client.next_command()
    if not command:
        return False
    cid = int(command.get("id"))
    action = str(command.get("action") or "")
    try:
        result = execute_central_command(action, command.get("payload") or {})
        client.command_result(cid, True, result)
    except Exception as exc:
        client.command_result(cid, False, {}, type(exc).__name__[:64])
    return True

def agent_loop() -> None:
    cfg = AgentConfig.load()
    client = CentralClient(cfg)
    failures = 0
    while True:
        try:
            hb = client.heartbeat(heartbeat_payload())
            desired = client.desired()
            state = load_json(STATE_FILE, {})
            state.update({
                "last_heartbeat": int(time.time()),
                "desired_revision": desired.get("revision"),
                "desired": desired,
                "last_error": None,
                "failures": 0,
            })
            save_json(STATE_FILE, state)
            process_one_command(client)
            failures = 0
        except Exception as exc:
            failures += 1
            state = load_json(STATE_FILE, {})
            state.update({"last_error": type(exc).__name__, "last_error_at": int(time.time()), "failures": failures})
            save_json(STATE_FILE, state)
        time.sleep(HEARTBEAT_INTERVAL if failures < 3 else min(60, HEARTBEAT_INTERVAL * failures))

def diagnostics() -> int:
    panel = detect_panel()
    cfg = load_json(CONFIG_FILE, {})
    checks = {
        "root": os.geteuid() == 0,
        "python": sys.version.split()[0],
        "panel": panel,
        "wireguard": wg_status(),
        "central_configured": bool(cfg.get("central") and cfg.get("node_id")),
        "agent_service": run(["systemctl", "is-active", "ganj-vps-agent"], timeout=5).stdout.strip(),
    }
    if cfg.get("central") and SECRET_FILE.exists():
        try:
            result = sync_once()
            checks["central"] = "ok"
            checks["desired_revision"] = result["desired"].get("revision")
        except Exception as exc:
            checks["central"] = f"error:{type(exc).__name__}"
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0

def status() -> int:
    panel = detect_panel()
    state = load_json(STATE_FILE, {})
    cfg = load_json(CONFIG_FILE, {})
    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Node:       {cfg.get('node_id','not enrolled')}")
    print(f"Panel:      {panel['name']}")
    print(f"WireGuard:  {'UP' if wg_status().get('up') else 'DOWN'}")
    print(f"Last sync:  {state.get('last_heartbeat','—')}")
    desired = state.get("desired") or {}
    print(f"Revision:   {desired.get('revision','—')}")
    print(f"Location:   {desired.get('location','automatic')}")
    license_info = desired.get("license") or {}
    if license_info:
        print(f"License:    {'ACTIVE' if license_info.get('active') else str(license_info.get('reason') or 'INACTIVE').upper()}")
        print(f"Expires:    {license_info.get('expires_at') or 'unlimited'}")
        limit = license_info.get("traffic_limit_bytes")
        used = int(license_info.get("traffic_used_bytes") or 0)
        if limit is not None:
            print(f"Traffic:    {used / (1024**3):.2f} / {int(limit) / (1024**3):.2f} GB")
        else:
            print(f"Traffic:    {used / (1024**3):.2f} GB / unlimited")
    return 0

def update_self() -> int:
    installer = "https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh"
    print("[~] Updating GANJ VPS from the official repository...")
    env = os.environ.copy()
    env["GANJ_SKIP_ENROLL"] = "1"
    p = subprocess.run(["bash", "-c", f"curl -fsSL {installer} | bash"], text=True, env=env)
    return p.returncode

def uninstall() -> int:
    answer = input("Remove GANJ VPS agent and WireGuard interface? [y/N] ").strip().lower()
    if answer != "y":
        return 0
    run(["systemctl", "disable", "--now", "ganj-vps-agent"], timeout=15)
    run(["systemctl", "disable", "--now", "wg-quick@ganj-vps"], timeout=15)
    for p in [Path("/etc/systemd/system/ganj-vps-agent.service"), Path("/usr/local/bin/ganj-vps"), WG_CONF]:
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    run(["systemctl", "daemon-reload"], timeout=10)
    print("[+] GANJ VPS runtime removed. Enrollment files remain in /etc/ganj-vps for safe recovery.")
    return 0

def menu() -> int:
    while True:
        os.system("clear")
        panel = detect_panel()
        print("╭────────────────────────────────────────╮")
        print("│              GANJ VPS                  │")
        print("│        Secure Node Controller          │")
        print("╰────────────────────────────────────────╯")
        print(f"Panel: {panel['name']}")
        print()
        print("[1] Status")
        print("[2] Configure / verify panel")
        print("[3] Panel status")
        print("[4] Install / sync 30 locations")
        print("[5] Remove GANJ locations")
        print("[6] Location catalog")
        print("[7] Sync with central")
        print("[8] WireGuard status")
        print("[9] Diagnostics")
        print("[10] Update")
        print("[11] Uninstall")
        print("[0] Exit")
        choice = input("> ").strip()
        try:
            if choice == "1":
                status()
            elif choice == "2":
                configure_panel()
            elif choice == "3":
                panel_status()
            elif choice == "4":
                locations_install()
            elif choice == "5":
                locations_remove()
            elif choice == "6":
                locations_list()
            elif choice == "7":
                print(json.dumps(sync_once(), ensure_ascii=False, indent=2))
            elif choice == "8":
                print(json.dumps(wg_status(), ensure_ascii=False, indent=2))
            elif choice == "9":
                diagnostics()
            elif choice == "10":
                return update_self()
            elif choice == "11":
                return uninstall()
            elif choice == "0":
                return 0
        except Exception as exc:
            print(f"[-] {type(exc).__name__}: {exc}")
        input("\nPress Enter...")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ganj-vps")
    sub = p.add_subparsers(dest="cmd")
    e = sub.add_parser("enroll")
    e.add_argument("--central", default=DEFAULT_CENTRAL)
    e.add_argument("--token", required=True)
    sub.add_parser("agent")
    sub.add_parser("status")
    sub.add_parser("diagnostics")
    sub.add_parser("sync")
    sub.add_parser("update")
    sub.add_parser("uninstall")
    pc = sub.add_parser("panel-configure")
    sub.add_parser("panel-status")
    li = sub.add_parser("locations-install")
    li.add_argument("--yes", action="store_true")
    lr = sub.add_parser("locations-remove")
    lr.add_argument("--yes", action="store_true")
    sub.add_parser("locations-list")
    return p

def main() -> int:
    if os.geteuid() != 0:
        print("GANJ VPS must run as root.", file=sys.stderr)
        return 1
    ETC_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ETC_DIR, 0o700)

    args = build_parser().parse_args()
    try:
        if args.cmd == "enroll":
            enroll(args.central, args.token)
            return 0
        if args.cmd == "agent":
            agent_loop()
            return 0
        if args.cmd == "status":
            return status()
        if args.cmd == "diagnostics":
            return diagnostics()
        if args.cmd == "sync":
            print(json.dumps(sync_once(), ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "panel-configure":
            return configure_panel()
        if args.cmd == "panel-status":
            return panel_status()
        if args.cmd == "locations-install":
            return locations_install(bool(args.yes))
        if args.cmd == "locations-remove":
            return locations_remove(bool(args.yes))
        if args.cmd == "locations-list":
            return locations_list()
        if args.cmd == "update":
            return update_self()
        if args.cmd == "uninstall":
            return uninstall()
        return menu()
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
