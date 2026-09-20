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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from panel_sync import (
    LOCATION_CATALOG,
    PREFERRED_LOCAL_PORTS,
    adapter_from_profile,
    detect_sanaei_local,
)

APP_NAME = "GANJ VPS"
APP_VERSION = "0.4.0"

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
GATEWAYS_FILE = ETC_DIR / "gateways.json"

DEFAULT_CENTRAL = "https://turkey.ufo-tuning.ir/ganj-agent"
HEARTBEAT_INTERVAL = 15
HTTP_TIMEOUT = 15
WIREGUARD_REPAIR_INTERVAL = 60
GATEWAY_EVALUATION_INTERVAL = 60
GATEWAY_SWITCH_COOLDOWN = 300
GATEWAY_SWITCH_HYSTERESIS_MS = 15.0
LOCATION_PROBE_INTERVAL = 10
LOCATION_PROBE_TIMEOUT = 1.2
AUTO_UPDATE_CHECK_INTERVAL = 3600
REMOTE_AGENT_URL = "https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/ganj_vps.py"

TOP_LOCATIONS = list(LOCATION_CATALOG.keys())

_WG_RATE_STATE: dict[str, float | int] = {}
_LOCATION_PROBE_CACHE: dict[str, Any] = {"at": 0.0, "signature": "", "rows": []}

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
        raw = input(f"{prompt}{suffix} (M = enter ID/tag manually): ").strip()
        if not raw and default_index:
            raw = str(default_index)
        if raw.lower() == "m":
            manual = input("Inbound ID or tag: ").strip()
            for row in rows:
                if str(row.get("id") or "") == manual or str(row.get("tag") or "") == manual:
                    return row
            print("[-] That ID/tag is not present in the panel inventory.")
            continue
        try:
            n = int(raw)
        except ValueError:
            print("[-] Enter a valid list number or M.")
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
            "core_id": 1,
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

    if kind == "pasarguard":
        try:
            adapter.login()
            cores = adapter.list_cores()
        except Exception:
            cores = []
        if cores:
            print("\nAvailable PasarGuard cores:")
            print("  #   ID    Type       Name")
            print("  --  ----  ---------  ------------------------------")
            for row in cores:
                print(
                    f"  {int(row.get('index') or 0):<2}  {int(row.get('id') or 0):<4}  "
                    f"{str(row.get('type') or '')[:9]:<9}  {str(row.get('name') or '')[:30]}"
                )
            chosen_core = _choose_index("Core list number", cores)
            profile["core_id"] = int(chosen_core.get("id") or 1)
        else:
            profile["core_id"] = int(_ask("Core ID", "1"))
        adapter = adapter_from_profile(profile)

    discovery = adapter.discover()
    inbounds = discovery.get("inbounds") or []
    _print_inbounds(kind, inbounds)

    if kind == "sanaei":
        print("\nChoose the dedicated template inbound. GANJ VPS will READ and CLONE it; the template itself will never be modified or deleted.")
        selected = _choose_index("Inbound list number", inbounds)
        profile["template_inbound_id"] = int(selected.get("id") or 0)
        if not profile["template_inbound_id"]:
            raise RuntimeError("invalid_template_inbound")
    else:
        print("\nChoose the dedicated template inbound tag. GANJ VPS will READ and CLONE it; the template itself will never be modified or deleted.")
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
                f"Host list number to clone (0 = no host, M = enter Host ID)"
                f"{f' [{default_host}]' if default_host else ''}: "
            ).strip()
            if not raw and default_host:
                raw = str(default_host)
            if raw in {"", "0"}:
                profile["template_host_id"] = 0
            else:
                if raw.lower() == "m":
                    manual_id = input("Host ID: ").strip()
                    host = next((x for x in hosts if str(x.get("id") or "") == manual_id), None)
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
    print("  Fixed GANJ location catalog will be used.")
    print("  Countries are assigned sequentially from :6000 through :6029.")
    print("  :6030 stays reserved for one future catalog location.")
    print("  Every requested port is conflict-checked before apply.")
    profile["base_port"] = 6000
    profile["port_mode"] = "fixed-location-range-6000-6030"

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
    print(f"    Port mode:  {profile.get('port_mode')}")

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


def panel_discovery() -> int:
    profile = panel_profile()
    result = adapter_from_profile(profile).discover()
    _print_inbounds(str(profile.get("type") or ""), result.get("inbounds") or [])
    if profile.get("type") == "pasarguard":
        _print_hosts(result.get("hosts") or [], str(profile.get("template_inbound_tag") or ""))
    return 0


def locations_plan() -> int:
    profile = panel_profile()
    adapter = adapter_from_profile(profile)
    plan = adapter.plan_locations(central_locations())
    items = plan.get("items") or []
    print("\nGANJ location plan")
    print("  CC  Local Port  Gateway Port  State        Inbound")
    print("  --  ----------  ------------  -----------  ------------------------")
    for item in items:
        gateway_text = str(item.get("gateway_port") or "—")
        state = "ready" if item.get("available") else "placeholder"
        print(
            f"  {str(item.get('country_code') or ''):<2}  "
            f"{str(item.get('local_port') or ''):<10}  "
            f"{gateway_text:<12}  "
            f"{state:<11}  "
            f"{str(item.get('inbound_tag') or item.get('template_inbound_id') or '')[:24]}"
        )
    print(f"\nTotal: {len(items)} · no changes applied")
    return 0

def locations_from_desired(data: dict[str, Any]) -> list[dict[str, Any]]:
    license_info = data.get("license") or {}
    if license_info and not license_info.get("active", False):
        raise RuntimeError(str(license_info.get("reason") or "license_inactive"))

    published_rows = ((data.get("gateway") or {}).get("locations") or [])
    published: dict[str, dict[str, Any]] = {}
    for row in published_rows:
        code = str(row.get("country_code") or "").upper()
        if code in LOCATION_CATALOG:
            published[code] = dict(row)

    rows: list[dict[str, Any]] = []
    for code, meta in LOCATION_CATALOG.items():
        source = published.get(code)
        raw = dict(source or {})
        port = int(raw.get("port") or 0)
        available = bool(source is not None and raw.get("enabled", True) and port > 0)
        raw.update({
            "country_code": code,
            "name": meta["country"],
            "city": meta["city"],
            "flag": meta["flag"],
            "port": port,
            "enabled": available,
            "available": available,
        })
        rows.append(raw)
    return rows


def locations_signature(rows: list[dict[str, Any]]) -> str:
    compact = [
        {
            "country_code": str(row.get("country_code") or ""),
            "port": int(row.get("port") or 0),
            "available": bool(row.get("available")),
        }
        for row in rows
    ]
    raw = json.dumps(compact, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def central_locations() -> list[dict[str, Any]]:
    cfg = AgentConfig.load()
    return locations_from_desired(CentralClient(cfg).desired())

def locations_list() -> int:
    rows = central_locations()
    for x in rows:
        port_text = str(x.get("port") or "—")
        status = "ready" if x.get("available") else "placeholder"
        city = str(x.get("city") or "")
        print(
            f"{x.get('country_code','--'):>2}  :{port_text:<5}  "
            f"{x.get('name','')} — {city}  [{status}]"
        )
    print(f"\n{len(rows)} locations")
    return 0

def locations_install(assume_yes: bool = False) -> int:
    if not gateway_tunnel_ok():
        raise RuntimeError("wireguard_gateway_unreachable")
    profile = panel_profile()
    rows = central_locations()
    if not rows:
        raise RuntimeError("no_enabled_locations")

    adapter = adapter_from_profile(profile)
    plan = adapter.plan_locations(rows)
    items = plan.get("items") or []
    if len(items) != len(rows):
        raise RuntimeError("location_plan_incomplete")

    print("\nGANJ VPS · Install Plan")
    print("  CC  Local Port  Gateway Port  State        Host")
    print("  --  ----------  ------------  -----------  --------")
    for item in items:
        host_text = "clone" if item.get("host_clone") else ("—" if profile.get("type") == "pasarguard" else "n/a")
        gateway_text = str(item.get("gateway_port") or "—")
        state = "ready" if item.get("available") else "placeholder"
        print(
            f"  {str(item.get('country_code') or ''):<2}  "
            f"{str(item.get('local_port') or ''):<10}  "
            f"{gateway_text:<12}  {state:<11}  {host_text}"
        )

    if not assume_yes:
        answer = input(f"\nApply {len(rows)} location(s) to the panel? [y/N] ").strip().lower()
        if answer != "y":
            return 0

    result = adapter.install_locations(rows)
    verified = adapter.status()
    expected = len(rows)
    if int(verified.get("managed_inbounds") or 0) != expected:
        raise RuntimeError("post_install_inbound_verification_failed")
    if profile.get("type") == "pasarguard" and int(profile.get("template_host_id") or 0):
        if int(verified.get("managed_hosts") or 0) != expected:
            raise RuntimeError("post_install_host_verification_failed")

    cfg = AgentConfig.load()
    CentralClient(cfg).report({
        "status": "online",
        "data": {
            "operation": "locations_install",
            "installed": len(result.get("installed") or []),
            "managed_inbounds": verified.get("managed_inbounds"),
            "managed_hosts": verified.get("managed_hosts"),
        },
    })
    print(f"\n[+] Installed and verified: {expected} location(s).")
    print(f"    Managed inbounds: {verified.get('managed_inbounds', 0)}")
    if profile.get("type") == "pasarguard":
        print(f"    Managed hosts:    {verified.get('managed_hosts', 0)}")
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


def _current_wireguard_endpoint() -> str:
    if not WG_CONF.exists():
        return ""
    try:
        peer = _parse_wireguard_peer_config(WG_CONF.read_text(encoding="utf-8"))
        return str(peer.get("endpoint") or "").strip()
    except Exception:
        return ""


def _default_gateway_port() -> str:
    split = _split_wireguard_endpoint(_current_wireguard_endpoint())
    return split[1] if split else "51820"


def _normalize_gateway_candidate(value: Any, index: int = 0) -> dict[str, Any] | None:
    if isinstance(value, str):
        raw: dict[str, Any] = {"endpoint": value}
    elif isinstance(value, dict):
        raw = dict(value)
    else:
        return None

    wg = raw.get("wireguard") if isinstance(raw.get("wireguard"), dict) else {}
    endpoint = str(raw.get("endpoint") or wg.get("endpoint") or raw.get("host") or "").strip()
    if endpoint and _split_wireguard_endpoint(endpoint) is None and ":" not in endpoint:
        endpoint = f"{endpoint}:{_default_gateway_port()}"
    if not endpoint:
        return None

    ident = str(raw.get("id") or raw.get("code") or raw.get("name") or f"gateway-{index + 1}")
    name = str(raw.get("name") or raw.get("label") or ident)
    try:
        priority = int(raw.get("priority") if raw.get("priority") is not None else 100)
    except (TypeError, ValueError):
        priority = 100
    return {
        "id": ident,
        "name": name,
        "endpoint": endpoint,
        "priority": priority,
        "wireguard": dict(wg),
        "source": str(raw.get("source") or "central"),
    }


def _local_gateway_candidates() -> list[dict[str, Any]]:
    data = load_json(GATEWAYS_FILE, {"gateways": []})
    rows = data.get("gateways") if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return []
    out = []
    for i, row in enumerate(rows):
        item = _normalize_gateway_candidate(row, i)
        if item:
            item["source"] = "local"
            out.append(item)
    return out


def gateway_candidates(desired: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if desired is None:
        state = load_json(STATE_FILE, {})
        desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
    desired = desired if isinstance(desired, dict) else {}
    gateway = desired.get("gateway") if isinstance(desired.get("gateway"), dict) else {}

    sources: list[Any] = []
    for key in ("gateways",):
        rows = desired.get(key)
        if isinstance(rows, list):
            sources.extend(rows)
    for key in ("candidates", "gateways", "endpoints"):
        rows = gateway.get(key)
        if isinstance(rows, list):
            sources.extend(rows)
    if gateway.get("endpoint"):
        sources.append({
            "id": gateway.get("id") or "primary",
            "name": gateway.get("name") or "Primary",
            "endpoint": gateway.get("endpoint"),
            "priority": gateway.get("priority", 10),
            "wireguard": gateway.get("wireguard") or {},
        })
    sources.extend(_local_gateway_candidates())

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, row in enumerate(sources):
        item = _normalize_gateway_candidate(row, i)
        if not item:
            continue
        key = item["endpoint"].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(item)

    current = _current_wireguard_endpoint()
    if current and current.lower() not in seen:
        out.append({
            "id": "current",
            "name": "Current gateway",
            "endpoint": current,
            "priority": 999,
            "wireguard": {},
            "source": "runtime",
        })
    return out


def _gateway_host(candidate: dict[str, Any]) -> str:
    split = _split_wireguard_endpoint(str(candidate.get("endpoint") or ""))
    return split[0] if split else ""


def rank_gateways(desired: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ranked = []
    for candidate in gateway_candidates(desired):
        host = _gateway_host(candidate)
        latency = ping_latency_ms(host) if host else None
        ranked.append({**candidate, "latency_ms": latency})
    ranked.sort(key=lambda x: (
        x.get("latency_ms") is None,
        float(x.get("latency_ms") or 10**9),
        int(x.get("priority") or 100),
    ))
    return ranked


def gateway_ping_ok() -> bool:
    try:
        p = run(["ping", "-c", "1", "-W", "2", "10.60.0.1"], timeout=4)
        return p.returncode == 0
    except Exception:
        return False


def _rewrite_wireguard_endpoint(config_text: str, endpoint: str) -> str:
    lines = str(config_text or "").splitlines()
    section = ""
    replaced = False
    out = []
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        if section == "peer" and stripped.lower().startswith("endpoint") and "=" in raw:
            prefix = raw[:raw.index("=") + 1]
            out.append(f"{prefix} {endpoint}")
            replaced = True
        else:
            out.append(raw)
    if not replaced:
        raise RuntimeError("wireguard_endpoint_not_found")
    return "\n".join(out) + "\n"


def switch_gateway(candidate: dict[str, Any], verify: bool = True) -> bool:
    item = _normalize_gateway_candidate(candidate, 0)
    if not item:
        raise RuntimeError("invalid_gateway_candidate")
    if not WG_CONF.exists():
        raise RuntimeError("wireguard_config_missing")

    old_text = WG_CONF.read_text(encoding="utf-8")
    old_endpoint = _current_wireguard_endpoint()
    endpoint = str(item["endpoint"])
    if endpoint == old_endpoint and (not verify or gateway_ping_ok()):
        return True

    try:
        wg = item.get("wireguard") or {}
        if all(wg.get(k) for k in ("address", "server_public_key", "endpoint")):
            write_wireguard_config(wg)
        else:
            peer = _parse_wireguard_peer_config(old_text)
            public_key = str(peer.get("public_key") or "")
            if not public_key:
                raise RuntimeError("wireguard_peer_key_missing")
            atomic_write(WG_CONF, _rewrite_wireguard_endpoint(old_text, endpoint), 0o600)
            live = run(
                ["wg", "set", "ganj-vps", "peer", public_key, "endpoint", endpoint],
                timeout=8,
            )
            if live.returncode != 0:
                restart = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
                if restart.returncode != 0:
                    raise RuntimeError("gateway_switch_restart_failed")

        if verify:
            time.sleep(1)
            if not gateway_ping_ok():
                restart = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
                if restart.returncode != 0:
                    raise RuntimeError("gateway_switch_verify_restart_failed")
                time.sleep(1)
                if not gateway_ping_ok():
                    raise RuntimeError("gateway_switch_verification_failed")

        state = load_json(STATE_FILE, {})
        state["active_gateway"] = {
            "id": item["id"],
            "name": item["name"],
            "endpoint": endpoint,
            "latency_ms": ping_latency_ms(_gateway_host(item)),
            "switched_at": int(time.time()),
        }
        save_json(STATE_FILE, state)
        return True
    except Exception:
        atomic_write(WG_CONF, old_text, 0o600)
        run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
        raise


def choose_best_gateway(desired: dict[str, Any] | None = None, force: bool = False) -> dict[str, Any] | None:
    ranked = rank_gateways(desired)
    if not ranked:
        return None

    current_endpoint = _current_wireguard_endpoint()
    state = load_json(STATE_FILE, {})
    active = state.get("active_gateway") if isinstance(state.get("active_gateway"), dict) else {}
    last_switch = int(active.get("switched_at") or 0)
    gateway = desired.get("gateway") if isinstance(desired, dict) and isinstance(desired.get("gateway"), dict) else {}
    mode = str(gateway.get("mode") or "automatic").lower()

    current = next((x for x in ranked if x["endpoint"] == current_endpoint), None)
    best = ranked[0]
    healthy = gateway_ping_ok()

    should_switch = force or not healthy
    if not should_switch and mode in {"best", "best_ping", "latency"}:
        best_ms = best.get("latency_ms")
        cur_ms = current.get("latency_ms") if current else None
        cooldown_ok = int(time.time()) - last_switch >= GATEWAY_SWITCH_COOLDOWN
        if cooldown_ok and best["endpoint"] != current_endpoint:
            if cur_ms is None or (best_ms is not None and float(cur_ms) - float(best_ms) >= GATEWAY_SWITCH_HYSTERESIS_MS):
                should_switch = True

    if not should_switch:
        return current or best

    errors = []
    for candidate in ranked:
        if not force and healthy and candidate["endpoint"] == current_endpoint:
            continue
        try:
            if switch_gateway(candidate, verify=True):
                return candidate
        except Exception as exc:
            errors.append(f"{candidate['id']}:{type(exc).__name__}")
    if errors:
        state["last_gateway_failover_error"] = ",".join(errors)[:400]
        state["last_gateway_failover_at"] = int(time.time())
        save_json(STATE_FILE, state)
    return None


def gateways_list() -> int:
    ranked = rank_gateways()
    current = _current_wireguard_endpoint()
    print("\nGANJ gateways")
    print("  #   Active  Gateway                  Endpoint                         Ping")
    print("  --  ------  -----------------------  -------------------------------  --------")
    for i, row in enumerate(ranked, 1):
        mark = "★" if row["endpoint"] == current else ""
        ping = "offline" if row.get("latency_ms") is None else f"{row['latency_ms']:.1f} ms"
        print(f"  {i:<2}  {mark:<6}  {row['name'][:23]:<23}  {row['endpoint'][:31]:<31}  {ping}")
    return 0


def gateway_add(endpoint: str, name: str = "") -> int:
    item = _normalize_gateway_candidate({
        "id": name or endpoint,
        "name": name or endpoint,
        "endpoint": endpoint,
        "source": "local",
    })
    if not item:
        raise RuntimeError("invalid_gateway_endpoint")
    data = load_json(GATEWAYS_FILE, {"gateways": []})
    rows = data.get("gateways") if isinstance(data, dict) else []
    rows = rows if isinstance(rows, list) else []
    rows = [x for x in rows if str(x.get("endpoint") if isinstance(x, dict) else x) != item["endpoint"]]
    rows.append({"id": item["id"], "name": item["name"], "endpoint": item["endpoint"]})
    save_json(GATEWAYS_FILE, {"gateways": rows}, 0o600)
    print(f"[+] Gateway saved: {item['name']} · {item['endpoint']}")
    return 0


def gateway_remove(identifier: str) -> int:
    data = load_json(GATEWAYS_FILE, {"gateways": []})
    rows = data.get("gateways") if isinstance(data, dict) else []
    rows = rows if isinstance(rows, list) else []
    kept = []
    removed = 0
    for row in rows:
        item = _normalize_gateway_candidate(row)
        if item and identifier in {item["id"], item["name"], item["endpoint"]}:
            removed += 1
        else:
            kept.append(row)
    save_json(GATEWAYS_FILE, {"gateways": kept}, 0o600)
    print(f"[+] Removed {removed} local gateway(s).")
    return 0


def gateway_switch(identifier: str) -> int:
    ranked = rank_gateways()
    if identifier.lower() in {"best", "auto", "automatic"}:
        chosen = choose_best_gateway(load_json(STATE_FILE, {}).get("desired") or {}, force=True)
        if not chosen:
            raise RuntimeError("no_working_gateway")
        print(f"[+] Active gateway: {chosen['name']} · {chosen['endpoint']}")
        return 0
    for row in ranked:
        if identifier in {row["id"], row["name"], row["endpoint"]}:
            switch_gateway(row, verify=True)
            print(f"[+] Active gateway: {row['name']} · {row['endpoint']}")
            return 0
    raise RuntimeError("gateway_not_found")


def _parse_wireguard_peer_config(text: str) -> dict[str, str]:
    section = ""
    peer: dict[str, str] = {}
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "peer" or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.lower() == "publickey":
            peer["public_key"] = value
        elif key.lower() == "endpoint":
            peer["endpoint"] = value
    return peer


def _split_wireguard_endpoint(endpoint: str) -> tuple[str, str] | None:
    raw = str(endpoint or "").strip()
    if not raw:
        return None
    if raw.startswith("["):
        end = raw.find("]")
        if end <= 1 or end + 2 > len(raw) or raw[end + 1] != ":":
            return None
        return raw[1:end], raw[end + 2:]
    if ":" not in raw:
        return None
    host, port = raw.rsplit(":", 1)
    return (host.strip(), port.strip()) if host.strip() and port.strip() else None


def _is_ipv4_literal(host: str) -> bool:
    try:
        socket.inet_aton(str(host))
        return str(host).count(".") == 3
    except OSError:
        return False


def refresh_wireguard_endpoint_dns(force: bool = False) -> bool:
    if not WG_CONF.exists() or not shutil.which("wg"):
        return False
    try:
        peer = _parse_wireguard_peer_config(WG_CONF.read_text(encoding="utf-8"))
    except Exception:
        return False
    public_key = peer.get("public_key") or ""
    endpoint = _split_wireguard_endpoint(peer.get("endpoint") or "")
    if not public_key or not endpoint:
        return False
    host, port = endpoint
    if _is_ipv4_literal(host):
        return False
    try:
        resolved = socket.gethostbyname(host)
    except OSError:
        return False

    live_ip = ""
    p = run(["wg", "show", "ganj-vps", "endpoints"], timeout=5)
    if p.returncode == 0:
        for row in p.stdout.splitlines():
            parts = row.split()
            if len(parts) < 2 or parts[0] != public_key:
                continue
            live = _split_wireguard_endpoint(parts[1])
            if live:
                live_ip = live[0]
            break
    if not force and live_ip == resolved:
        return False

    update = run(
        ["wg", "set", "ganj-vps", "peer", public_key, "endpoint", f"{host}:{port}"],
        timeout=8,
    )
    if update.returncode != 0:
        restart = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
        return restart.returncode == 0
    return True


def ensure_wireguard_healthy() -> bool:
    refresh_wireguard_endpoint_dns()
    if gateway_tunnel_ok():
        return True
    restart = run(["systemctl", "restart", "wg-quick@ganj-vps"], timeout=20)
    if restart.returncode != 0:
        return False
    time.sleep(1)
    return gateway_tunnel_ok()


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

def ping_latency_ms(host: str) -> float | None:
    try:
        p = run(["ping", "-c", "1", "-W", "2", host], timeout=4)
        if p.returncode != 0:
            return None
        import re
        m = re.search(r"time[=<]([0-9.]+)\s*ms", p.stdout)
        return round(float(m.group(1)), 1) if m else None
    except Exception:
        return None


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


def _wg_transfer_bytes() -> tuple[int, int] | None:
    p = run(["wg", "show", "ganj-vps", "transfer"], timeout=5)
    if p.returncode != 0:
        return None
    rx = tx = 0
    found = False
    for row in p.stdout.splitlines():
        parts = row.split()
        if len(parts) < 3:
            continue
        try:
            rx += int(parts[-2])
            tx += int(parts[-1])
            found = True
        except ValueError:
            continue
    return (rx, tx) if found else None


def wireguard_rate_mbps() -> dict[str, float]:
    sample = _wg_transfer_bytes()
    now = time.monotonic()
    if sample is None:
        return {"rx_mbps": 0.0, "tx_mbps": 0.0, "total_mbps": 0.0}
    rx, tx = sample
    prev_at = float(_WG_RATE_STATE.get("at") or 0.0)
    prev_rx = int(_WG_RATE_STATE.get("rx") or rx)
    prev_tx = int(_WG_RATE_STATE.get("tx") or tx)
    _WG_RATE_STATE.update({"at": now, "rx": rx, "tx": tx})
    elapsed = now - prev_at
    if prev_at <= 0 or elapsed <= 0:
        return {"rx_mbps": 0.0, "tx_mbps": 0.0, "total_mbps": 0.0}
    rx_rate = max(0.0, (rx - prev_rx) * 8 / elapsed / 1_000_000)
    tx_rate = max(0.0, (tx - prev_tx) * 8 / elapsed / 1_000_000)
    return {
        "rx_mbps": round(rx_rate, 2),
        "tx_mbps": round(tx_rate, 2),
        "total_mbps": round(rx_rate + tx_rate, 2),
    }


def _socket_token_port(token: str) -> int | None:
    raw = str(token or "").strip()
    if not raw:
        return None
    if raw.startswith("[") and "]:" in raw:
        raw = raw.rsplit(":", 1)[-1]
    elif ":" in raw:
        raw = raw.rsplit(":", 1)[-1]
    try:
        return int(raw)
    except ValueError:
        return None


def established_connections_by_port(ports: set[int]) -> dict[int, int]:
    counts = {int(p): 0 for p in ports}
    if not counts:
        return counts
    p = run(["ss", "-Htn", "state", "established"], timeout=5)
    if p.returncode != 0:
        return counts
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        # In ss output the local endpoint is normally the penultimate endpoint
        # token. Scan from left to right and count the first managed local port.
        for token in parts:
            port = _socket_token_port(token)
            if port in counts:
                counts[port] += 1
                break
    return counts


def socks5_latency_ms(
    proxy_host: str,
    proxy_port: int,
    target_host: str = "1.1.1.1",
    target_port: int = 443,
    timeout: float = LOCATION_PROBE_TIMEOUT,
) -> float | None:
    started = time.monotonic()
    try:
        with socket.create_connection((proxy_host, int(proxy_port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                return None
            target_ip = socket.inet_aton(target_host)
            req = b"\x05\x01\x00\x01" + target_ip + int(target_port).to_bytes(2, "big")
            s.sendall(req)
            head = s.recv(4)
            if len(head) < 4 or head[1] != 0x00:
                return None
        return round((time.monotonic() - started) * 1000, 1)
    except (OSError, ValueError):
        return None


def location_runtime_rows(desired: dict[str, Any]) -> list[dict[str, Any]]:
    rows = locations_from_desired(desired)
    signature = locations_signature(rows)
    now = time.monotonic()
    cached_at = float(_LOCATION_PROBE_CACHE.get("at") or 0.0)
    if (
        _LOCATION_PROBE_CACHE.get("signature") == signature
        and now - cached_at < LOCATION_PROBE_INTERVAL
    ):
        probes = {
            str(x.get("country_code")): x.get("proxy_latency_ms")
            for x in (_LOCATION_PROBE_CACHE.get("rows") or [])
        }
    else:
        probes: dict[str, float | None] = {}
        available = [x for x in rows if x.get("available") and int(x.get("port") or 0) > 0]
        with ThreadPoolExecutor(max_workers=min(10, max(1, len(available)))) as pool:
            futures = {
                pool.submit(socks5_latency_ms, "10.60.0.1", int(row["port"])): str(row["country_code"])
                for row in available
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    probes[code] = future.result()
                except Exception:
                    probes[code] = None
        _LOCATION_PROBE_CACHE.update({
            "at": now,
            "signature": signature,
            "rows": [
                {"country_code": code, "proxy_latency_ms": latency}
                for code, latency in probes.items()
            ],
        })

    ports = {int(PREFERRED_LOCAL_PORTS[x["country_code"]]) for x in rows}
    connections = established_connections_by_port(ports)
    current_host = _gateway_host({"endpoint": _current_wireguard_endpoint()})
    gateway_latency = ping_latency_ms(current_host) if current_host else None
    out = []
    for row in rows:
        code = str(row["country_code"])
        local_port = int(PREFERRED_LOCAL_PORTS[code])
        proxy_latency = probes.get(code) if row.get("available") else None
        total_latency = None
        if gateway_latency is not None and proxy_latency is not None:
            total_latency = round(float(gateway_latency) + float(proxy_latency), 1)
        out.append({
            "country_code": code,
            "label": f"{row.get('flag','')} {row.get('name','')} — {row.get('city','')}".strip(),
            "local_port": local_port,
            "gateway_port": int(row.get("port") or 0) if row.get("available") else None,
            "available": bool(row.get("available")),
            "connections": int(connections.get(local_port, 0)),
            "proxy_latency_ms": proxy_latency,
            "total_latency_ms": total_latency,
        })
    return out


def light_runtime_metrics() -> dict[str, Any]:
    ports = set(PREFERRED_LOCAL_PORTS.values())
    connections = established_connections_by_port(ports)
    return {
        **wireguard_rate_mbps(),
        "active_connections": sum(connections.values()),
    }


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
    state = load_json(STATE_FILE, {})
    runtime = light_runtime_metrics()
    desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
    return {
        "agent_version": APP_VERSION,
        "hostname": socket.gethostname(),
        "fingerprint": machine_fingerprint(),
        "os": os_summary(),
        "panel": panel,
        "panel_runtime": panel_runtime_status(panel),
        "wireguard": {**wg_status(), "gateway_reachable": gateway_tunnel_ok()},
        "gateway": {
            "active": state.get("active_gateway") or {},
            "candidate_count": len(gateway_candidates(desired)),
        },
        "runtime": runtime,
        "capabilities": {
            "wireguard": bool(shutil.which("wg")),
            "wireguard_self_heal": True,
            "multi_gateway": True,
            "best_ping_gateway": True,
            "automatic_failover": True,
            "live_throughput": True,
            "live_connections": True,
            "location_latency": True,
            "desired_reconcile": True,
            "auto_update": True,
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

    # A node may be installed first and enrolled later from the CLI. Start the
    # agent here as well, not only from install.sh.
    unit = Path("/etc/systemd/system/ganj-vps-agent.service")
    if unit.exists():
        run(["systemctl", "daemon-reload"], timeout=10)
        svc = run(["systemctl", "enable", "--now", "ganj-vps-agent"], timeout=20)
        if svc.returncode == 0:
            print("[+] GANJ VPS agent enabled and started.")
        else:
            print("[!] Enrollment succeeded, but the agent service could not be started automatically.")


def reconcile_desired(desired: dict[str, Any], force: bool = False) -> dict[str, Any]:
    desired = desired if isinstance(desired, dict) else {}
    license_info = desired.get("license") if isinstance(desired.get("license"), dict) else {}
    if license_info and not license_info.get("active", False):
        return {"ok": True, "skipped": "license_inactive"}

    gateway = choose_best_gateway(desired, force=False)
    result: dict[str, Any] = {
        "ok": True,
        "gateway": gateway.get("id") if isinstance(gateway, dict) else None,
        "locations_changed": False,
    }

    if not PANEL_SECRET_FILE.exists():
        result["locations_skipped"] = "panel_not_configured"
        return result
    if not gateway_ping_ok():
        result["locations_skipped"] = "gateway_unreachable"
        return result

    rows = locations_from_desired(desired)
    signature = locations_signature(rows)
    state = load_json(STATE_FILE, {})
    if not force and state.get("locations_signature") == signature:
        return result

    adapter = adapter_from_profile(panel_profile())
    installed = adapter.install_locations(rows)
    verified = adapter.status()
    expected = len(rows)
    if int(verified.get("managed_inbounds") or 0) != expected:
        raise RuntimeError("desired_reconcile_inbound_verification_failed")
    profile = panel_profile()
    if profile.get("type") == "pasarguard" and int(profile.get("template_host_id") or 0):
        if int(verified.get("managed_hosts") or 0) != expected:
            raise RuntimeError("desired_reconcile_host_verification_failed")

    state = load_json(STATE_FILE, {})
    state["locations_signature"] = signature
    state["last_reconcile"] = int(time.time())
    state["last_reconcile_revision"] = desired.get("revision")
    save_json(STATE_FILE, state)
    result["locations_changed"] = True
    result["installed"] = len(installed.get("installed") or [])
    return result


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for piece in str(value or "").strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts or [0])


def remote_agent_version() -> str | None:
    try:
        r = requests.get(REMOTE_AGENT_URL, timeout=10, headers={"Cache-Control": "no-cache"})
        r.raise_for_status()
        for line in r.text.splitlines()[:80]:
            stripped = line.strip()
            if stripped.startswith("APP_VERSION") and "=" in stripped:
                value = stripped.split("=", 1)[1].strip().strip("\"").strip("'")
                return value or None
    except Exception:
        return None
    return None


def perform_auto_update() -> bool:
    installer = "https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh"
    env = os.environ.copy()
    env["GANJ_SKIP_ENROLL"] = "1"
    env["GANJ_DEFER_RESTART"] = "1"
    p = subprocess.run(
        ["bash", "-c", f"curl -fsSL {installer} | bash"],
        text=True,
        env=env,
        capture_output=True,
        timeout=240,
    )
    if p.returncode != 0:
        state = load_json(STATE_FILE, {})
        state["last_auto_update_error"] = (p.stderr or p.stdout or "update_failed")[-500:]
        state["last_auto_update_at"] = int(time.time())
        save_json(STATE_FILE, state)
        return False
    return True


def maybe_auto_update() -> bool:
    state = load_json(STATE_FILE, {})
    now = int(time.time())
    last = int(state.get("last_update_check") or 0)
    if now - last < AUTO_UPDATE_CHECK_INTERVAL:
        return False
    state["last_update_check"] = now
    save_json(STATE_FILE, state)

    remote = remote_agent_version()
    if not remote or _version_tuple(remote) <= _version_tuple(APP_VERSION):
        return False
    if not perform_auto_update():
        return False

    python_bin = "/opt/ganj-vps/venv/bin/python"
    script = "/opt/ganj-vps/ganj_vps.py"
    if os.path.exists(python_bin) and os.path.exists(script):
        os.execv(python_bin, [python_bin, script, "agent"])
    return True


def sync_once() -> dict[str, Any]:
    cfg = AgentConfig.load()
    client = CentralClient(cfg)
    hb = client.heartbeat(heartbeat_payload())
    desired = client.desired()
    reconcile = reconcile_desired(desired)
    state = load_json(STATE_FILE, {})
    state.update({
        "last_heartbeat": int(time.time()),
        "desired_revision": desired.get("revision"),
        "desired": desired,
    })
    save_json(STATE_FILE, state)
    return {"heartbeat": hb, "desired": desired, "reconcile": reconcile}

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
    last_wg_repair = 0.0
    while True:
        try:
            now = time.monotonic()
            if now - last_wg_repair >= WIREGUARD_REPAIR_INTERVAL:
                ensure_wireguard_healthy()
                last_wg_repair = now
            hb = client.heartbeat(heartbeat_payload())
            desired = client.desired()
            reconcile = reconcile_desired(desired)
            state = load_json(STATE_FILE, {})
            state.update({
                "last_heartbeat": int(time.time()),
                "desired_revision": desired.get("revision"),
                "desired": desired,
                "last_reconcile_result": reconcile,
                "last_error": None,
                "failures": 0,
            })
            save_json(STATE_FILE, state)
            process_one_command(client)
            maybe_auto_update()
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

def _status_snapshot() -> dict[str, Any]:
    panel = detect_panel()
    state = load_json(STATE_FILE, {})
    cfg = load_json(CONFIG_FILE, {})
    wg = wg_status()
    snap: dict[str, Any] = {
        "version": APP_VERSION,
        "node_id": cfg.get("node_id"),
        "central": cfg.get("central"),
        "panel": panel,
        "panel_configured": PANEL_SECRET_FILE.exists(),
        "wireguard": wg,
        "gateway_reachable": gateway_tunnel_ok(),
        "gateway_latency_ms": ping_latency_ms("10.60.0.1") if wg.get("up") else None,
        "last_sync": state.get("last_heartbeat"),
        "last_error": state.get("last_error"),
        "desired": state.get("desired") or {},
    }
    if PANEL_SECRET_FILE.exists():
        try:
            snap["panel_status"] = adapter_from_profile(panel_profile()).status()
        except Exception as exc:
            snap["panel_status"] = {"ok": False, "error": type(exc).__name__}
    return snap


def _human_time(epoch: Any) -> str:
    try:
        age = max(0, int(time.time()) - int(epoch))
    except Exception:
        return "—"
    if age < 60:
        return f"{age}s ago"
    if age < 3600:
        return f"{age//60}m ago"
    return f"{age//3600}h ago"


def _print_status_snapshot(snap: dict[str, Any]) -> None:
    desired = snap.get("desired") or {}
    license_info = desired.get("license") or {}
    panel = snap.get("panel") or {}
    ps = snap.get("panel_status") or {}
    wg = snap.get("wireguard") or {}
    print("╭──────────────────── GANJ VPS STATUS ────────────────────╮")
    print(f"  Agent       v{snap.get('version')}  ·  Node {(snap.get('node_id') or 'not enrolled')[:12]}")
    print(f"  Panel       {panel.get('name','Unknown'):<20} {'configured' if snap.get('panel_configured') else 'not configured'}")
    if snap.get("panel_configured"):
        if ps.get("ok"):
            print(
                f"  Panel API   ONLINE  · inbounds {ps.get('inbounds',0)} "
                f"· GANJ {ps.get('managed_inbounds',0)}"
            )
            if ps.get("type") == "pasarguard":
                print(f"  Hosts       {ps.get('hosts',0)} total · {ps.get('managed_hosts',0)} GANJ")
        else:
            print(f"  Panel API   OFFLINE · {ps.get('error','unknown')}")
    print(
        f"  WireGuard   {'UP' if wg.get('up') else 'DOWN'}  · "
        f"Gateway {'ONLINE' if snap.get('gateway_reachable') else 'OFFLINE'}"
        + (f" · {snap.get('gateway_latency_ms')} ms" if snap.get("gateway_latency_ms") is not None else "")
    )
    print(f"  Central     {'configured' if snap.get('central') else 'not enrolled'} · last sync {_human_time(snap.get('last_sync'))}")
    if snap.get("last_error"):
        print(f"  Last error  {snap.get('last_error')}")
    if license_info:
        state = "ACTIVE" if license_info.get("active") else str(license_info.get("reason") or "INACTIVE").upper()
        print(f"  License     {state} · expires {license_info.get('expires_at') or 'unlimited'}")
        used = int(license_info.get("traffic_used_bytes") or 0) / (1024**3)
        limit = license_info.get("traffic_limit_bytes")
        print(f"  Traffic     {used:.2f} GB / {('∞' if limit is None else f'{int(limit)/(1024**3):.2f} GB')}")
    locations = ((desired.get("gateway") or {}).get("locations") or [])
    if locations:
        print(f"  Locations   {len(locations)} published · desired {desired.get('location') or 'automatic'}")
    print("╰─────────────────────────────────────────────────────────╯")


def status(watch: bool = False) -> int:
    if not watch:
        _print_status_snapshot(_status_snapshot())
        return 0
    try:
        while True:
            os.system("clear")
            _print_status_snapshot(_status_snapshot())
            print("\nCtrl+C to return")
            time.sleep(2)
    except KeyboardInterrupt:
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
        print("[1] Live Status")
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
                status(watch=True)
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
    st = sub.add_parser("status")
    st.add_argument("--watch", action="store_true")
    sub.add_parser("diagnostics")
    sub.add_parser("sync")
    sub.add_parser("update")
    sub.add_parser("uninstall")
    pc = sub.add_parser("panel-configure")
    pc.add_argument("--manual", action="store_true")
    sub.add_parser("panel-detect")
    sub.add_parser("panel-status")
    sub.add_parser("panel-inbounds")
    li = sub.add_parser("locations-install")
    li.add_argument("--yes", action="store_true")
    lr = sub.add_parser("locations-remove")
    lr.add_argument("--yes", action="store_true")
    sub.add_parser("locations-list")
    sub.add_parser("locations-plan")
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
            return status(bool(args.watch))
        if args.cmd == "diagnostics":
            return diagnostics()
        if args.cmd == "sync":
            print(json.dumps(sync_once(), ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "panel-configure":
            return configure_panel(bool(args.manual))
        if args.cmd == "panel-detect":
            print(json.dumps({"items": detect_panels()}, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "panel-status":
            return panel_status()
        if args.cmd == "panel-inbounds":
            return panel_discovery()
        if args.cmd == "locations-install":
            return locations_install(bool(args.yes))
        if args.cmd == "locations-remove":
            return locations_remove(bool(args.yes))
        if args.cmd == "locations-list":
            return locations_list()
        if args.cmd == "locations-plan":
            return locations_plan()
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
