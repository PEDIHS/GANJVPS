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

APP_NAME = "GANJ VPS"
APP_VERSION = "0.1.0"

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

def detect_panel() -> dict[str, Any]:
    if Path("/usr/local/x-ui/x-ui").exists() or Path("/etc/x-ui/x-ui.db").exists():
        version = None
        try:
            p = run(["/usr/local/x-ui/x-ui", "version"], timeout=6)
            version = (p.stdout or p.stderr).strip().splitlines()[0][:120]
        except Exception:
            pass
        return {"type": "sanaei", "name": "Sanaei 3x-ui", "version": version, "detected": True}

    pg_paths = [Path("/opt/pasarguard"), Path("/opt/PasarGuard"), Path("/etc/pasarguard"), Path("/etc/PasarGuard")]
    if any(p.exists() for p in pg_paths):
        return {"type": "pasarguard", "name": "PasarGuard", "version": None, "detected": True}

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
        "wireguard": wg_status(),
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

def agent_loop() -> None:
    AgentConfig.load()
    failures = 0
    while True:
        try:
            sync_once()
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
    return 0

def update_self() -> int:
    installer = "https://raw.githubusercontent.com/PEDIHS/GANJVPS/main/install.sh"
    print("[~] Updating GANJ VPS from the official repository...")
    p = subprocess.run(["bash", "-c", f"curl -fsSL {installer} | GANJ_ENROLL_TOKEN='' bash"], text=True)
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
        print("[2] Detect panel")
        print("[3] Sync with central")
        print("[4] WireGuard status")
        print("[5] Diagnostics")
        print("[6] Update")
        print("[7] Uninstall")
        print("[0] Exit")
        choice = input("> ").strip()
        try:
            if choice == "1":
                status()
            elif choice == "2":
                print(json.dumps(detect_panel(), ensure_ascii=False, indent=2))
            elif choice == "3":
                print(json.dumps(sync_once(), ensure_ascii=False, indent=2))
            elif choice == "4":
                print(json.dumps(wg_status(), ensure_ascii=False, indent=2))
            elif choice == "5":
                diagnostics()
            elif choice == "6":
                return update_self()
            elif choice == "7":
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
