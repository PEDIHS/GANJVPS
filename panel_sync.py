from __future__ import annotations

import copy
import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import requests

BACKUP_DIR = Path("/var/lib/ganj-vps/backups")
GANJ_IN_PREFIX = "ganj-"
GANJ_OUT_PREFIX = "ganj-egress-"
GANJ_REMARK_PREFIX = "GANJ "


def _atomic_backup(name: str, data: Any) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    path = BACKUP_DIR / f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _location_map(locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for x in locations:
        code = str(x.get("country_code") or "").upper()
        port = int(x.get("port") or 0)
        if len(code) != 2 or not port or not x.get("enabled", True):
            continue
        out.append({
            "country_code": code,
            "name": str(x.get("name") or code),
            "flag": str(x.get("flag") or ""),
            "port": port,
        })
    return out


def _alloc_ports(existing: set[int], count: int, base: int) -> list[int]:
    result = []
    p = max(1024, int(base))
    while len(result) < count and p <= 65000:
        if p not in existing:
            result.append(p)
            existing.add(p)
        p += 1
    if len(result) != count:
        raise RuntimeError("not_enough_free_ports")
    return result


def system_listening_ports() -> set[int]:
    ports: set[int] = set()
    try:
        p = subprocess.run(
            ["ss", "-H", "-lntu"],
            capture_output=True, text=True, timeout=5,
        )
        for line in p.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[4]
            m = re.search(r":(\d+)$", local)
            if m:
                ports.add(int(m.group(1)))
    except Exception:
        pass
    return ports


def choose_port_block(existing: set[int], count: int, preferred_base: int = 20000, ignore_listening: set[int] | None = None) -> list[int]:
    live = system_listening_ports()
    if ignore_listening:
        live -= set(ignore_listening)
    existing = set(existing) | live
    starts = [preferred_base, 20000, 21000, 22000, 23000, 24000, 25000, 30000, 31000, 32000]
    seen: set[int] = set()
    for start in starts:
        start = max(1024, int(start))
        if start in seen:
            continue
        seen.add(start)
        candidate = list(range(start, start + count))
        if candidate[-1] <= 65000 and not any(p in existing for p in candidate):
            existing.update(candidate)
            return candidate
    return _alloc_ports(existing, count, max(1024, int(preferred_base)))


def _protocol_name(row: dict[str, Any]) -> str:
    return str(row.get("protocol") or row.get("type") or "unknown")


def _listen_text(row: dict[str, Any]) -> str:
    value = row.get("listen")
    if value in (None, "", "0.0.0.0", "::"):
        return "*"
    return str(value)


def _country_from_ganj_remark(value: str) -> str | None:
    m = re.match(r"^GANJ\s+([A-Za-z]{2})(?:\s|·|$)", str(value or "").strip())
    return m.group(1).upper() if m else None


def _strip_runtime_inbound_fields(src: dict[str, Any]) -> dict[str, Any]:
    deny = {
        "id", "up", "down", "total", "expiryTime", "clientStats",
        "lastTrafficResetTime", "created_at", "updated_at",
    }
    return {k: copy.deepcopy(v) for k, v in src.items() if k not in deny}


class PasarGuardAdapter:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.base = str(profile["url"]).rstrip("/")
        self.username = str(profile["username"])
        self.password = str(profile["password"])
        self.core_id = int(profile.get("core_id") or 1)
        self.template_inbound_tag = str(profile.get("template_inbound_tag") or "")
        self.template_host_id = int(profile.get("template_host_id") or 0)
        self.base_port = int(profile.get("base_port") or 20000)
        self.s = requests.Session()
        self.s.trust_env = False
        self.s.verify = bool(profile.get("verify_tls", False))

    def login(self) -> None:
        r = self.s.post(
            f"{self.base}/api/admin/token",
            data={"username": self.username, "password": self.password},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("pasarguard_login_failed")
        self.s.headers["Authorization"] = f"{data.get('token_type','Bearer')} {token}"

    def get_core(self) -> dict[str, Any]:
        r = self.s.get(f"{self.base}/api/core/{self.core_id}", timeout=15)
        r.raise_for_status()
        return r.json()


    def list_cores(self) -> list[dict[str, Any]]:
        r = self.s.get(f"{self.base}/api/cores", params={"all": "true"}, timeout=15)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        data = r.json()
        rows = data.get("cores") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return []
        out = []
        for i, row in enumerate(rows, 1):
            if not isinstance(row, dict):
                continue
            out.append({
                "index": i,
                "id": int(row.get("id") or 0),
                "name": str(row.get("name") or f"Core {row.get('id') or i}"),
                "type": str(row.get("type") or "xray"),
            })
        return out

    def update_core(self, core: dict[str, Any], config: dict[str, Any]) -> None:
        body = {
            "name": core.get("name"),
            "type": core.get("type") or "xray",
            "config": config,
            "exclude_inbound_tags": list(core.get("exclude_inbound_tags") or []),
            "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags") or []),
        }
        r = self.s.put(
            f"{self.base}/api/core/{self.core_id}",
            params={"restart_nodes": "true"},
            json=body,
            timeout=45,
        )
        r.raise_for_status()

    def get_hosts(self) -> list[dict[str, Any]]:
        r = self.s.get(f"{self.base}/api/hosts", timeout=15)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def delete_host(self, host_id: int) -> None:
        r = self.s.delete(f"{self.base}/api/host/{host_id}", timeout=15)
        if r.status_code not in (200, 204, 404):
            r.raise_for_status()

    def create_host(self, host: dict[str, Any]) -> None:
        r = self.s.post(f"{self.base}/api/host/", json=host, timeout=15)
        r.raise_for_status()

    def discover(self) -> dict[str, Any]:
        self.login()
        core = self.get_core()
        cfg = core.get("config") or {}
        inbounds = []
        for i, row in enumerate(cfg.get("inbounds") or [], 1):
            inbounds.append({
                "index": i,
                "tag": str(row.get("tag") or ""),
                "port": int(row.get("port") or 0),
                "protocol": _protocol_name(row),
                "listen": _listen_text(row),
            })
        hosts = []
        for i, row in enumerate(self.get_hosts(), 1):
            hosts.append({
                "index": i,
                "id": int(row.get("id") or 0),
                "remark": str(row.get("remark") or ""),
                "inbound_tag": str(row.get("inbound_tag") or ""),
                "port": row.get("port"),
                "address": sorted(row.get("address") or []) if isinstance(row.get("address"), (set, list, tuple)) else row.get("address"),
            })
        return {
            "ok": True,
            "type": "pasarguard",
            "core": {
                "id": self.core_id,
                "name": core.get("name") or f"Core {self.core_id}",
                "type": core.get("type") or "xray",
            },
            "inbounds": inbounds,
            "hosts": hosts,
        }

    def managed_status(self) -> dict[str, Any]:
        self.login()
        core = self.get_core()
        cfg = core.get("config") or {}
        inbounds = cfg.get("inbounds") or []
        outbounds = cfg.get("outbounds") or []
        rules = (cfg.get("routing") or {}).get("rules") or []
        hosts = self.get_hosts()
        managed_inbounds = [x for x in inbounds if str(x.get("tag") or "").startswith(GANJ_IN_PREFIX)]
        managed_outbounds = [x for x in outbounds if str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        managed_hosts = [x for x in hosts if str(x.get("inbound_tag") or "").startswith(GANJ_IN_PREFIX)]
        return {
            "ok": True,
            "type": "pasarguard",
            "core_id": self.core_id,
            "template_inbound_tag": self.template_inbound_tag,
            "template_host_id": self.template_host_id,
            "base_port": self.base_port,
            "inbounds": len(inbounds),
            "outbounds": len(outbounds),
            "hosts": len(hosts),
            "managed_inbounds": len(managed_inbounds),
            "managed_outbounds": len(managed_outbounds),
            "managed_hosts": len(managed_hosts),
            "managed_rules": sum(
                1 for x in rules
                if str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
            ),
            "managed_ports": sorted(int(x.get("port") or 0) for x in managed_inbounds if x.get("port")),
        }

    def plan_locations(self, locations: list[dict[str, Any]]) -> dict[str, Any]:
        self.login()
        locs = _location_map(locations)
        if not locs:
            raise RuntimeError("no_locations")
        core = self.get_core()
        cfg = core.get("config") or {}
        inbounds = cfg.get("inbounds") or []
        template = next((x for x in inbounds if x.get("tag") == self.template_inbound_tag), None)
        if not template:
            raise RuntimeError("pasarguard_template_inbound_not_found")
        hosts = self.get_hosts()
        template_host = next((x for x in hosts if int(x.get("id") or 0) == self.template_host_id), None)
        if self.template_host_id and not template_host:
            raise RuntimeError("pasarguard_template_host_not_found")
        existing_by_country: dict[str, int] = {}
        for row in inbounds:
            tag = str(row.get("tag") or "")
            if tag.startswith(GANJ_IN_PREFIX) and row.get("port"):
                code = tag[len(GANJ_IN_PREFIX):].upper()
                if len(code) == 2:
                    existing_by_country[code] = int(row["port"])
        used = {
            int(x.get("port"))
            for x in inbounds
            if x.get("port") and not str(x.get("tag") or "").startswith(GANJ_IN_PREFIX)
        }
        preserved = set(existing_by_country.values())
        missing = [loc for loc in locs if loc["country_code"] not in existing_by_country]
        new_ports = iter(choose_port_block(used | preserved, len(missing), self.base_port, ignore_listening=preserved))
        assigned: dict[str, int] = {}
        for loc in locs:
            code = loc["country_code"]
            assigned[code] = existing_by_country.get(code) or next(new_ports)
        items = []
        for loc in locs:
            local_port = assigned[loc["country_code"]]
            items.append({
                "country_code": loc["country_code"],
                "name": loc["name"],
                "gateway_port": loc["port"],
                "local_port": local_port,
                "inbound_tag": GANJ_IN_PREFIX + loc["country_code"].lower(),
                "host_clone": bool(template_host),
            })
        return {
            "ok": True,
            "type": "pasarguard",
            "template_inbound_tag": self.template_inbound_tag,
            "template_host_id": self.template_host_id,
            "items": items,
        }

    def status(self) -> dict[str, Any]:
        return self.managed_status()

    def install_locations(self, locations: list[dict[str, Any]]) -> dict[str, Any]:
        self.login()
        locs = _location_map(locations)
        if not locs:
            raise RuntimeError("no_locations")
        core = self.get_core()
        config = copy.deepcopy(core.get("config") or {})
        inbounds = config.setdefault("inbounds", [])
        outbounds = config.setdefault("outbounds", [])
        routing = config.setdefault("routing", {})
        rules = routing.setdefault("rules", [])

        template = next((x for x in inbounds if x.get("tag") == self.template_inbound_tag), None)
        if not template:
            raise RuntimeError("pasarguard_template_inbound_not_found")

        _atomic_backup("pasarguard-core", core)
        hosts = self.get_hosts()
        template_host = next((x for x in hosts if int(x.get("id") or 0) == self.template_host_id), None)
        if self.template_host_id and not template_host:
            raise RuntimeError("pasarguard_template_host_not_found")

        managed_tags = {GANJ_IN_PREFIX + x["country_code"].lower() for x in locs}
        managed_out = {GANJ_OUT_PREFIX + x["country_code"].lower() for x in locs}
        inbounds[:] = [x for x in inbounds if x.get("tag") not in managed_tags]
        outbounds[:] = [x for x in outbounds if x.get("tag") not in managed_out]
        rules[:] = [
            x for x in rules
            if x.get("outboundTag") not in managed_out
            and not any(str(t).startswith(GANJ_IN_PREFIX) for t in (x.get("inboundTag") or []))
        ]

        plan = self.plan_locations(locs)
        planned_ports = {
            str(x.get("country_code")): int(x.get("local_port"))
            for x in (plan.get("items") or [])
        }

        created = []
        for loc in locs:
            local_port = planned_ports[loc["country_code"]]
            code = loc["country_code"]
            in_tag = GANJ_IN_PREFIX + code.lower()
            out_tag = GANJ_OUT_PREFIX + code.lower()

            inbound = copy.deepcopy(template)
            inbound["tag"] = in_tag
            inbound["port"] = local_port
            inbounds.append(inbound)

            outbounds.append({
                "tag": out_tag,
                "protocol": "socks",
                "settings": {"servers": [{"address": "10.60.0.1", "port": loc["port"]}]},
            })
            rules.insert(0, {
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag,
            })
            created.append({"country_code": code, "inbound_tag": in_tag, "local_port": local_port, "gateway_port": loc["port"]})

        self.update_core(core, config)

        if template_host:
            current_hosts = self.get_hosts()
            for h in current_hosts:
                tag = str(h.get("inbound_tag") or "")
                if tag.startswith(GANJ_IN_PREFIX) and h.get("id"):
                    self.delete_host(int(h["id"]))
            for item, loc in zip(created, locs):
                h = copy.deepcopy(template_host)
                h.pop("id", None)
                h["remark"] = f"{GANJ_REMARK_PREFIX}{loc['country_code']} · {loc['name']}"
                h["inbound_tag"] = item["inbound_tag"]
                host_port_mode = str(self.profile.get("host_port_mode") or "template")
                if host_port_mode == "inbound":
                    h["port"] = int(item["local_port"])
                elif host_port_mode == "none":
                    h["port"] = None
                # template mode intentionally preserves the selected host's port.
                self.create_host(h)

        return {"ok": True, "installed": created, "backup": str(BACKUP_DIR)}

    def remove_locations(self) -> dict[str, Any]:
        self.login()
        core = self.get_core()
        config = copy.deepcopy(core.get("config") or {})
        _atomic_backup("pasarguard-core-remove", core)
        inbounds = config.setdefault("inbounds", [])
        outbounds = config.setdefault("outbounds", [])
        rules = config.setdefault("routing", {}).setdefault("rules", [])
        before = len(inbounds)
        inbounds[:] = [x for x in inbounds if not str(x.get("tag") or "").startswith(GANJ_IN_PREFIX)]
        outbounds[:] = [x for x in outbounds if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        rules[:] = [
            x for x in rules
            if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
            and not any(str(t).startswith(GANJ_IN_PREFIX) for t in (x.get("inboundTag") or []))
        ]
        self.update_core(core, config)
        removed_hosts = 0
        for h in self.get_hosts():
            if str(h.get("inbound_tag") or "").startswith(GANJ_IN_PREFIX) and h.get("id"):
                self.delete_host(int(h["id"]))
                removed_hosts += 1
        return {"ok": True, "removed_inbounds": before - len(inbounds), "removed_hosts": removed_hosts}


class SanaeiAdapter:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.base = str(profile["url"]).rstrip("/")
        self.api_token = str(profile.get("api_token") or "")
        self.username = str(profile.get("username") or "")
        self.password = str(profile.get("password") or "")
        self.template_inbound_id = int(profile.get("template_inbound_id") or 0)
        self.base_port = int(profile.get("base_port") or 20000)
        self.s = requests.Session()
        self.s.trust_env = False
        self.s.verify = bool(profile.get("verify_tls", False))
        self.s.headers.update({"Accept": "application/json"})
        if self.api_token:
            self.s.headers["Authorization"] = f"Bearer {self.api_token}"

    def login(self) -> None:
        if self.api_token:
            return
        r = self.s.post(f"{self.base}/login", data={"username": self.username, "password": self.password}, timeout=15)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError("sanaei_login_failed")

    def list_inbounds(self) -> list[dict[str, Any]]:
        r = self.s.post(f"{self.base}/panel/api/inbounds/list", timeout=15)
        if r.status_code != 200:
            r = self.s.get(f"{self.base}/panel/api/inbounds/list", timeout=15)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError("sanaei_list_inbounds_failed")
        return data.get("obj") or []

    def add_inbound(self, payload: dict[str, Any]) -> None:
        url = f"{self.base}/panel/api/inbounds/add"
        r = self.s.post(url, json=payload, timeout=15)
        ok = False
        try:
            ok = r.status_code == 200 and bool(r.json().get("success"))
        except Exception:
            ok = False
        if ok:
            return

        form: dict[str, Any] = {}
        for key, value in payload.items():
            if key in {"settings", "streamSettings", "sniffing", "allocate"} and not isinstance(value, str):
                form[key] = json.dumps(value, separators=(",", ":"))
            elif isinstance(value, bool):
                form[key] = "true" if value else "false"
            else:
                form[key] = value
        r = self.s.post(url, data=form, timeout=15)
        r.raise_for_status()
        try:
            data = r.json()
        except Exception as exc:
            raise RuntimeError("sanaei_add_inbound_invalid_response") from exc
        if not data.get("success"):
            raise RuntimeError("sanaei_add_inbound_failed")

    def delete_inbound(self, inbound_id: int) -> None:
        r = self.s.post(f"{self.base}/panel/api/inbounds/del/{inbound_id}", timeout=15)
        if r.status_code != 200:
            r.raise_for_status()

    def get_xray(self) -> tuple[dict[str, Any], str]:
        r = self.s.post(f"{self.base}/panel/api/xray/", timeout=15)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError("sanaei_xray_settings_failed")
        obj = data.get("obj") or {}
        raw = obj.get("xraySetting") or "{}"
        cfg = json.loads(raw) if isinstance(raw, str) else raw
        return cfg, str(obj.get("outboundTestUrl") or "https://www.gstatic.com/generate_204")

    def update_xray(self, cfg: dict[str, Any], test_url: str) -> None:
        r = self.s.post(
            f"{self.base}/panel/api/xray/update",
            data={"xraySetting": json.dumps(cfg, separators=(",", ":")), "outboundTestUrl": test_url},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError("sanaei_xray_update_failed")

    def discover(self) -> dict[str, Any]:
        self.login()
        rows = self.list_inbounds()
        inbounds = []
        for i, row in enumerate(rows, 1):
            inbounds.append({
                "index": i,
                "id": int(row.get("id") or 0),
                "remark": str(row.get("remark") or ""),
                "port": int(row.get("port") or 0),
                "protocol": _protocol_name(row),
                "listen": _listen_text(row),
                "enable": bool(row.get("enable", True)),
                "tag": str(row.get("tag") or ""),
            })
        return {"ok": True, "type": "sanaei", "inbounds": inbounds}

    def managed_status(self) -> dict[str, Any]:
        self.login()
        rows = self.list_inbounds()
        managed = [x for x in rows if str(x.get("remark") or "").startswith(GANJ_REMARK_PREFIX)]
        cfg, _ = self.get_xray()
        outbounds = cfg.get("outbounds") or []
        rules = (cfg.get("routing") or {}).get("rules") or []
        return {
            "ok": True,
            "type": "sanaei",
            "template_inbound_id": self.template_inbound_id,
            "base_port": self.base_port,
            "inbounds": len(rows),
            "managed_inbounds": len(managed),
            "managed_outbounds": sum(1 for x in outbounds if str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)),
            "managed_rules": sum(1 for x in rules if str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)),
            "managed_ports": sorted(int(x.get("port") or 0) for x in managed if x.get("port")),
        }

    def plan_locations(self, locations: list[dict[str, Any]]) -> dict[str, Any]:
        self.login()
        locs = _location_map(locations)
        if not locs:
            raise RuntimeError("no_locations")
        rows = self.list_inbounds()
        template = next((x for x in rows if int(x.get("id") or 0) == self.template_inbound_id), None)
        if not template:
            raise RuntimeError("sanaei_template_inbound_not_found")
        existing_by_country: dict[str, int] = {}
        for row in rows:
            code = _country_from_ganj_remark(str(row.get("remark") or ""))
            if code and row.get("port"):
                existing_by_country[code] = int(row["port"])
        used = {
            int(x.get("port"))
            for x in rows
            if x.get("port") and not str(x.get("remark") or "").startswith(GANJ_REMARK_PREFIX)
        }
        preserved = set(existing_by_country.values())
        missing = [loc for loc in locs if loc["country_code"] not in existing_by_country]
        new_ports = iter(choose_port_block(used | preserved, len(missing), self.base_port, ignore_listening=preserved))
        assigned: dict[str, int] = {}
        for loc in locs:
            code = loc["country_code"]
            assigned[code] = existing_by_country.get(code) or next(new_ports)
        items = []
        for loc in locs:
            local_port = assigned[loc["country_code"]]
            items.append({
                "country_code": loc["country_code"],
                "name": loc["name"],
                "gateway_port": loc["port"],
                "local_port": local_port,
                "template_inbound_id": self.template_inbound_id,
            })
        return {"ok": True, "type": "sanaei", "items": items}

    def status(self) -> dict[str, Any]:
        return self.managed_status()

    def install_locations(self, locations: list[dict[str, Any]]) -> dict[str, Any]:
        self.login()
        locs = _location_map(locations)
        rows = self.list_inbounds()
        template = next((x for x in rows if int(x.get("id") or 0) == self.template_inbound_id), None)
        if not template:
            raise RuntimeError("sanaei_template_inbound_not_found")
        _atomic_backup("sanaei-inbounds", rows)

        for x in rows:
            if str(x.get("remark") or "").startswith(GANJ_REMARK_PREFIX) and x.get("id"):
                self.delete_inbound(int(x["id"]))

        plan = self.plan_locations(locs)
        planned_ports = {
            str(x.get("country_code")): int(x.get("local_port"))
            for x in (plan.get("items") or [])
        }
        created = []

        allowed = ["enable","listen","protocol","settings","streamSettings","sniffing","allocate"]
        for loc in locs:
            port = planned_ports[loc["country_code"]]
            payload = {k: copy.deepcopy(template[k]) for k in allowed if k in template}
            payload["remark"] = f"{GANJ_REMARK_PREFIX}{loc['country_code']} · {loc['name']}"
            payload["port"] = port
            payload["enable"] = True
            self.add_inbound(payload)
            created.append({"country_code": loc["country_code"], "local_port": port, "gateway_port": loc["port"]})

        now_rows = self.list_inbounds()
        cfg, test_url = self.get_xray()
        _atomic_backup("sanaei-xray", cfg)
        outbounds = cfg.setdefault("outbounds", [])
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        outbounds[:] = [x for x in outbounds if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        rules[:] = [
            x for x in rules
            if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
            and not any(str(t).startswith(GANJ_IN_PREFIX) for t in (x.get("inboundTag") or []))
        ]

        for item, loc in zip(created, locs):
            row = next((x for x in now_rows if x.get("remark") == f"{GANJ_REMARK_PREFIX}{loc['country_code']} · {loc['name']}"), None)
            inbound_tag = str((row or {}).get("tag") or (f"inbound-{row.get('id')}" if row and row.get("id") else f"inbound-{item['local_port']}"))
            item["inbound_tag"] = inbound_tag
            out_tag = GANJ_OUT_PREFIX + loc["country_code"].lower()
            outbounds.append({
                "tag": out_tag,
                "protocol": "socks",
                "settings": {"servers": [{"address": "10.60.0.1", "port": loc["port"]}]},
            })
            rules.insert(0, {"type": "field", "inboundTag": [inbound_tag], "outboundTag": out_tag})

        self.update_xray(cfg, test_url)
        return {"ok": True, "installed": created, "backup": str(BACKUP_DIR)}

    def remove_locations(self) -> dict[str, Any]:
        self.login()
        removed = 0
        for x in self.list_inbounds():
            if str(x.get("remark") or "").startswith(GANJ_REMARK_PREFIX) and x.get("id"):
                self.delete_inbound(int(x["id"]))
                removed += 1
        cfg, test_url = self.get_xray()
        _atomic_backup("sanaei-xray-remove", cfg)
        outbounds = cfg.setdefault("outbounds", [])
        rules = cfg.setdefault("routing", {}).setdefault("rules", [])
        outbounds[:] = [x for x in outbounds if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        rules[:] = [x for x in rules if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)]
        self.update_xray(cfg, test_url)
        return {"ok": True, "removed_inbounds": removed}


def adapter_from_profile(profile: dict[str, Any]):
    kind = str(profile.get("type") or "")
    if kind == "pasarguard":
        return PasarGuardAdapter(profile)
    if kind == "sanaei":
        return SanaeiAdapter(profile)
    raise RuntimeError("panel_profile_not_configured")


def detect_sanaei_local() -> dict[str, Any] | None:
    binary = Path("/usr/local/x-ui/x-ui")
    if not binary.exists():
        return None
    def cli(*args):
        p = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=10)
        return (p.stdout or "") + "\n" + (p.stderr or "")
    show = cli("setting", "-show")
    m_port = re.search(r"(?mi)^\s*port:\s*(\d+)", show)
    if not m_port:
        return None
    m_path = re.search(r"(?mi)^\s*webBasePath:\s*(\S*)", show)
    base_path = (m_path.group(1) if m_path else "").strip().strip("/")
    tok = cli("setting", "-getApiToken")
    m_tok = re.search(r"(?mi)^\s*apiToken:\s*(\S+)", tok)
    if not m_tok:
        return None
    port = m_port.group(1)
    base = f"http://127.0.0.1:{port}"
    if base_path:
        base += "/" + base_path
    return {"type": "sanaei", "url": base, "api_token": m_tok.group(1), "verify_tls": False}
