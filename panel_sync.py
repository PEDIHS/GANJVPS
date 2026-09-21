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
REQUIRED_USER_PROTOCOL = "vless"

# Canonical GANJ location catalog. The order is also the deterministic
# user-facing inbound port order: 6000, 6001, ... 6039.
PORT_RANGE_START = 6000
PORT_RANGE_END = 6039
LOCATION_CATALOG = {
    "DE": {"country": "Germany", "city": "Berlin", "flag": "🇩🇪"},
    "NL": {"country": "Netherlands", "city": "Amsterdam", "flag": "🇳🇱"},
    "FR": {"country": "France", "city": "Paris", "flag": "🇫🇷"},
    "GB": {"country": "United Kingdom", "city": "London", "flag": "🇬🇧"},
    "TR": {"country": "Türkiye", "city": "Ankara", "flag": "🇹🇷"},
    "FI": {"country": "Finland", "city": "Helsinki", "flag": "🇫🇮"},
    "SE": {"country": "Sweden", "city": "Stockholm", "flag": "🇸🇪"},
    "CH": {"country": "Switzerland", "city": "Bern", "flag": "🇨🇭"},
    "AT": {"country": "Austria", "city": "Vienna", "flag": "🇦🇹"},
    "BE": {"country": "Belgium", "city": "Brussels", "flag": "🇧🇪"},
    "PL": {"country": "Poland", "city": "Warsaw", "flag": "🇵🇱"},
    "IT": {"country": "Italy", "city": "Rome", "flag": "🇮🇹"},
    "ES": {"country": "Spain", "city": "Madrid", "flag": "🇪🇸"},
    "RO": {"country": "Romania", "city": "Bucharest", "flag": "🇷🇴"},
    "BG": {"country": "Bulgaria", "city": "Sofia", "flag": "🇧🇬"},
    "CZ": {"country": "Czechia", "city": "Prague", "flag": "🇨🇿"},
    "NO": {"country": "Norway", "city": "Oslo", "flag": "🇳🇴"},
    "DK": {"country": "Denmark", "city": "Copenhagen", "flag": "🇩🇰"},
    "IE": {"country": "Ireland", "city": "Dublin", "flag": "🇮🇪"},
    "LT": {"country": "Lithuania", "city": "Vilnius", "flag": "🇱🇹"},
    "LV": {"country": "Latvia", "city": "Riga", "flag": "🇱🇻"},
    "EE": {"country": "Estonia", "city": "Tallinn", "flag": "🇪🇪"},
    "US": {"country": "United States", "city": "Washington, D.C.", "flag": "🇺🇸"},
    "CA": {"country": "Canada", "city": "Ottawa", "flag": "🇨🇦"},
    "AE": {"country": "United Arab Emirates", "city": "Abu Dhabi", "flag": "🇦🇪"},
    "RU": {"country": "Russia", "city": "Moscow", "flag": "🇷🇺"},
    "SG": {"country": "Singapore", "city": "Singapore", "flag": "🇸🇬"},
    "JP": {"country": "Japan", "city": "Tokyo", "flag": "🇯🇵"},
    "KR": {"country": "South Korea", "city": "Seoul", "flag": "🇰🇷"},
    "AU": {"country": "Australia", "city": "Canberra", "flag": "🇦🇺"},
    "BR": {"country": "Brazil", "city": "São Paulo", "flag": "🇧🇷"},
    "MX": {"country": "Mexico", "city": "Mexico City", "flag": "🇲🇽"},
    "IN": {"country": "India", "city": "New Delhi", "flag": "🇮🇳"},
    "HK": {"country": "Hong Kong", "city": "Hong Kong", "flag": "🇭🇰"},
    "TW": {"country": "Taiwan", "city": "Taipei", "flag": "🇹🇼"},
    "TH": {"country": "Thailand", "city": "Bangkok", "flag": "🇹🇭"},
    "MY": {"country": "Malaysia", "city": "Kuala Lumpur", "flag": "🇲🇾"},
    "ID": {"country": "Indonesia", "city": "Jakarta", "flag": "🇮🇩"},
    "ZA": {"country": "South Africa", "city": "Pretoria", "flag": "🇿🇦"},
    "UA": {"country": "Ukraine", "city": "Kyiv", "flag": "🇺🇦"},
}
PREFERRED_LOCAL_PORTS = {
    code: PORT_RANGE_START + index
    for index, code in enumerate(LOCATION_CATALOG)
}
if PREFERRED_LOCAL_PORTS and max(PREFERRED_LOCAL_PORTS.values()) > PORT_RANGE_END:
    raise RuntimeError("ganj_location_catalog_exceeds_reserved_port_range")

DISPLAY_LABELS = {
    code: f"{meta['flag']} {meta['country']} — {meta['city']}"
    for code, meta in LOCATION_CATALOG.items()
}

# Exact legacy labels accepted only for migration. Do not classify every
# flag-prefixed user object as GANJ-owned: operators may have unrelated
# inbounds/hosts such as "🇩🇪 Personal".
LEGACY_DISPLAY_LABELS = {
    code: {
        f"{meta['flag']} {meta['country']}",
        f"GANJ {code} · {meta['country']}",
    }
    for code, meta in LOCATION_CATALOG.items()
}
LEGACY_DISPLAY_LABELS["FR"].add("🇫🇷 France dc")
LEGACY_DISPLAY_LABELS["NL"].add("🇳🇱 The Netherlands")


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
        if len(code) != 2:
            continue
        port = int(x.get("port") or 0)
        enabled = bool(x.get("enabled", True))
        central_available = x.get("available")
        meta = LOCATION_CATALOG.get(code) or {}
        out.append({
            "country_code": code,
            "name": str(x.get("name") or meta.get("country") or code),
            "city": str(x.get("city") or meta.get("city") or ""),
            "flag": str(x.get("flag") or meta.get("flag") or ""),
            "port": port,
            "enabled": enabled,
            "available": bool(
                enabled and port and
                (bool(central_available) if central_available is not None else True)
            ),
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
    if int(count) <= 0:
        return []
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


def _display_label(loc: dict[str, Any]) -> str:
    code = str(loc.get("country_code") or "").upper()
    if code in DISPLAY_LABELS:
        return DISPLAY_LABELS[code]
    flag = str(loc.get("flag") or "").strip()
    name = str(loc.get("name") or code).strip()
    return f"{flag} {name}".strip()

def _pasarguard_location_tag(loc: dict[str, Any]) -> str:
    # PasarGuard rejects commas in inbound tags. The ganj-XX prefix is also
    # the strict ownership boundary so old operator country objects are safe.
    code = str(loc.get("country_code") or "").upper()
    label = _display_label(loc)
    label = re.sub(r"[,\r\n\t]+", " ", label)
    label = re.sub(r"\s+", " ", label).strip()
    return f"{GANJ_IN_PREFIX}{code.lower()} {label}".strip()


def _is_ganj_pasarguard_owned_tag(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw.startswith(GANJ_IN_PREFIX):
        return False
    code = raw[len(GANJ_IN_PREFIX):len(GANJ_IN_PREFIX) + 2].upper()
    return code in LOCATION_CATALOG


GANJ_SHARED_PUBLIC_PORT = 443


def _pasarguard_shared_sni(local_port: int) -> str:
    # The selected REALITY template targets www.aparat.com and its certificate
    # covers *.aparat.com. A unique, certificate-valid SNI lets HAProxy
    # demultiplex all GANJ locations on the single public HTTPS port.
    return f"hs-{int(local_port)}.aparat.com"


def _apply_pasarguard_shared_sni(
    inbound: dict[str, Any],
    local_port: int,
) -> str | None:
    stream = inbound.get("streamSettings") or {}
    reality = stream.get("realitySettings")
    if not isinstance(reality, dict):
        return None
    sni = _pasarguard_shared_sni(local_port)
    names = [str(x) for x in (reality.get("serverNames") or []) if str(x)]
    if sni not in names:
        names.append(sni)
    reality["serverNames"] = names
    stream["realitySettings"] = reality
    inbound["streamSettings"] = stream
    return sni


def _clone_pasarguard_host(
    template_host: dict[str, Any],
    inbound_tag: str,
    local_port: int,
    remark: str,
    public_sni: str | None = None,
) -> dict[str, Any]:
    # Clone the selected Host. The generated inbound stays on its stable local
    # port, while REALITY hosts are published on shared public :443 and use a
    # unique certificate-valid SNI. Cached old clients remain supported by the
    # legacy high-port HAProxy frontends.
    host = copy.deepcopy(template_host)
    host.pop("id", None)
    host["inbound_tag"] = str(inbound_tag)
    host["port"] = GANJ_SHARED_PUBLIC_PORT if public_sni else int(local_port)
    if public_sni:
        host["sni"] = [str(public_sni)]
    host["remark"] = str(remark)
    return host


def _validate_pasarguard_template_pair(
    template_inbound: dict[str, Any],
    template_host: dict[str, Any] | None,
) -> None:
    if not template_host:
        return
    inbound_tag = str(template_inbound.get("tag") or "")
    host_tag = str(template_host.get("inbound_tag") or "")
    if host_tag and host_tag != inbound_tag:
        raise RuntimeError(
            "pasarguard_template_host_inbound_mismatch:"
            f"host={host_tag}:inbound={inbound_tag}"
        )


def _template_requires_proxy_frontend(template: dict[str, Any]) -> bool:
    listen = str(template.get("listen") or "").strip().lower()
    sockopt = ((template.get("streamSettings") or {}).get("sockopt") or {})
    return (
        listen in {"127.0.0.1", "localhost", "::1"}
        and bool(sockopt.get("acceptProxyProtocol"))
    )


def _primary_bind_ipv4() -> str:
    try:
        p = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        m = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", p.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    raise RuntimeError("ganj_public_bind_ipv4_not_detected")


_HAPROXY_BEGIN = "# BEGIN GANJ VPS LOCATION PORTS"
_HAPROXY_END = "# END GANJ VPS LOCATION PORTS"


def _haproxy_without_ganj_block(text: str) -> str:
    if _HAPROXY_BEGIN not in text:
        return text.rstrip() + "\n"
    if _HAPROXY_END not in text:
        raise RuntimeError("ganj_haproxy_marker_corrupt")
    start = text.index(_HAPROXY_BEGIN)
    end = text.index(_HAPROXY_END, start) + len(_HAPROXY_END)
    return (text[:start].rstrip() + "\n\n" + text[end:].lstrip()).rstrip() + "\n"


def _ganj_haproxy_block(bind_ip: str, ports: list[int]) -> str:
    lines = [_HAPROXY_BEGIN]
    for port in sorted({int(x) for x in ports}):
        lines.extend([
            f"frontend ft_ganj_{port}",
            "    mode tcp",
            f"    bind {bind_ip}:{port}",
            f"    default_backend be_ganj_{port}",
            "",
            f"backend be_ganj_{port}",
            "    mode tcp",
            f"    server xray 127.0.0.1:{port} send-proxy",
            "",
        ])
    lines.append(_HAPROXY_END)
    return "\n".join(lines) + "\n"


def _sync_pasarguard_haproxy_ports(
    template: dict[str, Any],
    ports: list[int],
) -> dict[str, Any]:
    cfg = Path(os.environ.get("GANJ_HAPROXY_CONFIG", "/etc/haproxy/haproxy.cfg"))
    if not _template_requires_proxy_frontend(template):
        return {"managed": False, "ports": []}

    if not cfg.exists():
        raise RuntimeError("pasarguard_proxy_protocol_requires_haproxy_config")
    if not Path("/usr/sbin/haproxy").exists() and not Path("/usr/local/sbin/haproxy").exists():
        raise RuntimeError("pasarguard_proxy_protocol_requires_haproxy")

    current = cfg.read_text(encoding="utf-8")
    base = _haproxy_without_ganj_block(current)
    desired_ports = sorted({int(x) for x in ports})
    bind_ip = _primary_bind_ipv4()
    desired = base
    if desired_ports:
        desired = base.rstrip() + "\n\n" + _ganj_haproxy_block(bind_ip, desired_ports)

    if desired == current:
        return {"managed": True, "ports": desired_ports, "bind_ip": bind_ip}

    candidate = cfg.with_name(cfg.name + ".ganj-candidate")
    candidate.write_text(desired, encoding="utf-8")
    try:
        check = subprocess.run(
            ["haproxy", "-c", "-f", str(candidate)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if check.returncode != 0:
            raise RuntimeError(
                "ganj_haproxy_validation_failed:" +
                (check.stderr or check.stdout)[-500:].replace("\n", " ")
            )

        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup = BACKUP_DIR / f"haproxy-{time.strftime('%Y%m%d-%H%M%S')}.cfg"
        backup.write_text(current, encoding="utf-8")
        os.chmod(backup, 0o600)

        cfg.write_text(desired, encoding="utf-8")
        reload_result = subprocess.run(
            ["systemctl", "reload", "haproxy"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if reload_result.returncode != 0:
            cfg.write_text(current, encoding="utf-8")
            subprocess.run(
                ["systemctl", "reload", "haproxy"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            raise RuntimeError(
                "ganj_haproxy_reload_failed:" +
                (reload_result.stderr or reload_result.stdout)[-500:].replace("\n", " ")
            )
    finally:
        candidate.unlink(missing_ok=True)

    if desired_ports:
        deadline = time.time() + 10
        missing = set(desired_ports)
        while time.time() < deadline:
            live = system_listening_ports()
            missing = set(desired_ports) - live
            if not missing:
                break
            time.sleep(0.5)
        if missing:
            raise RuntimeError(
                "ganj_haproxy_public_ports_not_listening:" +
                ",".join(str(x) for x in sorted(missing))
            )

    return {"managed": True, "ports": desired_ports, "bind_ip": bind_ip}


def _country_from_ganj_remark(value: str) -> str | None:
    raw = str(value or "").strip()
    m = re.match(r"^GANJ\s+([A-Za-z]{2})(?:\s|·|$)", raw)
    if m:
        code = m.group(1).upper()
        return code if code in LOCATION_CATALOG else None
    for code, label in DISPLAY_LABELS.items():
        if raw == label or raw in LEGACY_DISPLAY_LABELS.get(code, set()):
            return code
    return None


def _country_from_pasarguard_tag(value: str) -> str | None:
    raw = str(value or "").strip()
    if raw.startswith(GANJ_IN_PREFIX):
        code = raw[len(GANJ_IN_PREFIX):len(GANJ_IN_PREFIX) + 2].upper()
        if code in LOCATION_CATALOG:
            return code
    return _country_from_ganj_remark(raw)


def _is_ganj_pasarguard_tag(value: str) -> bool:
    return _country_from_pasarguard_tag(value) is not None


def _require_vless(template: dict[str, Any]) -> None:
    if _protocol_name(template).lower() != REQUIRED_USER_PROTOCOL:
        raise RuntimeError("template_protocol_must_be_vless")


def _gateway_outbound(loc: dict[str, Any], out_tag: str) -> dict[str, Any]:
    if bool(loc.get("available")) and int(loc.get("port") or 0) > 0:
        return {
            "tag": out_tag,
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": "10.60.0.1",
                    "port": int(loc["port"]),
                }]
            },
        }
    # Keep the Host/Inbound pre-created without allowing accidental direct
    # egress before the central gateway publishes a real config for it.
    return {
        "tag": out_tag,
        "protocol": "blackhole",
        "settings": {"response": {"type": "none"}},
    }


def _plan_stable_country_ports(
    locs: list[dict[str, Any]],
    used: set[int],
    existing_by_country: dict[str, int],
) -> dict[str, int]:
    live = system_listening_ports()
    preserved = set(existing_by_country.values())
    assigned: dict[str, int] = {}
    for loc in locs:
        code = loc["country_code"]
        preferred = PREFERRED_LOCAL_PORTS.get(code)
        if preferred is None:
            raise RuntimeError(f"preferred_port_missing_{code}")

        owner = next(
            (other for other, port in existing_by_country.items() if int(port) == int(preferred)),
            None,
        )
        if owner and owner != code:
            raise RuntimeError(f"preferred_port_owned_by_{owner}_{preferred}")
        if preferred in used or (preferred in live and preferred not in preserved):
            raise RuntimeError(f"preferred_port_conflict_{code}_{preferred}")

        assigned[code] = int(preferred)
        used.add(int(preferred))
    return assigned


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
        if not self.s.verify:
            requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
            )

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

    def _wait_core_after_restart(self, expected_config: dict[str, Any], timeout: int = 75) -> None:
        deadline = time.time() + max(10, int(timeout))
        last_error = ""
        while time.time() < deadline:
            try:
                # A PasarGuard all-in-one restart can replace the panel
                # container itself, invalidating the old HTTP connection and
                # bearer token. Re-login and verify the persisted Core.
                self.login()
                current = self.get_core()
                if (current.get("config") or {}) == expected_config:
                    return
                last_error = "core_config_mismatch_after_restart"
            except Exception as exc:
                last_error = f"{type(exc).__name__}:{exc}"
            time.sleep(2)
        raise RuntimeError(
            f"pasarguard_restart_recovery_timeout:{last_error[:300]}"
        )

    def _put_core(self, core: dict[str, Any], config: dict[str, Any], restart_nodes: bool) -> None:
        body = {
            "name": core.get("name"),
            "type": core.get("type") or "xray",
            "config": config,
            "exclude_inbound_tags": list(core.get("exclude_inbound_tags") or []),
            "fallbacks_inbound_tags": list(core.get("fallbacks_inbound_tags") or []),
        }
        try:
            r = self.s.put(
                f"{self.base}/api/core/{self.core_id}",
                params={"restart_nodes": "true" if restart_nodes else "false"},
                json=body,
                timeout=45,
            )
        except requests.RequestException:
            if restart_nodes:
                # Expected on PasarGuard all-in-one: the restart may close the
                # API socket before an HTTP response is returned.
                self._wait_core_after_restart(config)
                return
            raise

        if r.status_code >= 400:
            if restart_nodes and r.status_code in (502, 503, 504):
                self._wait_core_after_restart(config)
                return
            detail = (r.text or "").strip()
            raise RuntimeError(
                f"pasarguard_core_update_failed_http_{r.status_code}: {detail[:500]}"
            )

    def update_core(self, core: dict[str, Any], config: dict[str, Any]) -> None:
        # Save first without restarting. Restart happens once, after Core and
        # Host read-back verification succeeds.
        self._put_core(core, config, restart_nodes=False)

    def restart_core(self, core: dict[str, Any], config: dict[str, Any]) -> None:
        self._put_core(core, config, restart_nodes=True)

    def get_hosts(self) -> list[dict[str, Any]]:
        r = self.s.get(f"{self.base}/api/hosts", timeout=15)
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def get_groups(self) -> list[dict[str, Any]]:
        r = self.s.get(
            f"{self.base}/api/groups",
            params={"limit": 10000},
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        rows = data.get("groups") if isinstance(data, dict) else data
        return rows if isinstance(rows, list) else []

    def update_group(self, group: dict[str, Any]) -> None:
        group_id = int(group.get("id") or 0)
        if not group_id:
            raise RuntimeError("pasarguard_group_id_missing")
        body = {
            "name": str(group.get("name") or ""),
            "inbound_tags": list(group.get("inbound_tags") or []),
            "is_disabled": bool(group.get("is_disabled")),
        }
        r = self.s.put(
            f"{self.base}/api/group/{group_id}",
            json=body,
            timeout=180,
        )
        if r.status_code >= 400:
            detail = (r.text or "").strip()
            raise RuntimeError(
                f"pasarguard_group_update_failed_http_{r.status_code}: "
                f"{detail[:500]}"
            )

    def template_groups(self) -> list[dict[str, Any]]:
        return [
            copy.deepcopy(group)
            for group in self.get_groups()
            if self.template_inbound_tag in (group.get("inbound_tags") or [])
        ]

    def restore_groups(self, snapshot: list[dict[str, Any]]) -> None:
        for group in snapshot:
            self.update_group(copy.deepcopy(group))

    def sync_template_groups(
        self,
        managed_tags: set[str],
        snapshot: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        # PasarGuard authorizes/synchronizes users through Group -> Inbound
        # membership. Cloning only the Core inbound and Host leaves generated
        # locations unauthenticated for users outside whatever default group
        # PasarGuard happened to assign. Mirror the selected template's group
        # memberships for every GANJ-managed inbound.
        template_groups = (
            copy.deepcopy(snapshot)
            if snapshot is not None
            else self.template_groups()
        )
        if not template_groups:
            return {
                "template_groups": [],
                "updated_groups": [],
                "managed_tags": len(managed_tags),
                "verified": True,
            }

        _atomic_backup("pasarguard-groups", template_groups)
        changed_originals: list[dict[str, Any]] = []
        updated_ids: list[int] = []
        ordered_managed = sorted(str(x) for x in managed_tags)

        try:
            for group in template_groups:
                existing = list(group.get("inbound_tags") or [])
                merged = list(dict.fromkeys(existing + ordered_managed))
                if merged == existing:
                    continue
                changed_originals.append(copy.deepcopy(group))
                payload = copy.deepcopy(group)
                payload["inbound_tags"] = merged
                self.update_group(payload)
                updated_ids.append(int(group.get("id") or 0))

            # Read-after-write verification is mandatory because missing group
            # membership produces valid-looking Hosts/ports but every client
            # handshake times out.
            verify = {int(g.get("id") or 0): g for g in self.get_groups()}
            missing: dict[int, list[str]] = {}
            for group in template_groups:
                gid = int(group.get("id") or 0)
                current = set((verify.get(gid) or {}).get("inbound_tags") or [])
                absent = sorted(set(ordered_managed) - current)
                if absent:
                    missing[gid] = absent
            if missing:
                raise RuntimeError(
                    "pasarguard_group_membership_verification_failed:"
                    + ",".join(
                        f"{gid}:{len(tags)}"
                        for gid, tags in sorted(missing.items())
                    )
                )
        except Exception:
            for group in changed_originals:
                try:
                    self.update_group(group)
                except Exception:
                    pass
            raise

        return {
            "template_groups": [
                {"id": int(g.get("id") or 0), "name": str(g.get("name") or "")}
                for g in template_groups
            ],
            "updated_groups": updated_ids,
            "managed_tags": len(managed_tags),
            "verified": True,
        }

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
        managed_inbounds = [x for x in inbounds if _is_ganj_pasarguard_owned_tag(str(x.get("tag") or ""))]
        managed_outbounds = [x for x in outbounds if str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        managed_hosts = [x for x in hosts if _is_ganj_pasarguard_owned_tag(str(x.get("inbound_tag") or ""))]
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
        if _is_ganj_pasarguard_tag(str(template.get("tag") or "")):
            raise RuntimeError("pasarguard_template_must_be_dedicated_non_ganj_inbound")
        _require_vless(template)
        hosts = self.get_hosts()
        template_host = next((x for x in hosts if int(x.get("id") or 0) == self.template_host_id), None)
        if self.template_host_id and not template_host:
            raise RuntimeError("pasarguard_template_host_not_found")
        _validate_pasarguard_template_pair(template, template_host)
        _validate_pasarguard_template_pair(template, template_host)
        existing_by_country: dict[str, int] = {}
        for row in inbounds:
            tag = str(row.get("tag") or "")
            code = _country_from_pasarguard_tag(tag)
            if code and row.get("port"):
                existing_by_country[code] = int(row["port"])
        used = {
            int(x.get("port"))
            for x in inbounds
            if x.get("port") and not _is_ganj_pasarguard_owned_tag(str(x.get("tag") or ""))
        }
        assigned = _plan_stable_country_ports(locs, used, existing_by_country)
        items = []
        for loc in locs:
            local_port = assigned[loc["country_code"]]
            items.append({
                "country_code": loc["country_code"],
                "name": loc["name"],
                "gateway_port": int(loc["port"]) if loc.get("available") else None,
                "local_port": local_port,
                "inbound_tag": _pasarguard_location_tag(loc),
                "host_clone": bool(template_host),
                "available": bool(loc.get("available")),
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

        # Plan first so an existing GANJ port mapping remains stable on re-sync.
        plan = self.plan_locations(locs)
        planned_ports = {
            str(x.get("country_code")): int(x.get("local_port"))
            for x in (plan.get("items") or [])
        }

        core = self.get_core()
        old_core = copy.deepcopy(core)
        config = copy.deepcopy(core.get("config") or {})
        inbounds = config.setdefault("inbounds", [])
        outbounds = config.setdefault("outbounds", [])
        routing = config.setdefault("routing", {})
        rules = routing.setdefault("rules", [])

        template = next((x for x in inbounds if x.get("tag") == self.template_inbound_tag), None)
        if not template:
            raise RuntimeError("pasarguard_template_inbound_not_found")

        hosts = self.get_hosts()
        template_host = next((x for x in hosts if int(x.get("id") or 0) == self.template_host_id), None)
        if self.template_host_id and not template_host:
            raise RuntimeError("pasarguard_template_host_not_found")
        old_managed_hosts = [
            copy.deepcopy(x) for x in hosts
            if _is_ganj_pasarguard_owned_tag(str(x.get("inbound_tag") or ""))
        ]
        old_template_groups = self.template_groups()

        _atomic_backup("pasarguard-core", old_core)
        if old_managed_hosts:
            _atomic_backup("pasarguard-hosts", old_managed_hosts)
        if old_template_groups:
            _atomic_backup("pasarguard-groups-preinstall", old_template_groups)

        managed_tags = {_pasarguard_location_tag(x) for x in locs}
        managed_out = {GANJ_OUT_PREFIX + x["country_code"].lower() for x in locs}
        inbounds[:] = [
            x for x in inbounds
            if not _is_ganj_pasarguard_owned_tag(str(x.get("tag") or ""))
        ]
        outbounds[:] = [
            x for x in outbounds
            if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)
        ]
        rules[:] = [
            x for x in rules
            if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
            and not any(_is_ganj_pasarguard_owned_tag(str(t)) for t in (x.get("inboundTag") or []))
        ]

        created = []
        for loc in locs:
            code = loc["country_code"]
            local_port = planned_ports[code]
            in_tag = _pasarguard_location_tag(loc)
            out_tag = GANJ_OUT_PREFIX + code.lower()

            inbound = copy.deepcopy(template)
            inbound["tag"] = in_tag
            inbound["port"] = local_port
            inbounds.append(inbound)

            outbounds.append(_gateway_outbound(loc, out_tag))
            rules.insert(0, {
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag,
            })
            created.append({
                "country_code": code,
                "inbound_tag": in_tag,
                "local_port": local_port,
                "gateway_port": int(loc["port"]) if loc.get("available") else None,
                "available": bool(loc.get("available")),
            })

        core_applied = False
        groups_applied = False
        group_sync: dict[str, Any] = {
            "template_groups": [],
            "updated_groups": [],
            "managed_tags": len(managed_tags),
            "verified": False,
        }
        try:
            self.update_core(core, config)
            core_applied = True

            if template_host:
                for h in self.get_hosts():
                    tag = str(h.get("inbound_tag") or "")
                    if _is_ganj_pasarguard_owned_tag(tag) and h.get("id"):
                        self.delete_host(int(h["id"]))

                for item, loc in zip(created, locs):
                    h = _clone_pasarguard_host(
                        template_host,
                        item["inbound_tag"],
                        int(item["local_port"]),
                        _display_label(loc),
                    )
                    self.create_host(h)

            # Read-after-write verification catches API success responses that
            # did not actually persist all requested objects.
            verify_core = self.get_core()
            verify_cfg = verify_core.get("config") or {}
            verify_in = {str(x.get("tag") or "") for x in (verify_cfg.get("inbounds") or [])}
            verify_out = {str(x.get("tag") or "") for x in (verify_cfg.get("outbounds") or [])}
            if not managed_tags.issubset(verify_in) or not managed_out.issubset(verify_out):
                raise RuntimeError("pasarguard_post_install_core_verification_failed")

            if template_host:
                verify_hosts = {
                    str(x.get("inbound_tag") or "")
                    for x in self.get_hosts()
                    if _is_ganj_pasarguard_owned_tag(str(x.get("inbound_tag") or ""))
                }
                if not managed_tags.issubset(verify_hosts):
                    raise RuntimeError("pasarguard_post_install_host_verification_failed")

            group_sync = self.sync_template_groups(
                managed_tags,
                old_template_groups,
            )
            groups_applied = bool(group_sync.get("updated_groups"))

            # Only now reload/restart the selected Core/Nodes once. Saving the
            # Core and cloning Hosts are deliberately completed first so users
            # never see a half-applied runtime.
            self.restart_core(core, config)

            # If this Core is local (its selected template port is currently
            # listening on this machine), require every generated location
            # port to become live after the restart.
            template_port = int(template.get("port") or 0)
            live_before = system_listening_ports()
            if template_port and template_port in live_before:
                expected_ports = {int(x["local_port"]) for x in created}
                deadline = time.time() + 20
                live_after: set[int] = set()
                while time.time() < deadline:
                    live_after = system_listening_ports()
                    if expected_ports.issubset(live_after):
                        break
                    time.sleep(1)
                if not expected_ports.issubset(live_after):
                    missing = sorted(expected_ports - live_after)
                    raise RuntimeError(
                        "pasarguard_runtime_ports_not_listening:" +
                        ",".join(str(x) for x in missing)
                    )

            proxy_publish = _sync_pasarguard_haproxy_ports(
                template,
                [int(x["local_port"]) for x in created],
            )

            return {
                "ok": True,
                "installed": created,
                "backup": str(BACKUP_DIR),
                "proxy_publish": proxy_publish,
                "group_sync": group_sync,
            }

        except Exception:
            # Roll back both the core document and only GANJ-owned Host
            # objects. Legacy/operator country Hosts are intentionally ignored.
            try:
                old_config = copy.deepcopy(old_core.get("config") or {})
                if groups_applied:
                    self.restore_groups(old_template_groups)
                if core_applied:
                    self.update_core(old_core, old_config)
                if template_host:
                    for h in self.get_hosts():
                        if _is_ganj_pasarguard_owned_tag(str(h.get("inbound_tag") or "")) and h.get("id"):
                            self.delete_host(int(h["id"]))
                    for old in old_managed_hosts:
                        h = copy.deepcopy(old)
                        h.pop("id", None)
                        self.create_host(h)
                if core_applied:
                    self.restart_core(old_core, old_config)
            except Exception:
                pass
            raise

    def remove_locations(self) -> dict[str, Any]:
        self.login()
        core = self.get_core()
        config = copy.deepcopy(core.get("config") or {})
        _atomic_backup("pasarguard-core-remove", core)
        inbounds = config.setdefault("inbounds", [])
        outbounds = config.setdefault("outbounds", [])
        rules = config.setdefault("routing", {}).setdefault("rules", [])
        before = len(inbounds)
        inbounds[:] = [x for x in inbounds if not _is_ganj_pasarguard_owned_tag(str(x.get("tag") or ""))]
        outbounds[:] = [x for x in outbounds if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
        rules[:] = [
            x for x in rules
            if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
            and not any(_is_ganj_pasarguard_owned_tag(str(t)) for t in (x.get("inboundTag") or []))
        ]
        self.update_core(core, config)
        removed_hosts = 0
        for h in self.get_hosts():
            if _is_ganj_pasarguard_owned_tag(str(h.get("inbound_tag") or "")) and h.get("id"):
                self.delete_host(int(h["id"]))
                removed_hosts += 1
        self.restart_core(core, config)
        try:
            _sync_pasarguard_haproxy_ports(
                {"listen": "127.0.0.1", "streamSettings": {"sockopt": {"acceptProxyProtocol": True}}},
                [],
            )
        except RuntimeError as exc:
            # Do not leave removal half-failed merely because HAProxy is not
            # used on this installation. A corrupt GANJ-managed marker still
            # surfaces as an error.
            if "marker_corrupt" in str(exc):
                raise
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
        if not self.s.verify:
            requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
            )
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

    def update_inbound(self, inbound_id: int, payload: dict[str, Any]) -> None:
        url = f"{self.base}/panel/api/inbounds/update/{int(inbound_id)}"
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
            raise RuntimeError("sanaei_update_inbound_invalid_response") from exc
        if not data.get("success"):
            raise RuntimeError("sanaei_update_inbound_failed")

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
        managed = [x for x in rows if _country_from_ganj_remark(str(x.get("remark") or ""))]
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
        if _country_from_ganj_remark(str(template.get("remark") or "")):
            raise RuntimeError("sanaei_template_must_be_dedicated_non_ganj_inbound")
        _require_vless(template)
        existing_by_country: dict[str, int] = {}
        for row in rows:
            code = _country_from_ganj_remark(str(row.get("remark") or ""))
            if code and row.get("port"):
                existing_by_country[code] = int(row["port"])
        used = {
            int(x.get("port"))
            for x in rows
            if x.get("port") and not _country_from_ganj_remark(str(x.get("remark") or ""))
        }
        assigned = _plan_stable_country_ports(locs, used, existing_by_country)
        items = []
        for loc in locs:
            local_port = assigned[loc["country_code"]]
            items.append({
                "country_code": loc["country_code"],
                "name": loc["name"],
                "gateway_port": int(loc["port"]) if loc.get("available") else None,
                "local_port": local_port,
                "template_inbound_id": self.template_inbound_id,
                "available": bool(loc.get("available")),
            })
        return {"ok": True, "type": "sanaei", "items": items}

    def status(self) -> dict[str, Any]:
        return self.managed_status()

    def install_locations(self, locations: list[dict[str, Any]]) -> dict[str, Any]:
        self.login()
        locs = _location_map(locations)
        if not locs:
            raise RuntimeError("no_locations")

        # Plan before any destructive operation. Existing GANJ country ports are
        # therefore preserved across re-syncs.
        plan = self.plan_locations(locs)
        planned_ports = {
            str(x.get("country_code")): int(x.get("local_port"))
            for x in (plan.get("items") or [])
        }

        rows_before = self.list_inbounds()
        template = next((x for x in rows_before if int(x.get("id") or 0) == self.template_inbound_id), None)
        if not template:
            raise RuntimeError("sanaei_template_inbound_not_found")

        old_xray, test_url = self.get_xray()
        old_xray = copy.deepcopy(old_xray)
        _atomic_backup("sanaei-inbounds", rows_before)
        _atomic_backup("sanaei-xray", old_xray)

        allowed = ["enable", "listen", "protocol", "settings", "streamSettings", "sniffing", "allocate"]
        existing_by_country = {}
        old_managed = []
        for row in rows_before:
            code = _country_from_ganj_remark(str(row.get("remark") or ""))
            if code:
                existing_by_country[code] = row
                old_managed.append(copy.deepcopy(row))

        desired_codes = {x["country_code"] for x in locs}
        original_ids = {int(x.get("id") or 0) for x in old_managed if x.get("id")}
        created = []

        def payload_for(loc):
            payload = {k: copy.deepcopy(template[k]) for k in allowed if k in template}
            payload["remark"] = _display_label(loc)
            payload["port"] = int(planned_ports[loc["country_code"]])
            payload["enable"] = True
            return payload

        try:
            # Update existing country inbounds in place so IDs/tags/subscription
            # references stay stable; only missing countries are created.
            for loc in locs:
                code = loc["country_code"]
                payload = payload_for(loc)
                existing = existing_by_country.get(code)
                if existing and existing.get("id"):
                    self.update_inbound(int(existing["id"]), payload)
                else:
                    self.add_inbound(payload)
                created.append({
                    "country_code": code,
                    "local_port": int(planned_ports[code]),
                    "gateway_port": int(loc["port"]) if loc.get("available") else None,
                    "available": bool(loc.get("available")),
                })

            now_rows = self.list_inbounds()
            desired_rows = {}
            for row in now_rows:
                code = _country_from_ganj_remark(str(row.get("remark") or ""))
                if code in desired_codes:
                    desired_rows[code] = row
            if len(desired_rows) != len(desired_codes):
                raise RuntimeError("sanaei_post_apply_inbound_missing")

            cfg = copy.deepcopy(old_xray)
            outbounds = cfg.setdefault("outbounds", [])
            rules = cfg.setdefault("routing", {}).setdefault("rules", [])
            outbounds[:] = [x for x in outbounds if not str(x.get("tag") or "").startswith(GANJ_OUT_PREFIX)]
            rules[:] = [
                x for x in rules
                if not str(x.get("outboundTag") or "").startswith(GANJ_OUT_PREFIX)
                and not any(_is_ganj_pasarguard_owned_tag(str(t)) for t in (x.get("inboundTag") or []))
            ]

            for item, loc in zip(created, locs):
                row = desired_rows[loc["country_code"]]
                inbound_tag = str(
                    row.get("tag")
                    or (f"inbound-{row.get('id')}" if row.get("id") else f"inbound-{item['local_port']}")
                )
                item["inbound_tag"] = inbound_tag
                out_tag = GANJ_OUT_PREFIX + loc["country_code"].lower()
                outbounds.append(_gateway_outbound(loc, out_tag))
                rules.insert(0, {"type": "field", "inboundTag": [inbound_tag], "outboundTag": out_tag})

            self.update_xray(cfg, test_url)

            # Remove countries no longer published only after routing switched.
            for row in now_rows:
                code = _country_from_ganj_remark(str(row.get("remark") or ""))
                if code and code not in desired_codes and row.get("id"):
                    self.delete_inbound(int(row["id"]))

            final_rows = self.list_inbounds()
            final_codes = {
                _country_from_ganj_remark(str(x.get("remark") or ""))
                for x in final_rows
            }
            if not desired_codes.issubset(final_codes):
                raise RuntimeError("sanaei_post_install_verification_failed")

            return {"ok": True, "installed": created, "backup": str(BACKUP_DIR)}

        except Exception:
            # Best-effort transactional rollback: remove objects created by this
            # attempt, restore previous managed inbounds in-place where possible,
            # and restore the old Xray routing document.
            try:
                current = self.list_inbounds()
                current_ids = {int(x.get("id") or 0): x for x in current if x.get("id")}
                for row in current:
                    code = _country_from_ganj_remark(str(row.get("remark") or ""))
                    iid = int(row.get("id") or 0)
                    if code and iid and iid not in original_ids:
                        self.delete_inbound(iid)

                for old in old_managed:
                    iid = int(old.get("id") or 0)
                    restore = {k: copy.deepcopy(old[k]) for k in allowed if k in old}
                    restore["remark"] = str(old.get("remark") or "")
                    restore["port"] = int(old.get("port") or 0)
                    restore["enable"] = bool(old.get("enable", True))
                    if iid and iid in current_ids:
                        self.update_inbound(iid, restore)
                    else:
                        self.add_inbound(restore)
                self.update_xray(copy.deepcopy(old_xray), test_url)
            except Exception:
                pass
            raise

    def remove_locations(self) -> dict[str, Any]:
        self.login()
        removed = 0
        for x in self.list_inbounds():
            if _country_from_ganj_remark(str(x.get("remark") or "")) and x.get("id"):
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
