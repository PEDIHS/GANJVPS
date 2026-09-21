#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, AsyncIterator

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

import ganj_vps
from panel_sync import adapter_from_profile

APP_VERSION = "0.1.0"
BIND_HOST = os.environ.get("GANJ_WEB_BIND", "127.0.0.1")
BIND_PORT = int(os.environ.get("GANJ_WEB_PORT", "9877"))

ETC_DIR = Path("/etc/ganj-vps")
STATE_DIR = Path("/var/lib/ganj-vps")
LOG_DIR = Path("/var/log/ganj-vps")
AUTH_FILE = ETC_DIR / "web-auth.json"
AUDIT_FILE = LOG_DIR / "web-audit.jsonl"
INDEX_FILE = Path(__file__).resolve().parent / "web" / "index.html"

SESSION_COOKIE = "ganj_session"
SESSION_TTL = 12 * 60 * 60
LOGIN_WINDOW = 10 * 60
LOGIN_MAX_FAILURES = 8
ACTION_LOCK = threading.RLock()

PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

_sessions: dict[str, dict[str, Any]] = {}
_login_failures: dict[str, deque[float]] = defaultdict(deque)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=512)


class ActionBody(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    target: str | None = Field(default=None, max_length=256)
    name: str | None = Field(default=None, max_length=128)
    endpoint: str | None = Field(default=None, max_length=256)
    confirm: str | None = Field(default=None, max_length=128)


class WebUserBody(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=10, max_length=512)


app = FastAPI(
    title="GANJ Representative Panel",
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _now() -> int:
    return int(time.time())


def _json_load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _json_write(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def configure_web_user(username: str, password: str) -> None:
    username = str(username or "").strip()
    if len(username) < 3:
        raise ValueError("username_too_short")
    if len(password) < 10:
        raise ValueError("password_too_short")
    _json_write(
        AUTH_FILE,
        {
            "username": username,
            "password_hash": PASSWORD_HASHER.hash(password),
            "created_at": _now(),
            "updated_at": _now(),
        },
        0o600,
    )


def _auth_config() -> dict[str, Any]:
    return _json_load(AUTH_FILE, {})


def _client_ip(request: Request) -> str:
    peer = str(request.client.host if request.client else "")
    if peer in {"127.0.0.1", "::1"}:
        forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()[:128]
    return peer[:128]


def _clean_sessions() -> None:
    cutoff = _now() - SESSION_TTL
    for token, session in list(_sessions.items()):
        if int(session.get("last_seen") or 0) < cutoff:
            _sessions.pop(token, None)


def _session_from_request(request: Request) -> tuple[str, dict[str, Any]]:
    _clean_sessions()
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        raise HTTPException(status_code=401, detail="authentication_required")
    session = _sessions.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="session_expired")
    session["last_seen"] = _now()
    return token, session


def _require_session(request: Request) -> dict[str, Any]:
    return _session_from_request(request)[1]


def _require_csrf(request: Request) -> dict[str, Any]:
    _, session = _session_from_request(request)
    supplied = request.headers.get("x-csrf-token", "")
    expected = str(session.get("csrf") or "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="csrf_failed")
    return session


def _audit(request: Request, event: str, ok: bool, details: dict[str, Any] | None = None) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": _now(),
        "event": event,
        "ok": bool(ok),
        "ip": _client_ip(request),
        "details": details or {},
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    try:
        os.chmod(AUDIT_FILE, 0o600)
    except Exception:
        pass


def _login_limited(ip: str) -> bool:
    q = _login_failures[ip]
    now = time.time()
    while q and now - q[0] > LOGIN_WINDOW:
        q.popleft()
    return len(q) >= LOGIN_MAX_FAILURES


def _record_login_failure(ip: str) -> None:
    _login_failures[ip].append(time.time())


def _service_state(name: str) -> str:
    try:
        p = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=4,
        )
        return p.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _proc_mem() -> dict[str, int]:
    rows: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" not in line:
                continue
            key, raw = line.split(":", 1)
            value = int(raw.strip().split()[0]) * 1024
            rows[key] = value
    except Exception:
        pass
    total = rows.get("MemTotal", 0)
    available = rows.get("MemAvailable", 0)
    return {
        "total": total,
        "used": max(0, total - available),
        "available": available,
    }


def _cpu_usage() -> float:
    def sample() -> tuple[int, int]:
        values = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return sum(values), idle

    try:
        total1, idle1 = sample()
        time.sleep(0.08)
        total2, idle2 = sample()
        dt = max(1, total2 - total1)
        return round(100.0 * (1.0 - ((idle2 - idle1) / dt)), 1)
    except Exception:
        return 0.0


def _system_metrics() -> dict[str, Any]:
    memory = _proc_mem()
    disk = shutil.disk_usage("/")
    uptime = 0
    try:
        uptime = int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        pass
    return {
        "cpu_percent": _cpu_usage(),
        "load": [round(float(x), 2) for x in os.getloadavg()],
        "memory": memory,
        "disk": {
            "total": int(disk.total),
            "used": int(disk.used),
            "free": int(disk.free),
        },
        "uptime_seconds": uptime,
    }


def _license_usage(desired: dict[str, Any]) -> dict[str, Any]:
    license_info = desired.get("license") if isinstance(desired, dict) else {}
    license_info = license_info if isinstance(license_info, dict) else {}
    used = int(license_info.get("traffic_used_bytes") or 0)
    limit = int(license_info.get("traffic_limit_bytes") or 0)
    percent = round((used / limit) * 100, 2) if limit > 0 else 0.0
    return {
        "active": bool(license_info.get("active")),
        "reason": license_info.get("reason"),
        "expires_at": license_info.get("expires_at"),
        "used_bytes": used,
        "limit_bytes": limit,
        "percent": min(100.0, percent),
    }


def _safe_panel_snapshot() -> dict[str, Any]:
    if not ganj_vps.PANEL_SECRET_FILE.exists():
        return {"configured": False, "status": {}, "profile": {}}
    profile = ganj_vps.panel_profile()
    safe_profile = {
        k: v for k, v in profile.items()
        if k not in {"password", "token", "secret"}
    }
    try:
        adapter = adapter_from_profile(profile)
        status = adapter.status()
        discovery = adapter.discover()
        return {
            "configured": True,
            "status": status,
            "profile": safe_profile,
            "inbounds": discovery.get("inbounds") or [],
            "hosts": discovery.get("hosts") or [],
        }
    except Exception as exc:
        return {
            "configured": True,
            "status": {"ok": False, "error": type(exc).__name__},
            "profile": safe_profile,
            "inbounds": [],
            "hosts": [],
        }


def _dashboard_payload() -> dict[str, Any]:
    snap = ganj_vps._status_snapshot(include_locations=True)
    desired = snap.get("desired") or {}
    transfer = ganj_vps._wg_transfer_bytes()
    wg = dict(snap.get("wireguard") or {})
    if transfer is not None:
        wg["rx_bytes"], wg["tx_bytes"] = transfer
    return {
        "ts": _now(),
        "version": ganj_vps.APP_VERSION,
        "web_version": APP_VERSION,
        "node_id": snap.get("node_id"),
        "hostname": os.uname().nodename,
        "system": _system_metrics(),
        "license": _license_usage(desired),
        "runtime": snap.get("runtime") or {},
        "wireguard": wg,
        "gateway": snap.get("gateway") or {},
        "gateway_reachable": bool(snap.get("gateway_reachable")),
        "gateway_latency_ms": snap.get("gateway_latency_ms"),
        "locations": snap.get("locations_runtime") or [],
        "last_sync": snap.get("last_sync"),
        "last_error": snap.get("last_error"),
        "services": {
            "agent": _service_state("ganj-vps-agent.service"),
            "web": _service_state("ganj-vps-web.service"),
            "haproxy": _service_state("haproxy.service"),
        },
    }


def _gateway_payload() -> dict[str, Any]:
    rows = ganj_vps.rank_gateways()
    current = ganj_vps._current_wireguard_endpoint()
    return {"current": current, "items": rows}


def _capture(fn, *args, **kwargs) -> tuple[Any, str]:
    import contextlib
    import io

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


def _run_action(action: str, body: ActionBody) -> dict[str, Any]:
    with ACTION_LOCK:
        if action == "sync":
            return {"result": ganj_vps.sync_once()}
        if action == "reconcile":
            state = ganj_vps.load_json(ganj_vps.STATE_FILE, {})
            desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
            return {"result": ganj_vps.reconcile_desired(desired, force=True)}
        if action == "locations_install":
            _, output = _capture(ganj_vps.locations_install, True)
            return {"output": output}
        if action == "locations_remove":
            if body.confirm != "REMOVE":
                raise HTTPException(status_code=400, detail="confirmation_required")
            _, output = _capture(ganj_vps.locations_remove, True)
            return {"output": output}
        if action == "gateway_switch":
            if not body.target:
                raise HTTPException(status_code=400, detail="target_required")
            _, output = _capture(ganj_vps.gateway_switch, body.target)
            return {"output": output}
        if action == "gateway_add":
            if not body.endpoint:
                raise HTTPException(status_code=400, detail="endpoint_required")
            _, output = _capture(ganj_vps.gateway_add, body.endpoint, body.name or "")
            return {"output": output}
        if action == "gateway_remove":
            if not body.target:
                raise HTTPException(status_code=400, detail="target_required")
            _, output = _capture(ganj_vps.gateway_remove, body.target)
            return {"output": output}
        if action == "health_refresh":
            state = ganj_vps.load_json(ganj_vps.STATE_FILE, {})
            desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
            return {"result": ganj_vps.refresh_location_health_cache(desired)}
        if action == "restart_agent":
            subprocess.run(["systemctl", "restart", "ganj-vps-agent.service"], check=True, timeout=20)
            return {"ok": True}
        if action == "restart_haproxy":
            subprocess.run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"], check=True, timeout=15)
            subprocess.run(["systemctl", "reload", "haproxy.service"], check=True, timeout=20)
            return {"ok": True}
        if action == "update":
            subprocess.Popen(
                ["/usr/local/bin/ganj-vps", "update"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"accepted": True}
        if action == "uninstall":
            if body.confirm != "UNINSTALL":
                raise HTTPException(status_code=400, detail="confirmation_required")
            subprocess.Popen(
                ["/usr/local/bin/ganj-vps", "uninstall"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {"accepted": True}
        raise HTTPException(status_code=400, detail="unsupported_action")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index() -> Response:
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=503, detail="web_assets_missing")
    return FileResponse(INDEX_FILE)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "version": APP_VERSION, "auth_configured": AUTH_FILE.exists()}


@app.post("/api/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    cfg = _auth_config()
    if not cfg.get("username") or not cfg.get("password_hash"):
        raise HTTPException(status_code=503, detail="web_login_not_configured")
    ip = _client_ip(request)
    if _login_limited(ip):
        _audit(request, "login_rate_limited", False)
        raise HTTPException(status_code=429, detail="too_many_attempts")

    username_ok = hmac.compare_digest(
        str(body.username),
        str(cfg.get("username") or ""),
    )
    password_ok = False
    if username_ok:
        try:
            password_ok = PASSWORD_HASHER.verify(
                str(cfg["password_hash"]),
                body.password,
            )
        except VerifyMismatchError:
            password_ok = False
        except Exception:
            password_ok = False

    if not username_ok or not password_ok:
        _record_login_failure(ip)
        _audit(request, "login_failed", False)
        raise HTTPException(status_code=401, detail="invalid_credentials")

    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    _sessions[token] = {
        "username": str(cfg["username"]),
        "csrf": csrf,
        "created_at": _now(),
        "last_seen": _now(),
    }
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )
    _audit(request, "login_success", True)
    return {"ok": True, "username": cfg["username"], "csrf": csrf}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict[str, Any]:
    token, _ = _session_from_request(request)
    _sessions.pop(token, None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    _audit(request, "logout", True)
    return {"ok": True}


@app.get("/api/session")
def session(request: Request) -> dict[str, Any]:
    session = _require_session(request)
    return {
        "authenticated": True,
        "username": session.get("username"),
        "csrf": session.get("csrf"),
        "expires_in": SESSION_TTL,
    }


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    _require_session(request)
    return _dashboard_payload()


@app.get("/api/locations")
def locations(request: Request) -> dict[str, Any]:
    _require_session(request)
    state = ganj_vps.load_json(ganj_vps.STATE_FILE, {})
    desired = state.get("desired") if isinstance(state.get("desired"), dict) else {}
    return {
        "items": ganj_vps.location_runtime_rows(desired),
        "catalog_size": len(ganj_vps.TOP_LOCATIONS),
        "health": _json_load(ganj_vps.LOCATION_HEALTH_FILE, {}),
    }


@app.get("/api/panel")
def panel(request: Request) -> dict[str, Any]:
    _require_session(request)
    return _safe_panel_snapshot()


@app.get("/api/gateways")
def gateways(request: Request) -> dict[str, Any]:
    _require_session(request)
    return _gateway_payload()


@app.get("/api/diagnostics")
def diagnostics(request: Request) -> dict[str, Any]:
    _require_session(request)
    snap = _dashboard_payload()
    panel = _safe_panel_snapshot()
    checks = {
        "agent": snap["services"]["agent"] == "active",
        "web": snap["services"]["web"] == "active",
        "wireguard": bool((snap.get("wireguard") or {}).get("up")),
        "gateway": bool(snap.get("gateway_reachable")),
        "panel": bool((panel.get("status") or {}).get("ok")),
        "locations_managed": int((panel.get("status") or {}).get("managed_inbounds") or 0),
        "haproxy": snap["services"]["haproxy"] == "active",
    }
    return {"checks": checks, "dashboard": snap, "panel": panel}


@app.get("/api/logs")
def logs(request: Request, lines: int = 100) -> dict[str, Any]:
    _require_session(request)
    lines = max(20, min(300, int(lines)))
    p = subprocess.run(
        ["journalctl", "-u", "ganj-vps-agent.service", "-n", str(lines), "--no-pager", "-o", "short-iso"],
        capture_output=True,
        text=True,
        timeout=8,
    )
    return {"lines": (p.stdout or "")[-50000:]}


@app.post("/api/action")
def action(body: ActionBody, request: Request) -> dict[str, Any]:
    session = _require_csrf(request)
    started = time.monotonic()
    try:
        result = _run_action(body.action, body)
        _audit(
            request,
            "action",
            True,
            {
                "action": body.action,
                "target": body.target,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "user": session.get("username"),
            },
        )
        return {"ok": True, **result}
    except HTTPException:
        raise
    except Exception as exc:
        _audit(
            request,
            "action",
            False,
            {
                "action": body.action,
                "target": body.target,
                "error": type(exc).__name__,
            },
        )
        raise HTTPException(
            status_code=500,
            detail=f"{type(exc).__name__}:{str(exc)[:220]}",
        ) from exc


@app.get("/api/events")
async def events(request: Request) -> StreamingResponse:
    _require_session(request)

    async def stream() -> AsyncIterator[str]:
        while True:
            if await request.is_disconnected():
                return
            try:
                payload = _dashboard_payload()
                yield "event: status\ndata: " + json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ) + "\n\n"
            except Exception as exc:
                yield "event: error\ndata: " + json.dumps(
                    {"error": type(exc).__name__},
                    separators=(",", ":"),
                ) + "\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "web_panel:app",
        host=BIND_HOST,
        port=BIND_PORT,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1,::1",
    )
