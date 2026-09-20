from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Cookie, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

APP_VERSION = "0.4.0"
DB_PATH = Path(os.environ.get("GANJ_CENTRAL_DB", "/var/lib/ganj-central/central.db"))
ADMIN_TOKEN = os.environ.get("GANJ_ADMIN_TOKEN", "")
WG_INTERFACE = os.environ.get("GANJ_WG_INTERFACE", "ganj-gateway")
WG_ENDPOINT = os.environ.get("GANJ_WG_ENDPOINT", "")
WG_SERVER_PUBLIC_KEY = os.environ.get("GANJ_WG_SERVER_PUBLIC_KEY", "")
WG_ALLOWED_IPS = os.environ.get("GANJ_WG_ALLOWED_IPS", "10.60.0.0/16")
WG_MTU = int(os.environ.get("GANJ_WG_MTU", "1380"))
ONLINE_WINDOW = int(os.environ.get("GANJ_ONLINE_WINDOW_SEC", "60"))

app = FastAPI(title="GANJ Control Plane", version=APP_VERSION)


def now_ts() -> int:
    return int(time.time())


def iso_ts(value: int | None) -> str | None:
    if not value:
        return None
    return datetime.fromtimestamp(int(value), timezone.utc).isoformat()


def parse_expiry(value: str | None) -> int | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.isdigit():
        return int(raw)
    normalized = raw.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def secure_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a), str(b))


def admin_cookie_value() -> str:
    if not ADMIN_TOKEN:
        return ""
    return hmac.new(ADMIN_TOKEN.encode(), b"ganj-admin-session-v1", hashlib.sha256).hexdigest()


def admin_authenticated(cookie: str | None) -> bool:
    expected = admin_cookie_value()
    return bool(expected and cookie and secure_eq(cookie, expected))


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS representatives (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                traffic_limit_bytes INTEGER,
                traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
                speed_limit_bps INTEGER,
                max_connections INTEGER,
                starts_at INTEGER,
                expires_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id TEXT PRIMARY KEY,
                representative_id TEXT NOT NULL REFERENCES representatives(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                issued_at INTEGER NOT NULL,
                expires_at INTEGER,
                used_at INTEGER,
                node_id TEXT,
                bound_ip TEXT,
                bound_fingerprint TEXT,
                bound_wg_public_key TEXT
            );
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                representative_id TEXT NOT NULL REFERENCES representatives(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                bound_ip TEXT,
                fingerprint TEXT,
                secret_hash TEXT NOT NULL,
                wg_public_key TEXT NOT NULL,
                wg_ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'online',
                agent_version TEXT,
                panel_json TEXT,
                runtime_json TEXT,
                last_seen_at INTEGER,
                last_rx_bytes INTEGER NOT NULL DEFAULT 0,
                last_tx_bytes INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                error TEXT,
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                representative_id TEXT,
                node_id TEXT,
                kind TEXT NOT NULL,
                data_json TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_rep ON enrollment_tokens(representative_id, issued_at DESC);
            CREATE INDEX IF NOT EXISTS idx_nodes_rep ON nodes(representative_id, last_seen_at DESC);
            CREATE INDEX IF NOT EXISTS idx_commands_node ON commands(node_id, status, id);
            """
        )
        migrations = {
            "enrollment_tokens": {
                "bound_ip": "TEXT",
                "bound_fingerprint": "TEXT",
                "bound_wg_public_key": "TEXT",
            },
            "nodes": {
                "bound_ip": "TEXT",
                "fingerprint": "TEXT",
            },
        }
        for table, columns in migrations.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


@app.on_event("startup")
def _startup() -> None:
    init_db()


def add_event(conn: sqlite3.Connection, kind: str, representative_id: str | None = None, node_id: str | None = None, data: dict[str, Any] | None = None) -> None:
    conn.execute(
        "INSERT INTO events(representative_id,node_id,kind,data_json,created_at) VALUES(?,?,?,?,?)",
        (representative_id, node_id, kind, json.dumps(data or {}, ensure_ascii=False), now_ts()),
    )


def license_state(rep: sqlite3.Row | dict[str, Any]) -> tuple[bool, str]:
    status = str(rep["status"] if isinstance(rep, sqlite3.Row) else rep.get("status") or "active")
    if status != "active":
        return False, status
    now = now_ts()
    starts = rep["starts_at"] if isinstance(rep, sqlite3.Row) else rep.get("starts_at")
    expires = rep["expires_at"] if isinstance(rep, sqlite3.Row) else rep.get("expires_at")
    used = int((rep["traffic_used_bytes"] if isinstance(rep, sqlite3.Row) else rep.get("traffic_used_bytes")) or 0)
    limit = rep["traffic_limit_bytes"] if isinstance(rep, sqlite3.Row) else rep.get("traffic_limit_bytes")
    if starts and now < int(starts):
        return False, "not_started"
    if expires and now >= int(expires):
        return False, "expired"
    if limit is not None and used >= int(limit):
        return False, "quota_exceeded"
    return True, "active"


def allocate_wg_ip(conn: sqlite3.Connection) -> str:
    used = {
        str(row["wg_ip"]).split("/", 1)[0]
        for row in conn.execute("SELECT wg_ip FROM nodes").fetchall()
    }
    for host in range(10, 250):
        candidate = f"10.60.0.{host}"
        if candidate not in used:
            return candidate + "/32"
    raise HTTPException(503, "wireguard_address_pool_exhausted")


def wg_peer_apply(public_key: str, wg_ip: str, enabled: bool) -> None:
    if not shutil_which("wg"):
        return
    cmd = ["wg", "set", WG_INTERFACE, "peer", public_key]
    if enabled:
        cmd += ["allowed-ips", wg_ip]
    else:
        cmd += ["remove"]
    subprocess.run(cmd, capture_output=True, text=True, timeout=10)


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


def gateways_config() -> list[dict[str, Any]]:
    raw = os.environ.get("GANJ_GATEWAYS_JSON", "").strip()
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict) and x.get("endpoint")]
        except Exception:
            pass
    if WG_ENDPOINT:
        return [{"id": "primary", "name": "Primary", "endpoint": WG_ENDPOINT, "priority": 10}]
    return []


def locations_config() -> list[dict[str, Any]]:
    raw = os.environ.get("GANJ_LOCATIONS_JSON", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
    except Exception:
        return []


def latest_token(conn: sqlite3.Connection, representative_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM enrollment_tokens WHERE representative_id=? ORDER BY issued_at DESC LIMIT 1",
        (representative_id,),
    ).fetchone()


def token_effective_status(row: sqlite3.Row | None) -> str:
    if not row:
        return "none"
    status = str(row["status"])
    if status == "pending" and row["expires_at"] and now_ts() >= int(row["expires_at"]):
        return "expired"
    return status


def representative_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    reps = conn.execute("SELECT * FROM representatives ORDER BY created_at DESC").fetchall()
    result: list[dict[str, Any]] = []
    now = now_ts()
    for rep in reps:
        tok = latest_token(conn, str(rep["id"]))
        nodes = conn.execute(
            "SELECT * FROM nodes WHERE representative_id=? ORDER BY last_seen_at DESC",
            (rep["id"],),
        ).fetchall()
        connected = [n for n in nodes if n["last_seen_at"] and now - int(n["last_seen_at"]) <= ONLINE_WINDOW]
        active, reason = license_state(rep)
        result.append({
            **dict(rep),
            "license_active": active,
            "license_reason": reason,
            "token_status": token_effective_status(tok),
            "token_expires_at": tok["expires_at"] if tok else None,
            "token_issued_at": tok["issued_at"] if tok else None,
            "token_used_at": tok["used_at"] if tok else None,
            "panel_online": bool(connected),
            "connected_panels": len(connected),
            "panel_count": len(nodes),
        })
    return result


def issue_representative_token(
    name: str,
    traffic_limit_bytes: int | None,
    license_expires_at: int | None,
    token_expires_at: int | None,
) -> tuple[str, str]:
    raw_token = "GANJ-" + secrets.token_urlsafe(28)
    rep_id = str(uuid.uuid4())
    now = now_ts()
    with db() as conn:
        conn.execute(
            """INSERT INTO representatives
               (id,name,status,traffic_limit_bytes,traffic_used_bytes,expires_at,created_at,updated_at)
               VALUES(?,?,?,?,0,?,?,?)""",
            (rep_id, name.strip(), "active", traffic_limit_bytes, license_expires_at, now, now),
        )
        conn.execute(
            """INSERT INTO enrollment_tokens
               (id,representative_id,token_hash,status,issued_at,expires_at)
               VALUES(?,?,?,?,?,?)""",
            (str(uuid.uuid4()), rep_id, hash_secret(raw_token), "pending", now, token_expires_at),
        )
        add_event(conn, "representative_created", rep_id, data={"name": name.strip()})
    return rep_id, raw_token


def request_public_ip(request: Request) -> str:
    peer = str(request.client.host if request.client else "").strip()
    raw = peer
    try:
        peer_ip = __import__("ipaddress").ip_address(peer)
        if peer_ip.is_loopback:
            raw = str(request.headers.get("x-real-ip") or peer).strip()
    except ValueError:
        pass
    try:
        return str(__import__("ipaddress").ip_address(raw))
    except ValueError:
        raise HTTPException(400, "invalid_client_ip")


def authenticate_node(
    node_id: str | None,
    authorization: str | None,
    request: Request,
    fingerprint: str | None = None,
) -> sqlite3.Row:
    if not node_id or not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "node_auth_required")
    secret = authorization.split(" ", 1)[1].strip()
    client_ip = request_public_ip(request)
    disable_peer: tuple[str, str] | None = None
    with db() as conn:
        row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        if not row or not secure_eq(str(row["secret_hash"]), hash_secret(secret)):
            raise HTTPException(401, "invalid_node_credentials")
        if str(row["status"] or "") in {"revoked", "ip_mismatch", "identity_mismatch"}:
            raise HTTPException(403, "node_binding_locked")
        reason = None
        if row["bound_ip"] and str(row["bound_ip"]) != client_ip:
            reason = "ip_mismatch"
        elif fingerprint and row["fingerprint"] and str(row["fingerprint"]) != str(fingerprint):
            reason = "identity_mismatch"
        if reason:
            conn.execute("UPDATE nodes SET status=?,updated_at=? WHERE id=?", (reason, now_ts(), node_id))
            disable_peer = (str(row["wg_public_key"]), str(row["wg_ip"]))
        else:
            return row
    if disable_peer:
        try:
            wg_peer_apply(disable_peer[0], disable_peer[1], False)
        except Exception:
            pass
    raise HTTPException(403, "node_binding_changed_rotate_token_required")


def record_usage(conn: sqlite3.Connection, node: sqlite3.Row, wireguard: dict[str, Any]) -> int:
    try:
        rx = max(0, int(wireguard.get("rx_bytes") or 0))
        tx = max(0, int(wireguard.get("tx_bytes") or 0))
    except (TypeError, ValueError):
        return 0
    prev_rx = int(node["last_rx_bytes"] or 0)
    prev_tx = int(node["last_tx_bytes"] or 0)
    delta_rx = rx - prev_rx if rx >= prev_rx else rx
    delta_tx = tx - prev_tx if tx >= prev_tx else tx
    delta = max(0, delta_rx) + max(0, delta_tx)
    conn.execute(
        "UPDATE nodes SET last_rx_bytes=?,last_tx_bytes=?,updated_at=? WHERE id=?",
        (rx, tx, now_ts(), node["id"]),
    )
    if delta:
        conn.execute(
            "UPDATE representatives SET traffic_used_bytes=traffic_used_bytes+?,updated_at=? WHERE id=?",
            (delta, now_ts(), node["representative_id"]),
        )
    return delta


def format_bytes(value: int | None) -> str:
    if value is None:
        return "نامحدود"
    n = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def fmt_date(value: int | None) -> str:
    if not value:
        return "نامحدود"
    return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M")


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def status_badge(value: str) -> str:
    labels = {
        "active": "فعال", "pending": "در انتظار استفاده", "used": "استفاده‌شده",
        "expired": "منقضی", "revoked": "لغوشده", "quota_exceeded": "اتمام حجم",
        "not_started": "شروع‌نشده", "none": "بدون توکن",
    }
    cls = "ok" if value in {"active", "used"} else ("warn" if value in {"pending", "not_started"} else "bad")
    return f'<span class="badge {cls}">{esc(labels.get(value, value))}</span>'


def layout(title: str, body: str) -> str:
    return f"""<!doctype html><html dir="rtl" lang="fa"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#070b12;color:#e8edf5;font-family:Tahoma,Arial,sans-serif}}
a{{color:inherit;text-decoration:none}}.wrap{{max-width:1450px;margin:auto;padding:24px}}nav{{display:flex;gap:10px;align-items:center;margin-bottom:22px}}
.logo{{font-size:22px;font-weight:800;margin-left:auto}}.nav{{padding:10px 14px;border:1px solid #1e2a3b;border-radius:12px;background:#0d1420}}
.grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}}.card{{background:#0d1420;border:1px solid #1d293a;border-radius:18px;padding:18px}}
.kpi{{font-size:28px;font-weight:800;margin-top:8px}}.muted{{color:#8fa0b8;font-size:13px}}table{{width:100%;border-collapse:collapse;margin-top:16px}}
th,td{{padding:13px 10px;border-bottom:1px solid #1b2635;text-align:right;vertical-align:middle}}th{{color:#8fa0b8;font-size:12px}}
.badge{{display:inline-flex;padding:5px 9px;border-radius:999px;font-size:12px;border:1px solid}}.ok{{color:#66e3a4;border-color:#1d6a4a;background:#0c2a20}}
.warn{{color:#ffd166;border-color:#745b1f;background:#2b240e}}.bad{{color:#ff7b8b;border-color:#71303a;background:#2a1117}}
.progress{{width:150px;height:8px;background:#172131;border-radius:999px;overflow:hidden;margin-top:5px}}.progress>i{{display:block;height:100%;background:#55d69e}}
input,button{{background:#0b111a;color:#e8edf5;border:1px solid #26364c;border-radius:10px;padding:10px}}button{{cursor:pointer;background:#173c31;border-color:#24644f}}
.row{{display:flex;gap:10px;flex-wrap:wrap;align-items:end}}label{{display:flex;flex-direction:column;gap:6px;color:#9caabd;font-size:12px}}
.notice{{padding:14px;border:1px solid #2c5d4b;background:#0d241c;border-radius:12px;margin:14px 0;word-break:break-all}}
@media(max-width:900px){{.grid{{grid-template-columns:1fr 1fr}}table{{font-size:12px}}}}@media(max-width:600px){{.grid{{grid-template-columns:1fr}}.wrap{{padding:12px}}}}
</style></head><body><div class="wrap"><nav><div class="logo">GANJ Control</div>
<a class="nav" href="/admin">نمای کلی</a><a class="nav" href="/admin/representatives">نمایندگان</a>
</nav>{body}</div></body></html>"""


def require_admin(cookie: str | None) -> None:
    if not admin_authenticated(cookie):
        raise HTTPException(401, "admin_login_required")


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form() -> str:
    return layout("ورود مدیریت", '<div class="card" style="max-width:450px;margin:70px auto"><h2>ورود مدیریت</h2><form method="post"><label>توکن مدیریت<input name="token" type="password" required></label><br><button>ورود</button></form></div>')


@app.post("/admin/login")
def admin_login(token: str = Form(...)):
    if not ADMIN_TOKEN or not secure_eq(token, ADMIN_TOKEN):
        raise HTTPException(401, "invalid_admin_token")
    response = RedirectResponse("/admin", 303)
    response.set_cookie("ganj_admin", admin_cookie_value(), httponly=True, secure=True, samesite="strict", max_age=86400)
    return response


@app.get("/admin", response_class=HTMLResponse)
def admin_home(ganj_admin: str | None = Cookie(default=None)):
    if not admin_authenticated(ganj_admin):
        return RedirectResponse("/admin/login", 303)
    with db() as conn:
        rows = representative_rows(conn)
    total = len(rows)
    online = sum(1 for x in rows if x["panel_online"])
    active = sum(1 for x in rows if x["license_active"])
    used = sum(int(x["traffic_used_bytes"] or 0) for x in rows)
    body = f"""<h1>پنل اصلی</h1><div class="grid">
<div class="card"><div class="muted">نمایندگان</div><div class="kpi">{total}</div></div>
<div class="card"><div class="muted">پنل متصل</div><div class="kpi">{online}</div></div>
<div class="card"><div class="muted">اشتراک فعال</div><div class="kpi">{active}</div></div>
<div class="card"><div class="muted">مصرف کل</div><div class="kpi">{format_bytes(used)}</div></div>
</div><div class="card" style="margin-top:16px"><h3>نمایندگان اخیر</h3>{representatives_table(rows[:10])}</div>"""
    return layout("GANJ — پنل اصلی", body)


def representatives_table(rows: list[dict[str, Any]]) -> str:
    trs = []
    for x in rows:
        limit = x["traffic_limit_bytes"]
        used = int(x["traffic_used_bytes"] or 0)
        pct = 0 if not limit else min(100, int(used * 100 / max(1, int(limit))))
        panel = '<span class="badge ok">آنلاین</span>' if x["panel_online"] else '<span class="badge bad">آفلاین</span>'
        trs.append(f"""<tr>
<td><a href="/admin/representatives/{esc(x['id'])}"><b>{esc(x['name'])}</b></a><div class="muted">{x['panel_count']} پنل ثبت‌شده</div></td>
<td>{panel}</td><td>{status_badge(x['token_status'])}<div class="muted">{fmt_date(x['token_expires_at'])}</div></td>
<td>{status_badge(x['license_reason'])}<div class="muted">تا {fmt_date(x['expires_at'])}</div></td>
<td>{format_bytes(used)} / {format_bytes(limit)}<div class="progress"><i style="width:{pct}%"></i></div></td>
<td>{x['connected_panels']}</td></tr>""")
    return """<div style="overflow:auto"><table><thead><tr><th>نماینده</th><th>وضعیت پنل</th><th>توکن / انقضا</th><th>اشتراک / انقضا</th><th>مصرف / محدودیت</th><th>اتصال فعال</th></tr></thead><tbody>""" + "".join(trs) + "</tbody></table></div>"


@app.get("/admin/representatives", response_class=HTMLResponse)
def admin_representatives(ganj_admin: str | None = Cookie(default=None)):
    if not admin_authenticated(ganj_admin):
        return RedirectResponse("/admin/login", 303)
    with db() as conn:
        rows = representative_rows(conn)
    form = """<div class="card"><h3>صدور توکن برای نماینده</h3><form class="row" method="post" action="/admin/representatives/issue">
<label>نام نماینده<input name="name" required></label>
<label>محدودیت حجم (GB، خالی=نامحدود)<input name="traffic_limit_gb" type="number" min="0" step="0.1"></label>
<label>انقضای اشتراک<input name="license_expires_at" type="datetime-local"></label>
<label>اعتبار توکن ثبت‌نام (ساعت)<input name="token_ttl_hours" type="number" min="1" value="24"></label>
<button>ساخت نماینده و صدور توکن</button></form></div>"""
    return layout("نمایندگان", f"<h1>نمایندگان</h1>{form}<div class='card' style='margin-top:16px'>{representatives_table(rows)}</div>")


@app.post("/admin/representatives/issue", response_class=HTMLResponse)
def admin_issue_representative(
    name: str = Form(...),
    traffic_limit_gb: str = Form(""),
    license_expires_at: str = Form(""),
    token_ttl_hours: int = Form(24),
    ganj_admin: str | None = Cookie(default=None),
):
    require_admin(ganj_admin)
    limit = int(float(traffic_limit_gb) * (1024 ** 3)) if str(traffic_limit_gb).strip() else None
    license_exp = parse_expiry(license_expires_at) if license_expires_at else None
    token_exp = now_ts() + max(1, int(token_ttl_hours)) * 3600
    rep_id, raw = issue_representative_token(name, limit, license_exp, token_exp)
    body = f"""<h1>توکن صادر شد</h1><div class="card"><p>نماینده: <b>{esc(name)}</b></p>
<div class="notice">{esc(raw)}</div><p class="muted">این توکن فقط همین‌بار نمایش داده می‌شود و در دیتابیس به‌صورت hash ذخیره شده است.</p>
<a class="nav" href="/admin/representatives/{rep_id}">مشاهده نماینده</a></div>"""
    return layout("توکن جدید", body)


@app.get("/admin/representatives/{representative_id}", response_class=HTMLResponse)
def admin_representative_detail(representative_id: str, ganj_admin: str | None = Cookie(default=None)):
    if not admin_authenticated(ganj_admin):
        return RedirectResponse("/admin/login", 303)
    with db() as conn:
        rep = conn.execute("SELECT * FROM representatives WHERE id=?", (representative_id,)).fetchone()
        if not rep:
            raise HTTPException(404, "representative_not_found")
        tokens = conn.execute("SELECT * FROM enrollment_tokens WHERE representative_id=? ORDER BY issued_at DESC", (representative_id,)).fetchall()
        nodes = conn.execute("SELECT * FROM nodes WHERE representative_id=? ORDER BY last_seen_at DESC", (representative_id,)).fetchall()
    active, reason = license_state(rep)
    used = int(rep["traffic_used_bytes"] or 0)
    token_rows = "".join(
        f"<tr><td>{status_badge(token_effective_status(t))}</td><td>{fmt_date(t['issued_at'])}</td><td>{fmt_date(t['expires_at'])}</td><td>{fmt_date(t['used_at']) if t['used_at'] else '—'}</td></tr>"
        for t in tokens
    )
    now = now_ts()
    node_rows = "".join(
        f"<tr><td>{esc(n['name'])}</td><td>{status_badge('active' if n['last_seen_at'] and now-int(n['last_seen_at'])<=ONLINE_WINDOW else 'expired')}</td><td>{fmt_date(n['last_seen_at']) if n['last_seen_at'] else '—'}</td><td>{esc(n['agent_version'] or '—')}</td></tr>"
        for n in nodes
    )
    body = f"""<h1>{esc(rep['name'])}</h1><div class="grid">
<div class="card"><div class="muted">وضعیت اشتراک</div><div class="kpi">{status_badge(reason)}</div></div>
<div class="card"><div class="muted">مصرف‌شده</div><div class="kpi">{format_bytes(used)}</div></div>
<div class="card"><div class="muted">محدودیت حجم</div><div class="kpi">{format_bytes(rep['traffic_limit_bytes'])}</div></div>
<div class="card"><div class="muted">انقضا</div><div class="kpi" style="font-size:18px">{fmt_date(rep['expires_at'])}</div></div></div>
<div class="card" style="margin-top:16px"><h3>ویرایش سهمیه و انقضا</h3>
<form class="row" method="post" action="/admin/representatives/{esc(representative_id)}/update">
<label>محدودیت حجم (GB، -1=نامحدود)<input name="traffic_limit_gb" type="number" step="0.1" value="{(-1 if rep['traffic_limit_bytes'] is None else round(int(rep['traffic_limit_bytes'])/(1024**3),2))}"></label>
<label>انقضا (خالی=نامحدود)<input name="expires_at" type="datetime-local"></label>
<label>وضعیت<select name="status" style="background:#0b111a;color:#fff;padding:10px;border:1px solid #26364c;border-radius:10px"><option value="active">فعال</option><option value="revoked">لغوشده</option></select></label>
<button>ذخیره</button></form></div>
<div class="card" style="margin-top:16px"><h3>توکن‌ها</h3><table><tr><th>وضعیت</th><th>صدور</th><th>انقضا</th><th>استفاده</th></tr>{token_rows}</table></div>
<div class="card" style="margin-top:16px"><h3>پنل‌های متصل</h3><table><tr><th>نام</th><th>وضعیت</th><th>آخرین ارتباط</th><th>Agent</th></tr>{node_rows}</table></div>"""
    return layout(f"نماینده {rep['name']}", body)


@app.post("/admin/representatives/{representative_id}/update")
def admin_representative_update(
    representative_id: str,
    traffic_limit_gb: float = Form(-1),
    expires_at: str = Form(""),
    status: str = Form("active"),
    ganj_admin: str | None = Cookie(default=None),
):
    require_admin(ganj_admin)
    limit = None if float(traffic_limit_gb) < 0 else int(float(traffic_limit_gb) * 1024 ** 3)
    expiry = parse_expiry(expires_at) if expires_at else None
    if status not in {"active", "revoked"}:
        raise HTTPException(400, "invalid_status")
    with db() as conn:
        cur = conn.execute(
            "UPDATE representatives SET traffic_limit_bytes=?,expires_at=?,status=?,updated_at=? WHERE id=?",
            (limit, expiry, status, now_ts(), representative_id),
        )
        if cur.rowcount != 1:
            raise HTTPException(404, "representative_not_found")
        add_event(conn, "representative_updated", representative_id, data={"status": status, "traffic_limit_bytes": limit, "expires_at": expiry})
    return RedirectResponse(f"/admin/representatives/{representative_id}", 303)


@app.post("/v1/enroll")
async def enroll(request: Request):
    body = await request.json()
    raw_token = str(body.get("token") or "")
    if not raw_token:
        raise HTTPException(400, "token_required")
    token_hash = hash_secret(raw_token)
    now = now_ts()
    client_ip = request_public_ip(request)
    fingerprint = str(body.get("fingerprint") or "").strip()
    if len(fingerprint) < 32:
        raise HTTPException(400, "fingerprint_required")
    with db() as conn:
        tok = conn.execute("SELECT * FROM enrollment_tokens WHERE token_hash=?", (token_hash,)).fetchone()
        if not tok:
            raise HTTPException(401, "invalid_token")
        effective = token_effective_status(tok)
        if effective != "pending":
            raise HTTPException(401, f"token_{effective}")
        rep = conn.execute("SELECT * FROM representatives WHERE id=?", (tok["representative_id"],)).fetchone()
        if not rep:
            raise HTTPException(401, "representative_missing")
        active, reason = license_state(rep)
        if not active:
            raise HTTPException(403, reason)
        if not WG_ENDPOINT or not WG_SERVER_PUBLIC_KEY:
            raise HTTPException(503, "wireguard_gateway_not_configured")

        node_id = str(uuid.uuid4())
        node_secret_raw = secrets.token_urlsafe(36)
        wg_ip = allocate_wg_ip(conn)
        wg_public_key = str(body.get("wg_public_key") or "")
        if not wg_public_key:
            raise HTTPException(400, "wg_public_key_required")
        conn.execute(
            """INSERT INTO nodes(id,representative_id,name,bound_ip,fingerprint,secret_hash,wg_public_key,wg_ip,status,agent_version,panel_json,last_seen_at,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                node_id, rep["id"], str(body.get("node_name") or body.get("hostname") or "Representative panel"),
                client_ip, fingerprint,
                hash_secret(node_secret_raw), wg_public_key, wg_ip, "online",
                str(body.get("agent_version") or ""), json.dumps(body.get("panel") or {}, ensure_ascii=False),
                now, now, now,
            ),
        )
        conn.execute(
            """UPDATE enrollment_tokens
               SET status='used',used_at=?,node_id=?,bound_ip=?,bound_fingerprint=?,bound_wg_public_key=?
               WHERE id=?""",
            (now, node_id, client_ip, fingerprint, wg_public_key, tok["id"]),
        )
        add_event(conn, "panel_enrolled", rep["id"], node_id)
        try:
            wg_peer_apply(wg_public_key, wg_ip, True)
        except Exception as exc:
            raise HTTPException(503, f"wireguard_peer_apply_failed:{type(exc).__name__}")

    return {
        "node_id": node_id,
        "node_secret": node_secret_raw,
        "wireguard": {
            "address": wg_ip,
            "server_public_key": WG_SERVER_PUBLIC_KEY,
            "endpoint": WG_ENDPOINT,
            "allowed_ips": WG_ALLOWED_IPS,
            "persistent_keepalive": 25,
            "mtu": WG_MTU,
        },
    }


@app.post("/v1/heartbeat")
async def heartbeat(request: Request, authorization: str | None = Header(default=None), x_ganj_node_id: str | None = Header(default=None)):
    body = await request.json()
    node = authenticate_node(x_ganj_node_id, authorization, request, str(body.get("fingerprint") or "") or None)
    now = now_ts()
    with db() as conn:
        current = conn.execute("SELECT * FROM nodes WHERE id=?", (node["id"],)).fetchone()
        delta = record_usage(conn, current, body.get("wireguard") or {})
        conn.execute(
            """UPDATE nodes SET status='online',last_seen_at=?,agent_version=?,panel_json=?,runtime_json=?,updated_at=? WHERE id=?""",
            (
                now, str(body.get("agent_version") or ""),
                json.dumps(body.get("panel") or {}, ensure_ascii=False),
                json.dumps(body.get("runtime") or {}, ensure_ascii=False),
                now, node["id"],
            ),
        )
        rep = conn.execute("SELECT * FROM representatives WHERE id=?", (node["representative_id"],)).fetchone()
        active, reason = license_state(rep)
        try:
            wg_peer_apply(str(node["wg_public_key"]), str(node["wg_ip"]), active)
        except Exception:
            pass
    return {"ok": True, "usage_delta_bytes": delta, "license_active": active, "reason": reason}


@app.get("/v1/desired")
def desired(request: Request, authorization: str | None = Header(default=None), x_ganj_node_id: str | None = Header(default=None)):
    node = authenticate_node(x_ganj_node_id, authorization, request)
    with db() as conn:
        rep = conn.execute("SELECT * FROM representatives WHERE id=?", (node["representative_id"],)).fetchone()
    if not rep:
        raise HTTPException(404, "representative_missing")
    active, reason = license_state(rep)
    gateways = gateways_config()
    return {
        "revision": f"{int(rep['updated_at'])}:{int(rep['traffic_used_bytes'])}",
        "location": "automatic",
        "license": {
            "active": active,
            "reason": reason,
            "expires_at": iso_ts(rep["expires_at"]),
            "traffic_used_bytes": int(rep["traffic_used_bytes"] or 0),
            "traffic_limit_bytes": rep["traffic_limit_bytes"],
            "speed_limit_bps": rep["speed_limit_bps"],
            "max_connections": rep["max_connections"],
        },
        "gateway": {
            "mode": "best_ping",
            "candidates": gateways,
            "locations": locations_config(),
        },
    }


@app.post("/v1/report")
async def report(request: Request, authorization: str | None = Header(default=None), x_ganj_node_id: str | None = Header(default=None)):
    node = authenticate_node(x_ganj_node_id, authorization, request)
    body = await request.json()
    with db() as conn:
        add_event(conn, "agent_report", node["representative_id"], node["id"], body)
    return {"ok": True}


@app.get("/v1/commands/next")
def next_command(request: Request, authorization: str | None = Header(default=None), x_ganj_node_id: str | None = Header(default=None)):
    node = authenticate_node(x_ganj_node_id, authorization, request)
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM commands WHERE node_id=? AND status='pending' ORDER BY id LIMIT 1",
            (node["id"],),
        ).fetchone()
        if not row:
            return {"command": None}
        conn.execute("UPDATE commands SET status='running' WHERE id=?", (row["id"],))
        return {"command": {"id": row["id"], "action": row["action"], "payload": json.loads(row["payload_json"] or "{}")}}


@app.post("/v1/commands/{command_id}/result")
async def command_result(command_id: int, request: Request, authorization: str | None = Header(default=None), x_ganj_node_id: str | None = Header(default=None)):
    node = authenticate_node(x_ganj_node_id, authorization, request)
    body = await request.json()
    with db() as conn:
        row = conn.execute("SELECT * FROM commands WHERE id=? AND node_id=?", (command_id, node["id"])).fetchone()
        if not row:
            raise HTTPException(404, "command_not_found")
        conn.execute(
            "UPDATE commands SET status=?,result_json=?,error=?,completed_at=? WHERE id=?",
            ("done" if body.get("ok") else "failed", json.dumps(body.get("data") or {}, ensure_ascii=False), body.get("error"), now_ts(), command_id),
        )
    return {"ok": True}


@app.get("/health")
def health():
    return {"ok": True, "version": APP_VERSION}
