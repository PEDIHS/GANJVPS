"""Telegram WebApp validation, signed session, admin RBAC."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
from urllib.parse import parse_qsl
from fastapi import HTTPException, Request, Depends
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.orm import Session
from app.config import config
from app.db import get_db
from app.services import require_permission


def validate_webapp_init_data(raw: str, *, token: str, now: int | None = None) -> dict:
    if not token:
        raise HTTPException(503, "توکن جدید تلگرام هنوز تنظیم نشده است")
    if not raw or len(raw) > 10000:
        raise HTTPException(401, "امضای تلگرام وجود ندارد")
    items = dict(parse_qsl(raw, keep_blank_values=True))
    received = items.pop("hash", "")
    if not received or not items.get("auth_date"):
        raise HTTPException(401, "امضای تلگرام ناقص است")
    try:
        authenticated_at = int(items["auth_date"])
        reference = int(now if now is not None else time.time())
    except ValueError:
        raise HTTPException(401, "زمان ورود نامعتبر است")
    if not 0 <= reference - authenticated_at <= 300:
        raise HTTPException(401, "زمان احراز هویت به پایان رسیده")
    canonical = "\n".join(f"{key}={value}" for key, value in sorted(items.items()))
    secret = hmac.new(b"WebAppData", token.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, canonical.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received, expected):
        raise HTTPException(401, "امضای تلگرام معتبر نیست")
    try:
        user = json.loads(items.get("user", "{}"))
        if int(user["id"]) <= 0:
            raise ValueError()
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        raise HTTPException(401, "هویت کاربر نامعتبر است")
    return user


def serializer() -> URLSafeTimedSerializer:
    if len(config.session_secret) < 32 or config.session_secret.startswith("REPLACE_"):
        raise HTTPException(503, "SESSION_SECRET امن تنظیم نشده است")
    return URLSafeTimedSerializer(config.session_secret, salt="ganj-vps-marketplace-v1")


def make_session(user_id: int) -> str:
    return serializer().dumps({"id": user_id})


def valid_admin_key(request: Request) -> bool:
    supplied = request.headers.get("x-admin-key", "")
    expected = os.getenv("ADMIN_API_KEY", "")
    return bool(expected and len(expected) >= 32 and supplied and hmac.compare_digest(supplied, expected))


def get_actor(request: Request) -> int:
    # Automation-only admin bootstrap. A real key is never sent to browser clients.
    if valid_admin_key(request):
        return config.owner_id
    token = request.cookies.get("ganj_session", "")
    if not token:
        raise HTTPException(401, "ابتدا با تلگرام وارد شوید")
    try:
        data = serializer().loads(token, max_age=86400)
        actor = int(data["id"])
        if actor <= 0:
            raise ValueError()
        return actor
    except (BadSignature, SignatureExpired, ValueError, KeyError, TypeError):
        raise HTTPException(401, "نشست نامعتبر یا منقضی شده است")


def csrf_guard(request: Request, actor: int = Depends(get_actor)) -> int:
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not valid_admin_key(request):
        expected = hmac.new(config.session_secret.encode(),
                            f"csrf:{actor}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), expected):
            raise HTTPException(403, "توکن امنیتی درخواست نامعتبر است")
    return actor


def csrf_token(actor: int) -> str:
    return hmac.new(config.session_secret.encode(), f"csrf:{actor}".encode(), hashlib.sha256).hexdigest()


def permission_for(feature: str):
    def check(actor: int = Depends(csrf_guard), db: Session = Depends(get_db)):
        require_permission(db, actor, feature)
        return actor
    return check
