from __future__ import annotations
import ipaddress
from pathlib import Path
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from app.config import config
from app.db import init_db, get_db, SessionLocal
from app.auth import validate_webapp_init_data, make_session, get_actor, csrf_guard, csrf_token, permission_for
from app.services import (create_host, create_plan, purchase, get_balance, adjust_wallet,
                         available_slots, owner_ids, request_operation, vote, audit, user_get_or_create)
from app.models import Host, Slot, Plan, Order, Subscription, Operation, Ticket, ProvisionJob, utcnow

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield

app = FastAPI(title="GANJ VPS Marketplace", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)

@app.middleware("http")
async def harden_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/healthz")
def health():
    return {"status": "ok", "service": "ganj-vps-marketplace"}

@app.get("/")
def home():
    return FileResponse(Path(__file__).resolve().parent.parent / "static" / "index.html")

class TelegramLogin(BaseModel):
    init_data: str

@app.post("/api/v1/auth/telegram")
def telegram_login(body: TelegramLogin, response: Response, db: Session = Depends(get_db)):
    data = validate_webapp_init_data(body.init_data, token=config.telegram_bot_token)
    user = user_get_or_create(db, int(data["id"]), data.get("first_name", ""))
    user.username = str(data.get("username", ""))[:128] or None
    db.commit()
    response.set_cookie("ganj_session", make_session(user.id), httponly=True, secure=config.cookie_secure,
                        samesite="strict", max_age=86400, path="/")
    return {"ok": True, "user_id": user.id}

@app.post("/api/v1/auth/logout")
def logout(response: Response, actor: int = Depends(csrf_guard)):
    response.delete_cookie("ganj_session", path="/")
    return {"ok": True}

@app.get("/api/v1/me")
def me(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    return {"id": actor, "balance_toman": get_balance(db, actor),
            "is_owner": actor == config.owner_id, "csrf": csrf_token(actor)}

@app.get("/api/v1/catalog")
def catalog(db: Session = Depends(get_db)):
    plans = db.scalars(select(Plan).where(Plan.enabled == True).order_by(Plan.price_toman)).all()
    return [{"id": p.id, "name": p.name, "region": p.region, "capacity": p.capacity,
             "price_toman": p.price_toman, "term_days": p.term_days,
             "available": len(available_slots(db, p))} for p in plans]

@app.get("/api/v1/subscriptions")
def subscriptions(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    rows = db.scalars(select(Subscription).where(Subscription.user_id == actor)).all()
    return [{"id": s.id, "status": s.status, "runtime": s.runtime_type,
             "ends_at": s.ends_at.isoformat(), "slot_id": s.slot_id,
             "ip": s.public_ip, "api_port": s.api_port} for s in rows]

class PurchaseRequest(BaseModel):
    plan_id: str
    runtime: str
    idempotency_key: str = Field(min_length=8, max_length=150)


def begin_write(db: Session):
    if db.bind.dialect.name == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")

@app.post("/api/v1/orders")
def buy(body: PurchaseRequest, actor: int = Depends(csrf_guard)):
    with SessionLocal() as db:
        try:
            begin_write(db)
            order, fresh = purchase(db, actor, body.plan_id, body.runtime.lower(), body.idempotency_key)
            answer = {"id": order.id, "status": order.status, "amount_toman": order.amount_toman,
                      "provisioning_status": "awaiting_connector", "replayed": not fresh}
            db.commit()
            return answer
        except Exception:
            db.rollback()
            raise

@app.get("/api/v1/orders/{order_id}")
def get_order(order_id: str, actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    order = db.get(Order, order_id)
    if not order or (order.user_id != actor and actor != config.owner_id):
        raise HTTPException(404, "سفارش پیدا نشد")
    job = db.scalar(select(ProvisionJob).where(ProvisionJob.order_id == order.id))
    return {"id": order.id, "status": order.status, "amount_toman": order.amount_toman,
            "provisioning_status": job.state if job else None}

class HostCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    region: str = Field(min_length=2, max_length=100)
    ip: str
    capacity: int
    cpu: int = 2
    ram_mb: int = 2048
    reserved_ram_mb: int = 256
    monthly_cost: int = 0
    provider: str = "manual"

@app.post("/api/v1/admin/hosts")
def add_host(body: HostCreate, actor: int = Depends(permission_for("servers.manage"))):
    with SessionLocal() as db:
        try:
            begin_write(db)
            host = create_host(db, actor, **body.model_dump())
            result = {"id": host.id, "name": host.name, "slots": host.capacity}
            db.commit()
            return result
        except Exception:
            db.rollback()
            raise

@app.get("/api/v1/admin/hosts")
def list_hosts(actor: int = Depends(permission_for("servers.manage")), db: Session = Depends(get_db)):
    hosts = db.scalars(select(Host).order_by(Host.created_at.desc())).all()
    return [{"id": h.id, "name": h.name, "region": h.region, "ip": h.ip,
             "capacity": h.capacity, "reserved_ram_mb": h.reserved_ram_mb,
             "occupied": db.scalar(select(func.count()).select_from(Slot).where(
                 Slot.host_id == h.id, Slot.status != "available")) or 0,
             "monthly_cost": h.monthly_cost} for h in hosts]

class PlanCreate(BaseModel):
    name: str
    region: str
    capacity: int
    price_toman: int
    term_days: int = 30

@app.post("/api/v1/admin/plans")
def add_plan(body: PlanCreate, actor: int = Depends(permission_for("plans.manage"))):
    with SessionLocal() as db:
        try:
            begin_write(db)
            p = create_plan(db, actor, **body.model_dump())
            result = {"id": p.id, "name": p.name}
            db.commit()
            return result
        except Exception:
            db.rollback()
            raise

class WalletAdjustment(BaseModel):
    user_id: int
    amount_toman: int
    reason: str
    reference: str

@app.post("/api/v1/admin/wallet-adjustments")
def wallet_adjust(body: WalletAdjustment, actor: int = Depends(permission_for("wallet.adjust"))):
    with SessionLocal() as db:
        try:
            begin_write(db)
            item = adjust_wallet(db, actor, body.user_id, body.amount_toman,
                                 body.reason, body.reference)
            balance = get_balance(db, body.user_id)
            db.commit()
            return {"id": item.id, "balance_toman": balance}
        except Exception:
            db.rollback()
            raise

class OperationRequest(BaseModel):
    host_id: str
    action: str
    reason: str

@app.post("/api/v1/operations")
def propose(body: OperationRequest, actor: int = Depends(csrf_guard)):
    with SessionLocal() as db:
        try:
            begin_write(db)
            op = request_operation(db, actor, body.host_id, body.action, body.reason)
            result = {"id": op.id, "status": op.status, "owners": len(op.owners_snapshot),
                      "execution": "disabled_until_provider_adapter_verified"}
            db.commit()
            return result
        except Exception:
            db.rollback()
            raise

class VoteRequest(BaseModel):
    choice: str
    reason: str = ""

@app.post("/api/v1/operations/{operation_id}/votes")
def cast_vote(operation_id: str, body: VoteRequest, actor: int = Depends(csrf_guard)):
    with SessionLocal() as db:
        try:
            begin_write(db)
            op = vote(db, actor, operation_id, body.choice, body.reason)
            status = op.status
            db.commit()
            return {"id": op.id, "status": status, "executed": False}
        except Exception:
            db.rollback()
            raise

@app.get("/api/v1/operations")
def my_operations(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    ops = db.scalars(select(Operation).order_by(Operation.created_at.desc()).limit(200)).all()
    return [{"id": op.id, "action": op.action, "status": op.status, "reason": op.reason,
             "expires_at": op.expires_at.isoformat(), "host_id": op.host_id,
             "eligible_to_vote": actor in op.owners_snapshot and actor != op.requester_id}
            for op in ops if actor in op.owners_snapshot]

class TicketCreate(BaseModel):
    subject: str = Field(min_length=4, max_length=200)
    message: str = Field(min_length=10, max_length=4000)

@app.post("/api/v1/tickets")
def create_ticket(body: TicketCreate, actor: int = Depends(csrf_guard), db: Session = Depends(get_db)):
    ticket = Ticket(user_id=actor, subject=body.subject, message=body.message)
    db.add(ticket)
    db.commit()
    return {"id": ticket.id, "status": ticket.status}

@app.get("/api/v1/tickets")
def get_tickets(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    rows = db.scalars(select(Ticket).where(Ticket.user_id == actor).order_by(Ticket.created_at.desc())).all()
    return [{"id": t.id, "subject": t.subject, "status": t.status} for t in rows]

@app.get("/api/v1/admin/summary")
def dashboard(actor: int = Depends(permission_for("reports.read")), db: Session = Depends(get_db)):
    return {"hosts": db.scalar(select(func.count()).select_from(Host)),
            "users": db.scalar(select(func.count()).select_from(__import__('app.models', fromlist=['User']).User)),
            "orders": db.scalar(select(func.count()).select_from(Order)),
            "subscriptions": db.scalar(select(func.count()).select_from(Subscription)),
            "pending_ops": db.scalar(select(func.count()).select_from(Operation).where(Operation.status == "pending_approval")),
            "execution_enabled": False}

from app.telegram import process_webhook
app.post("/telegram/webhook")(process_webhook)
