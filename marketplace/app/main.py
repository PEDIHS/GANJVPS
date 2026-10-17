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
from app.models import Host, Slot, Plan, Order, Subscription, Operation, Ticket, ProvisionJob, WalletEntry, User, Audit, TicketMessage, TelegramOutbox, utcnow

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

@app.get("/api/v1/admin/plans")
def admin_list_plans(actor: int = Depends(permission_for("plans.manage")), db: Session = Depends(get_db)):
    plans = db.scalars(select(Plan).order_by(Plan.name, Plan.id)).all()
    return [{"id": p.id, "name": p.name, "region": p.region, "capacity": p.capacity,
             "price_toman": p.price_toman, "term_days": p.term_days,
             "enabled": p.enabled, "available": len(available_slots(db, p))} for p in plans]


class PlanEdit(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=180)
    price_toman: int | None = Field(default=None, gt=0)
    term_days: int | None = Field(default=None, ge=1, le=365)
    enabled: bool | None = None


@app.patch("/api/v1/admin/plans/{plan_id}")
def admin_edit_plan(plan_id: str, body: PlanEdit,
                    actor: int = Depends(permission_for("plans.manage"))):
    values = body.model_dump(exclude_unset=True)
    if not values or any(value is None for value in values.values()):
        raise HTTPException(422, "فیلدهای ویرایش نامعتبرند")
    with SessionLocal() as db:
        plan = db.scalar(select(Plan).where(Plan.id == plan_id).with_for_update())
        if not plan:
            raise HTTPException(404, "پلن پیدا نشد")
        for key, value in values.items():
            setattr(plan, key, value)
        audit(db, actor, "plan.updated", plan.id, fields=sorted(values.keys()))
        db.commit()
        return {"ok": True, "id": plan.id, "enabled": plan.enabled}


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
    db.flush()
    db.add(TelegramOutbox(payload={"chat_id": config.owner_id,
        "text": "تیکت جدید در گنج VPS ثبت شد. شناسه: " + ticket.id[:12], "parse_mode": "HTML"}))
    db.commit()
    return {"id": ticket.id, "status": ticket.status}

@app.get("/api/v1/tickets")
def get_tickets(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    rows = db.scalars(select(Ticket).where(Ticket.user_id == actor).order_by(Ticket.created_at.desc())).all()
    return [{"id": t.id, "subject": t.subject, "status": t.status} for t in rows]


@app.get("/api/v1/wallet/transactions")
def wallet_transactions(actor: int = Depends(get_actor), db: Session = Depends(get_db)):
    rows = db.scalars(select(WalletEntry).where(WalletEntry.user_id == actor)
                      .order_by(WalletEntry.created_at.desc()).limit(100)).all()
    return [{"id": w.id, "delta_toman": w.delta_toman, "reason": w.reason,
             "created_at": w.created_at.isoformat()} for w in rows]

@app.get("/api/v1/admin/orders")
def admin_orders(actor: int = Depends(permission_for("orders.read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Order).order_by(Order.created_at.desc()).limit(100)).all()
    return [{"id": o.id, "user_id": o.user_id, "amount_toman": o.amount_toman,
             "status": o.status, "created_at": o.created_at.isoformat(),
             "plan_id": o.plan_id, "slot_id": o.slot_id} for o in rows]

@app.get("/api/v1/admin/users")
def admin_users(actor: int = Depends(permission_for("users.read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(User).order_by(User.created_at.desc()).limit(100)).all()
    return [{"id": u.id, "display_name": u.display_name, "username": u.username,
             "active": u.active, "created_at": u.created_at.isoformat(),
             "balance_toman": get_balance(db, u.id)} for u in rows]

@app.get("/api/v1/admin/tickets")
def admin_tickets(actor: int = Depends(permission_for("tickets.read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Ticket).order_by(Ticket.created_at.desc()).limit(100)).all()
    return [{"id": t.id, "user_id": t.user_id, "subject": t.subject,
             "message": t.message, "status": t.status, "department": t.department,
             "created_at": t.created_at.isoformat()} for t in rows]

@app.get("/api/v1/admin/finance")
def admin_finance(actor: int = Depends(permission_for("reports.read")), db: Session = Depends(get_db)):
    costs = int(db.scalar(select(func.coalesce(func.sum(Host.monthly_cost), 0))) or 0)
    receipts = int(db.scalar(select(func.coalesce(func.sum(Order.amount_toman), 0))
                             .where(Order.status == "paid")) or 0)
    balance = int(db.scalar(select(func.coalesce(func.sum(WalletEntry.delta_toman), 0))) or 0)
    by_host = []
    for host in db.scalars(select(Host).order_by(Host.created_at.desc()).limit(100)).all():
        occupied = int(db.scalar(select(func.count()).select_from(Slot).where(
            Slot.host_id == host.id, Slot.status != "available")) or 0)
        by_host.append({"id": host.id, "name": host.name, "monthly_cost": host.monthly_cost,
                        "capacity": host.capacity, "occupied": occupied})
    return {"paid_order_total_toman": receipts, "monthly_host_cost_toman": costs,
            "total_wallet_liability_toman": balance, "hosts": by_host,
            "note": "دریافتی سفارش‌ها، هزینه ماهانه میزبان و مانده کیف‌پول شاخص‌های جداگانه هستند؛ سود خالص حسابداری محسوب نمی‌شوند."}

@app.get("/api/v1/admin/audit")
def admin_audit(actor: int = Depends(permission_for("reports.read")), db: Session = Depends(get_db)):
    rows = db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(80)).all()
    return [{"event": a.event, "actor_id": a.actor_id, "entity_id": a.entity_id,
             "created_at": a.created_at.isoformat()} for a in rows]

def ticket_message_view(row: TicketMessage):
    return {"id": row.id, "body": row.body, "author_id": row.author_id,
            "is_staff": row.is_staff, "created_at": row.created_at.isoformat()}


def ticket_view(db: Session, ticket: Ticket):
    messages = db.scalars(select(TicketMessage).where(TicketMessage.ticket_id == ticket.id)
                          .order_by(TicketMessage.created_at, TicketMessage.id)).all()
    return {"id": ticket.id, "user_id": ticket.user_id, "subject": ticket.subject,
            "message": ticket.message, "status": ticket.status,
            "created_at": ticket.created_at.isoformat(),
            "messages": [ticket_message_view(m) for m in messages]}


@app.get("/api/v1/tickets/{ticket_id}")
def get_ticket_thread(ticket_id: str, actor: int = Depends(get_actor),
                      db: Session = Depends(get_db)):
    ticket = db.get(Ticket, ticket_id)
    if not ticket:
        raise HTTPException(404, "تیکت پیدا نشد")
    if actor != ticket.user_id:
        from app.services import require_permission
        require_permission(db, actor, "tickets.read")
    return ticket_view(db, ticket)


class TicketReply(BaseModel):
    message: str = Field(min_length=2, max_length=4000)


@app.post("/api/v1/tickets/{ticket_id}/messages")
def ticket_customer_reply(ticket_id: str, body: TicketReply,
                          actor: int = Depends(csrf_guard)):
    with SessionLocal() as db:
        ticket = db.scalar(select(Ticket).where(Ticket.id == ticket_id).with_for_update())
        if not ticket or ticket.user_id != actor:
            raise HTTPException(404, "تیکت پیدا نشد")
        if ticket.status == "closed":
            raise HTTPException(409, "این تیکت بسته شده است")
        item = TicketMessage(ticket_id=ticket.id, author_id=actor, body=body.message.strip(), is_staff=False)
        if len(item.body) < 2:
            raise HTTPException(422, "متن پاسخ کوتاه است")
        db.add(item)
        ticket.status = "waiting_support"
        db.flush()
        audit(db, actor, "ticket.customer_replied", ticket.id)
        db.add(TelegramOutbox(payload={"chat_id": config.owner_id,
             "text": "مشتری به تیکت گنج VPS پاسخ داد. شناسه: " + ticket.id[:12], "parse_mode": "HTML"}))
        db.commit()
        return ticket_message_view(item)


@app.post("/api/v1/admin/tickets/{ticket_id}/reply")
def admin_ticket_reply(ticket_id: str, body: TicketReply,
                       actor: int = Depends(permission_for("tickets.manage"))):
    with SessionLocal() as db:
        ticket = db.scalar(select(Ticket).where(Ticket.id == ticket_id).with_for_update())
        if not ticket:
            raise HTTPException(404, "تیکت پیدا نشد")
        if ticket.status == "closed":
            raise HTTPException(409, "ابتدا وضعیت تیکت را باز کنید")
        user_get_or_create(db, actor)
        item = TicketMessage(ticket_id=ticket.id, author_id=actor,
                             body=body.message.strip(), is_staff=True)
        if len(item.body) < 2:
            raise HTTPException(422, "متن پاسخ کوتاه است")
        db.add(item)
        ticket.status = "answered"
        db.flush()
        audit(db, actor, "ticket.staff_replied", ticket.id, customer_id=ticket.user_id)
        db.add(TelegramOutbox(payload={"chat_id": ticket.user_id,
             "text": "پشتیبانی گنج VPS به تیکت شما پاسخ داد. شناسه: " + ticket.id[:12] +
                     "\nبرای مشاهده پاسخ وارد بخش پشتیبانی شوید.", "parse_mode": "HTML"}))
        db.commit()
        return ticket_message_view(item)


class TicketStatusChange(BaseModel):
    status: str


@app.patch("/api/v1/admin/tickets/{ticket_id}/status")
def admin_ticket_status(ticket_id: str, body: TicketStatusChange,
                        actor: int = Depends(permission_for("tickets.manage"))):
    if body.status not in {"open", "in_progress", "answered", "closed"}:
        raise HTTPException(422, "وضعیت معتبر نیست")
    with SessionLocal() as db:
        ticket = db.scalar(select(Ticket).where(Ticket.id == ticket_id).with_for_update())
        if not ticket:
            raise HTTPException(404, "تیکت پیدا نشد")
        previous = ticket.status
        ticket.status = body.status
        audit(db, actor, "ticket.status_changed", ticket.id, old=previous, new=body.status)
        db.commit()
        return {"ok": True, "id": ticket.id, "status": ticket.status}


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
