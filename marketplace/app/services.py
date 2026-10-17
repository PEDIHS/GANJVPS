"""Pure-ish business operations. No remote power actions are executed here."""
from __future__ import annotations
from datetime import timedelta
import ipaddress
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models import (User, AdminPermission, Host, Slot, Plan, Order, Subscription,
                        WalletEntry, ProvisionJob, Operation, OperationVote, Audit, utcnow)
from app.config import config

RUNTIMES = {"pasarguard", "rebecca", "marzban"}
HOST_ACTIONS = {"restart_host", "power_off", "power_on", "change_shared_ip"}


def forbidden(message="دسترسی مجاز نیست"):
    raise HTTPException(403, message)


def user_get_or_create(db: Session, telegram_id: int, name: str = "") -> User:
    user = db.get(User, telegram_id)
    if user is None:
        user = User(id=telegram_id, display_name=name[:200])
        db.add(user)
        db.flush()
    if not user.active:
        forbidden("حساب کاربری غیرفعال است")
    return user


def require_permission(db: Session, actor: int, permission: str):
    if actor == config.owner_id:
        return
    p = db.get(AdminPermission, (actor, permission))
    if p is None:
        forbidden("مجوز مدیریت این بخش را ندارید")


def audit(db: Session, actor: int | None, event: str, entity: str | None = None, **detail):
    db.add(Audit(actor_id=actor, event=event, entity_id=entity, detail=detail))


def create_host(db: Session, actor: int, *, name: str, region: str, ip: str, capacity: int,
                cpu: int, ram_mb: int, reserved_ram_mb: int, monthly_cost: int, provider: str = "manual") -> Host:
    require_permission(db, actor, "servers.manage")
    if capacity not in (2, 3) or cpu < 1 or ram_mb <= reserved_ram_mb or reserved_ram_mb < 0 or monthly_cost < 0:
        raise HTTPException(422, "ظرفیت یا منابع نامعتبر است")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "آدرس IP نامعتبر است")
    host = Host(name=name[:200], region=region[:100], ip=ip, capacity=capacity, cpu=cpu,
                ram_mb=ram_mb, reserved_ram_mb=reserved_ram_mb,
                monthly_cost=monthly_cost, provider=provider[:100])
    db.add(host)
    db.flush()
    for number in range(1, capacity + 1):
        db.add(Slot(host_id=host.id, slot_no=number))
    audit(db, actor, "host.created", host.id, capacity=capacity)
    db.flush()
    return host


def create_plan(db: Session, actor: int, *, name: str, region: str, capacity: int,
                price_toman: int, term_days: int = 30) -> Plan:
    require_permission(db, actor, "plans.manage")
    if capacity not in (2, 3) or price_toman <= 0 or not 1 <= term_days <= 365:
        raise HTTPException(422, "پلن نامعتبر است")
    plan = Plan(name=name[:180], region=region[:100], capacity=capacity, price_toman=price_toman, term_days=term_days)
    db.add(plan)
    db.flush()
    audit(db, actor, "plan.created", plan.id)
    return plan


def get_balance(db: Session, user_id: int) -> int:
    return int(db.scalar(select(func.coalesce(func.sum(WalletEntry.delta_toman), 0)).where(WalletEntry.user_id == user_id)) or 0)


def lock_wallet_owner(db: Session, user_id: int) -> None:
    """Serialize balance-changing transactions per user on PostgreSQL.

    SUM(wallet_entries) cannot itself be locked. The stable user row serves
    as the wallet-level advisory lock, including when the balance is zero.
    SQLite callers already serialize writes with BEGIN IMMEDIATE.
    """
    if db.bind.dialect.name == "postgresql":
        db.execute(select(User.id).where(User.id == user_id).with_for_update()).first()


def adjust_wallet(db: Session, actor: int, user_id: int, delta: int, reason: str, reference: str):
    require_permission(db, actor, "wallet.adjust")
    if delta == 0 or not reason.strip() or not reference.strip():
        raise HTTPException(422, "مبلغ، توضیح و شناسه تراکنش الزامی است")
    user_get_or_create(db, user_id)
    lock_wallet_owner(db, user_id)
    existing = db.scalar(select(WalletEntry).where(WalletEntry.dedupe_key == "manual:" + reference))
    if existing:
        if existing.user_id != user_id or existing.delta_toman != delta:
            raise HTTPException(409, "شناسه تراکنش قبلاً با مقادیر دیگری استفاده شده")
        return existing
    if delta < 0 and get_balance(db, user_id) + delta < 0:
        raise HTTPException(409, "موجودی کافی نیست")
    item = WalletEntry(user_id=user_id, delta_toman=delta, reason=reason[:250], dedupe_key="manual:" + reference)
    db.add(item)
    audit(db, actor, "wallet.adjusted", item.id, user_id=user_id, amount=delta, reference=reference)
    db.flush()
    return item


def available_slots(db: Session, plan: Plan):
    return db.scalars(select(Slot).join(Host, Host.id == Slot.host_id)
        .where(Slot.status == "available", Host.region == plan.region,
               Host.capacity == plan.capacity, Host.status == "available")
        .order_by(Host.created_at, Slot.slot_no)).all()


def purchase(db: Session, buyer_id: int, plan_id: str, runtime: str, idem: str) -> tuple[Order, bool]:
    """Call with a serialized DB write transaction (Postgres host lock / SQLite BEGIN IMMEDIATE)."""
    if runtime not in RUNTIMES or not idem or len(idem) > 150:
        raise HTTPException(422, "نوع پنل یا شناسه سفارش نامعتبر است")
    user_get_or_create(db, buyer_id)
    lock_wallet_owner(db, buyer_id)
    existing = db.scalar(select(Order).where(Order.user_id == buyer_id, Order.idempotency_key == idem))
    if existing:
        return existing, False
    plan = db.get(Plan, plan_id)
    if not plan or not plan.enabled:
        raise HTTPException(404, "پلن موجود نیست")
    if get_balance(db, buyer_id) < plan.price_toman:
        raise HTTPException(409, "موجودی کیف پول کافی نیست")
    # Locked hosts on PostgreSQL; SQLite BEGIN IMMEDIATE is held by caller.
    host_ids = db.scalars(select(Host.id).where(Host.region == plan.region,
          Host.capacity == plan.capacity, Host.status == "available").with_for_update()).all()
    slot = db.scalar(select(Slot).where(Slot.host_id.in_(host_ids), Slot.status == "available")
                     .order_by(Slot.slot_no).with_for_update()) if host_ids else None
    if not slot:
        raise HTTPException(409, "موجودی نود در این لوکیشن تمام شده")
    order = Order(user_id=buyer_id, plan_id=plan.id, slot_id=slot.id,
                  amount_toman=plan.price_toman, idempotency_key=idem, status="paid")
    db.add(order)
    db.flush()
    slot.owner_id = buyer_id
    slot.status = "provisioning"
    slot.order_id = order.id
    db.add(WalletEntry(user_id=buyer_id, delta_toman=-plan.price_toman,
                       reason="خرید نود " + plan.name, dedupe_key="order:" + order.id))
    subscription = Subscription(user_id=buyer_id, slot_id=slot.id, order_id=order.id,
                     ends_at=utcnow() + timedelta(days=plan.term_days),
                     runtime_type=runtime, status="provisioning")
    db.add(subscription)
    db.add(ProvisionJob(order_id=order.id, slot_id=slot.id, runtime_type=runtime,
                        state="awaiting_connector"))
    audit(db, buyer_id, "order.paid", order.id, slot_id=slot.id, runtime=runtime)
    db.flush()
    return order, True


def owner_ids(db: Session, host_id: str) -> list[int]:
    now = utcnow()
    ids = db.scalars(select(Subscription.user_id).join(Slot, Slot.id == Subscription.slot_id)
             .where(Slot.host_id == host_id, Subscription.status.in_(["active", "provisioning"]),
                    Subscription.ends_at > now)).all()
    return sorted(set(ids))


def request_operation(db: Session, actor: int, host_id: str, action: str, reason: str) -> Operation:
    if action not in HOST_ACTIONS or len(reason.strip()) < 8 or len(reason) > 500:
        raise HTTPException(422, "دستور یا دلیل درخواست نامعتبر است")
    # Lock the host itself: locking only an existing Operation row does not
    # prevent two concurrent requests when no active operation exists.
    host = db.scalar(select(Host).where(Host.id == host_id).with_for_update())
    if not host:
        raise HTTPException(404, "سرور پیدا نشد")
    owners = owner_ids(db, host_id)
    if actor not in owners:
        forbidden("شما مالک نود فعال این سرور نیستید")
    live = db.scalar(select(Operation).where(Operation.host_id == host_id,
                 Operation.status.in_(["pending_approval", "approved", "scheduled", "running"])).with_for_update())
    if live:
        raise HTTPException(409, "یک درخواست حساس دیگر برای این سرور باز است")
    op = Operation(host_id=host_id, requester_id=actor, action=action, reason=reason.strip(),
        owners_snapshot=owners, expires_at=utcnow() + timedelta(hours=24),
        status="approved" if len(owners) == 1 else "pending_approval")
    db.add(op)
    db.flush()
    audit(db, actor, "operation.requested", op.id, owners_count=len(owners), action=action)
    return op


def vote(db: Session, voter: int, operation_id: str, choice: str, reason: str = "") -> Operation:
    if choice not in {"approve", "reject"}:
        raise HTTPException(422, "رأی نامعتبر است")
    op = db.scalar(select(Operation).where(Operation.id == operation_id).with_for_update())
    if not op:
        raise HTTPException(404, "درخواست وجود ندارد")
    if op.status != "pending_approval":
        raise HTTPException(409, "این درخواست دیگر قابل رأی‌دادن نیست")
    if op.expires_at <= utcnow():
        op.status = "expired"
        audit(db, voter, "operation.expired", op.id)
        return op
    if voter == op.requester_id or voter not in op.owners_snapshot:
        forbidden("شما رأی‌دهنده این درخواست نیستید")
    if owner_ids(db, op.host_id) != op.owners_snapshot:
        op.status = "cancelled"
        audit(db, voter, "operation.owners_changed", op.id)
        return op
    if db.scalar(select(OperationVote).where(OperationVote.operation_id == op.id, OperationVote.user_id == voter)):
        raise HTTPException(409, "برای این درخواست قبلاً رأی داده‌اید")
    if choice == "reject" and len(reason.strip()) < 3:
        raise HTTPException(422, "برای رد درخواست، دلیل بنویسید")
    db.add(OperationVote(operation_id=op.id, user_id=voter, choice=choice, reason=reason.strip()[:500]))
    db.flush()
    if choice == "reject":
        op.status = "rejected"
    else:
        approvals = db.scalar(select(func.count()).select_from(OperationVote).where(
          OperationVote.operation_id == op.id, OperationVote.choice == "approve")) or 0
        if approvals == len(op.owners_snapshot) - 1:
            op.status = "approved"
    audit(db, voter, "operation.voted", op.id, choice=choice)
    return op


def operation_can_execute(db: Session, op: Operation) -> bool:
    # Intentionally NOT an executor; infrastructure operations remain disabled.
    return (config.host_ops_enabled and not config.dry_run and op.status == "approved"
            and op.expires_at > utcnow() and owner_ids(db, op.host_id) == op.owners_snapshot)
