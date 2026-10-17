from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Integer, Boolean, ForeignKey, DateTime, UniqueConstraint, Index, JSON, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def uid() -> str:
    return uuid4().hex


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # Telegram user ID
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AdminPermission(Base):
    __tablename__ = "admin_permissions"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    permission: Mapped[str] = mapped_column(String(100), primary_key=True)
    department: Mapped[str] = mapped_column(String(80), default="management")
    granted_by: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(200))
    region: Mapped[str] = mapped_column(String(100))
    provider: Mapped[str] = mapped_column(String(100), default="manual")
    provider_server_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip: Mapped[str] = mapped_column(String(45))
    additional_ips: Mapped[list] = mapped_column(JSON, default=list)
    capacity: Mapped[int] = mapped_column(Integer)
    cpu: Mapped[int] = mapped_column(Integer, default=1)
    ram_mb: Mapped[int] = mapped_column(Integer, default=1024)
    reserved_ram_mb: Mapped[int] = mapped_column(Integer, default=256)
    monthly_cost: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(25), default="available")
    capabilities: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Slot(Base):
    __tablename__ = "slots"
    __table_args__ = (UniqueConstraint("host_id", "slot_no", name="unique_host_slot"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    slot_no: Mapped[int] = mapped_column(Integer)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="available")
    reserved_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    order_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Plan(Base):
    __tablename__ = "plans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(180))
    region: Mapped[str] = mapped_column(String(100))
    capacity: Mapped[int] = mapped_column(Integer)
    price_toman: Mapped[int] = mapped_column(Integer)
    term_days: Mapped[int] = mapped_column(Integer, default=30)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Order(Base):
    __tablename__ = "orders"
    __table_args__ = (UniqueConstraint("user_id", "idempotency_key", name="unique_order_idem"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    plan_id: Mapped[str] = mapped_column(ForeignKey("plans.id"))
    slot_id: Mapped[str] = mapped_column(ForeignKey("slots.id"))
    amount_toman: Mapped[int] = mapped_column(Integer)
    idempotency_key: Mapped[str] = mapped_column(String(150))
    status: Mapped[str] = mapped_column(String(30), default="reserved")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Subscription(Base):
    __tablename__ = "subscriptions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    slot_id: Mapped[str] = mapped_column(ForeignKey("slots.id"), unique=True)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"), unique=True)
    status: Mapped[str] = mapped_column(String(30), default="provisioning")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ends_at: Mapped[datetime] = mapped_column(DateTime)
    runtime_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    api_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    public_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class WalletEntry(Base):
    __tablename__ = "wallet_entries"
    __table_args__ = (UniqueConstraint("dedupe_key", name="unique_ledger_entry"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    delta_toman: Mapped[int] = mapped_column(Integer)
    reason: Mapped[str] = mapped_column(String(250))
    dedupe_key: Mapped[str] = mapped_column(String(180))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PortLease(Base):
    __tablename__ = "port_leases"
    __table_args__ = (UniqueConstraint("host_id", "ip", "protocol", "port", name="unique_external_port"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"))
    slot_id: Mapped[str] = mapped_column(ForeignKey("slots.id"))
    ip: Mapped[str] = mapped_column(String(45))
    protocol: Mapped[str] = mapped_column(String(5))
    port: Mapped[int] = mapped_column(Integer)
    purpose: Mapped[str] = mapped_column(String(40))


class ProvisionJob(Base):
    __tablename__ = "provision_jobs"
    __table_args__ = (UniqueConstraint("order_id", "runtime_type", name="unique_runtime_job"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    order_id: Mapped[str] = mapped_column(ForeignKey("orders.id"))
    slot_id: Mapped[str] = mapped_column(ForeignKey("slots.id"))
    runtime_type: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(40), default="queued")
    errors: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Operation(Base):
    __tablename__ = "operations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)
    requester_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(35), default="pending_approval")
    owners_snapshot: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class OperationVote(Base):
    __tablename__ = "operation_votes"
    __table_args__ = (UniqueConstraint("operation_id", "user_id", name="unique_operation_vote"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    operation_id: Mapped[str] = mapped_column(ForeignKey("operations.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    choice: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Ticket(Base):
    __tablename__ = "tickets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    subject: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    department: Mapped[str] = mapped_column(String(45), default="support")
    status: Mapped[str] = mapped_column(String(30), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TicketMessage(Base):
    __tablename__ = "ticket_messages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    is_staff: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    actor_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event: Mapped[str] = mapped_column(String(120))
    entity_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class BotState(Base):
    __tablename__ = "bot_states"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    action: Mapped[str] = mapped_column(String(55))
    resource_id: Mapped[str] = mapped_column(String(32))


class ProcessedUpdate(Base):
    __tablename__ = "processed_bot_updates"
    update_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
