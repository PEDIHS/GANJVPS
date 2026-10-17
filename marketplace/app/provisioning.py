"""GANJ VPS provisioning *preflight*, not a remote installer.

No call here executes shell commands, touches a VPS, configures Docker, or
marks a subscription active. Live deployment requires a separately authenticated
Host Agent, pinned installers, per-runtime PoC and health verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol
from sqlalchemy import select
from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.config import config
from app.models import Host, Order, Slot, Plan, PortLease, ProvisionJob, Subscription, Operation
from app.services import owner_ids

# Isolated TCP port candidates only. Ports for external Xray inbound services
# MUST be separately allocated and mapped; two nodes never share the same
# host_ip:port:protocol. Ports 22/80/443 and control-plane ports are excluded.
PORT_START = 30000
PORT_END = 44998
PORT_STEP = 2

RUNTIME_MATRIX = {
    "pasarguard": {
        "stage": "trial_needed",
        "control_ports": ("service", "xray_api"),
        "isolation": "isolated-node-instance",
        "upstream": "PasarGuard/scripts pg-node.sh",
    },
    "rebecca": {
        "stage": "poc_needed",
        "control_ports": ("service", "xray_api"),
        "isolation": "separate-runtime-and-certificate",
        "upstream": "rebeccapanel/Rebecca rebecca-node",
    },
    "marzban": {
        "stage": "poc_needed",
        "control_ports": ("service", "xray_api"),
        "isolation": "separate-runtime-and-certificate",
        "upstream": "Gozargah/Marzban-node",
    },
}

class HostInspector(Protocol):
    """Implemented in a later phase by a mutually authenticated trial agent."""
    def verify(self, host: Host) -> "Probe":
        ...


@dataclass(frozen=True)
class Probe:
    """A fresh live-agent observation; never derive this from UI or host.capabilities."""
    reachable: bool
    os_id: str = ""
    architecture: str = ""
    cgroup_v2: bool = False
    docker_available: bool = False
    bound_tcp_ports: frozenset[int] = frozenset()
    inspected_at: str = ""
    # This is a *test* proof: no auth token, password or certificate is returned.
    trial_agent_verified: bool = False


class OfflineInspector:
    def verify(self, host: Host) -> Probe:
        # Fail closed until the agent connection and certificate pinning exist.
        return Probe(reachable=False)


@dataclass(frozen=True)
class Preflight:
    order_id: str
    job_id: str
    slot_id: str
    host_id: str
    runtime: str
    state: str
    private_ip: str
    allowed_to_execute: bool
    blocked_by: tuple[str, ...]
    candidate_ports: tuple[int, ...]
    cpu_quota_percent: int
    memory_mb: int

    def admin_view(self) -> dict:
        # No server credentials or private install commands in API responses.
        return {
            "order_id": self.order_id,
            "job_id": self.job_id,
            "slot_id": self.slot_id,
            "host_id": self.host_id,
            "runtime": self.runtime,
            "state": self.state,
            "allowed_to_execute": self.allowed_to_execute,
            "blocked_by": list(self.blocked_by),
            "proposed_service_ports": list(self.candidate_ports),
            "per_node_cpu_quota_percent": self.cpu_quota_percent,
            "per_node_memory_mb": self.memory_mb,
            "note": "Read-only preflight. Ports are NOT reserved; no node has been installed.",
        }


def candidate_port_pair(db: Session, host: Host, observed: frozenset[int]) -> tuple[int, ...]:
    """Only proposes a port pair; never assumes unverified free OS ports."""
    leases = db.scalars(select(PortLease).where(
        PortLease.host_id == host.id, PortLease.ip == host.ip, PortLease.protocol == "tcp")).all()
    used = {port.port for port in leases} | set(observed)
    for base in range(PORT_START, PORT_END + 1, PORT_STEP):
        if base not in used and (base + 1) not in used:
            return (base, base + 1)
    return ()


def _models_for_order(db: Session, order_id: str):
    order = db.get(Order, order_id)
    if order is None:
        raise HTTPException(404, "سفارش پیدا نشد")
    job = db.scalar(select(ProvisionJob).where(ProvisionJob.order_id == order.id))
    slot = db.get(Slot, order.slot_id)
    sub = db.scalar(select(Subscription).where(Subscription.order_id == order.id))
    host = db.get(Host, slot.host_id) if slot else None
    if not all((job, slot, sub, host)):
        raise HTTPException(409, "اطلاعات نصب این سفارش ناقص است")
    return order, job, slot, sub, host


def preflight_order(db: Session, order_id: str,
                    inspector: HostInspector | None = None) -> Preflight:
    order, job, slot, sub, host = _models_for_order(db, order_id)
    reasons: list[str] = []

    def block(reason: str):
        if reason not in reasons:
            reasons.append(reason)

    runtime = job.runtime_type
    if runtime not in RUNTIME_MATRIX or runtime != sub.runtime_type:
        block("runtime_not_supported_or_mismatched")
    if order.status != "paid":
        block("order_not_paid")
    if slot.owner_id != order.user_id or slot.order_id != order.id or sub.slot_id != slot.id:
        block("order_slot_ownership_mismatch")
    if sub.status not in {"provisioning", "awaiting_customer_input"}:
        block("subscription_not_provisioning")
    if host.status not in {"available", "maintenance"}:
        block("host_not_available")
    if host.capacity not in (2, 3):
        block("invalid_capacity")
    if not host.ip:
        block("host_ip_missing")
    else:
        try:
            ip_address(host.ip)
        except ValueError:
            block("host_ip_invalid")
    if job.state not in {"awaiting_connector", "queued", "preflight",
                         "awaiting_customer_input", "retryable_error"}:
        block("job_state_not_eligible")
    active_ops = db.scalars(select(Operation).where(
        Operation.host_id == host.id,
        Operation.status.in_(["pending_approval", "approved", "scheduled",
                              "running", "verifying"]))).first()
    if active_ops:
        block("conflicting_host_operation")

    capacity = host.capacity if host.capacity in (2, 3) else 1
    ram = max(0, (host.ram_mb - host.reserved_ram_mb) // capacity)
    cpu_percent = max(0, int(host.cpu * 100 / capacity))
    if ram < 1024:
        block("insufficient_memory_after_host_reserve")
    if cpu_percent < 100:
        block("insufficient_cpu_quota")

    # The present management VPS is not a trial agent. The DB host record is
    # never sufficient evidence that an installer can touch the host.
    if not isinstance(host.capabilities, dict) or host.capabilities.get("purpose") != "trial-node":
        block("host_not_enrolled_as_trial")
    observed = (inspector or OfflineInspector()).verify(host)
    if not observed.reachable or not observed.trial_agent_verified:
        block("authenticated_trial_agent_missing")
    if observed.reachable:
        if observed.os_id not in {"ubuntu", "debian"}:
            block("unsupported_test_os")
        if observed.architecture not in {"x86_64", "aarch64"}:
            block("unsupported_architecture")
        if not observed.cgroup_v2:
            block("cgroup_v2_missing")
        if not observed.docker_available:
            block("container_runtime_missing")

    # Rebecca/Marzban cannot be assumed compatible just because a menu
    # exposes them. Their independently pinned runtime PoCs are pending.
    if runtime != "pasarguard":
        block("runtime_coexistence_poc_not_approved")
    # An immutable installer checksum AND version must be reviewed out of
    # band, then attested by the agent. Neither is presently installed.
    block("pinned_installer_and_agent_executor_not_integrated")
    if config.dry_run or not config.host_ops_enabled:
        block("production_safety_interlock_active")

    proposed = candidate_port_pair(db, host, observed.bound_tcp_ports)
    if len(proposed) != 2:
        block("no_two_conflict_free_ports")
    return Preflight(order_id=order.id, job_id=job.id,
                     slot_id=slot.id, host_id=host.id,
                     runtime=runtime, state=job.state, private_ip=host.ip,
                     allowed_to_execute=False,
                     blocked_by=tuple(reasons),
                     candidate_ports=proposed, cpu_quota_percent=cpu_percent,
                     memory_mb=ram)
