"""Admin-managed VPS catalogue. Adding a datacenter is metadata, not server provisioning."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.auth import permission_for
from app.db import get_db
from app.models import (Datacenter, CatalogLocation, HostCatalog, PlanCatalog,
                        Host, Plan, Slot, Order)
from app.services import audit, available_slots

router = APIRouter(prefix="/api/v1/admin/catalog", tags=["admin-catalog"])


def missing(resource: str):
    raise HTTPException(404, resource + " پیدا نشد")


def prevent(value: bool, error: str):
    if not value:
        raise HTTPException(422, error)


def datacenter_payload(d):
    return {"id": d.id, "name": d.name, "slug": d.slug, "enabled": d.enabled}


def location_payload(loc, d):
    return {"id": loc.id, "datacenter_id": d.id, "datacenter": d.name,
            "country_code": loc.country_code, "country_name": loc.country_name,
            "city": loc.city, "enabled": loc.enabled, "datacenter_enabled": d.enabled}


class DatacenterCreate(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,54}$")


class DatacenterEdit(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=150)
    enabled: bool | None = None


@router.get("/datacenters")
def list_datacenters(actor: int = Depends(permission_for("servers.manage")),
                     db: Session = Depends(get_db)):
    items = db.scalars(select(Datacenter).order_by(Datacenter.name)).all()
    return [datacenter_payload(item) for item in items]


@router.post("/datacenters")
def create_datacenter(body: DatacenterCreate,
                      actor: int = Depends(permission_for("servers.manage")),
                      db: Session = Depends(get_db)):
    prevent(db.scalar(select(Datacenter).where(
        Datacenter.slug == body.slug)) is None, "این شناسه دیتاسنتر قبلاً ثبت شده است")
    obj = Datacenter(name=body.name.strip(), slug=body.slug)
    db.add(obj)
    db.flush()
    audit(db, actor, "catalog.datacenter.created", obj.id)
    db.commit()
    return datacenter_payload(obj)


@router.patch("/datacenters/{datacenter_id}")
def edit_datacenter(datacenter_id: str, body: DatacenterEdit,
                    actor: int = Depends(permission_for("servers.manage")),
                    db: Session = Depends(get_db)):
    obj = db.get(Datacenter, datacenter_id)
    if not obj: missing("دیتاسنتر")
    changes = body.model_dump(exclude_unset=True)
    prevent(changes and all(v is not None for v in changes.values()), "تغییرات معتبر نیست")
    for k, v in changes.items():
        setattr(obj, k, v.strip() if isinstance(v, str) else v)
    audit(db, actor, "catalog.datacenter.updated", obj.id, fields=list(changes))
    db.commit()
    return datacenter_payload(obj)


class LocationCreate(BaseModel):
    datacenter_id: str
    country_code: str = Field(pattern=r"^[A-Z]{2}$")
    country_name: str = Field(min_length=2, max_length=90)
    city: str = Field(min_length=2, max_length=120)


class LocationEdit(BaseModel):
    enabled: bool | None = None
    country_name: str | None = Field(default=None, min_length=2, max_length=90)


@router.get("/locations")
def list_locations(actor: int = Depends(permission_for("servers.manage")),
                   db: Session = Depends(get_db)):
    rows = db.execute(select(CatalogLocation, Datacenter).join(
        Datacenter, Datacenter.id == CatalogLocation.datacenter_id).order_by(
        CatalogLocation.country_code, CatalogLocation.city, Datacenter.name)).all()
    return [location_payload(loc, d) for loc, d in rows]


@router.post("/locations")
def create_location(body: LocationCreate,
                    actor: int = Depends(permission_for("servers.manage")),
                    db: Session = Depends(get_db)):
    dc = db.get(Datacenter, body.datacenter_id)
    if not dc: missing("دیتاسنتر")
    code = body.country_code.upper()
    city = body.city.strip()
    prevent(db.scalar(select(CatalogLocation).where(
        CatalogLocation.datacenter_id == dc.id,
        CatalogLocation.country_code == code,
        CatalogLocation.city == city)) is None,
        "این لوکیشن در دیتاسنتر قبلاً ثبت شده است")
    loc = CatalogLocation(datacenter_id=dc.id, country_code=code,
                          country_name=body.country_name.strip(), city=city)
    db.add(loc)
    db.flush()
    audit(db, actor, "catalog.location.created", loc.id, datacenter_id=dc.id)
    db.commit()
    return location_payload(loc, dc)


@router.patch("/locations/{location_id}")
def edit_location(location_id: str, body: LocationEdit,
                  actor: int = Depends(permission_for("servers.manage")),
                  db: Session = Depends(get_db)):
    loc = db.get(CatalogLocation, location_id)
    if not loc: missing("لوکیشن")
    changes = body.model_dump(exclude_unset=True)
    prevent(changes and all(v is not None for v in changes.values()), "تغییرات معتبر نیست")
    for k, v in changes.items():
        setattr(loc, k, v.strip() if isinstance(v, str) else v)
    audit(db, actor, "catalog.location.updated", loc.id, fields=list(changes))
    db.commit()
    return location_payload(loc, db.get(Datacenter, loc.datacenter_id))


class HostPlacementRequest(BaseModel):
    location_id: str
    bandwidth_gb: int | None = Field(default=None, gt=0, le=1000000)
    os_family: str = Field(default="linux", pattern="^(linux|windows)$")


@router.get("/hosts")
def host_inventory(actor: int = Depends(permission_for("servers.manage")),
                   db: Session = Depends(get_db)):
    rows = db.scalars(select(Host).order_by(Host.name)).all()
    out = []
    for h in rows:
        link = db.get(HostCatalog, h.id)
        loc = db.get(CatalogLocation, link.location_id) if link else None
        dc = db.get(Datacenter, loc.datacenter_id) if loc else None
        occupied = db.scalar(select(func.count()).select_from(Slot).where(
            Slot.host_id == h.id, Slot.status != "available")) or 0
        out.append({"id": h.id, "name": h.name, "region": h.region,
                    "status": h.status, "cpu": h.cpu, "ram_mb": h.ram_mb,
                    "reserved_ram_mb": h.reserved_ram_mb, "capacity": h.capacity,
                    "occupied": occupied, "location_id": loc.id if loc else None,
                    "city": loc.city if loc else None,
                    "datacenter": dc.name if dc else None,
                    "bandwidth_gb": link.bandwidth_gb if link else None,
                    "os_family": link.os_family if link else None})
    return out


@router.put("/hosts/{host_id}/placement")
def assign_host(host_id: str, body: HostPlacementRequest,
                actor: int = Depends(permission_for("servers.manage")),
                db: Session = Depends(get_db)):
    host = db.get(Host, host_id)
    if not host: missing("سرور")
    loc = db.get(CatalogLocation, body.location_id)
    if not loc: missing("لوکیشن")
    prevent(host.region.upper() == loc.country_code,
            "کشور سرور با کشور لوکیشن تطابق ندارد")
    # A tenant's existing placement must not be reclassified under their feet.
    existing = db.get(HostCatalog, host.id)
    if existing and existing.location_id != loc.id:
        occupied = db.scalar(select(func.count()).select_from(Slot).where(
            Slot.host_id == host.id, Slot.status != "available")) or 0
        if occupied: raise HTTPException(409, "سرور دارای اشتراک است؛ انتقال لوکیشن مجاز نیست")
    if existing:
        existing.location_id = loc.id
        existing.bandwidth_gb = body.bandwidth_gb
        existing.os_family = body.os_family
    else:
        db.add(HostCatalog(host_id=host.id, location_id=loc.id,
                           bandwidth_gb=body.bandwidth_gb, os_family=body.os_family))
    audit(db, actor, "catalog.host.placed", host.id, location_id=loc.id)
    db.commit()
    return {"ok": True, "host_id": host.id, "location_id": loc.id,
            "note": "Metadata saved. No remote host provisioning executed."}


class PlanPlacementRequest(BaseModel):
    location_id: str
    min_vcpu: int = Field(default=1, ge=1, le=256)
    min_ram_mb: int = Field(default=1024, ge=512, le=1048576)
    min_traffic_gb: int | None = Field(default=None, gt=0, le=1000000)
    os_family: str = Field(default="linux", pattern="^(linux|windows)$")


@router.get("/plans")
def plan_inventory(actor: int = Depends(permission_for("plans.manage")),
                   db: Session = Depends(get_db)):
    plans = db.scalars(select(Plan).order_by(Plan.name)).all()
    rows = []
    for plan in plans:
        link = db.get(PlanCatalog, plan.id)
        loc = db.get(CatalogLocation, link.location_id) if link else None
        dc = db.get(Datacenter, loc.datacenter_id) if loc else None
        rows.append({"id": plan.id, "name": plan.name, "region": plan.region,
                     "capacity": plan.capacity, "enabled": plan.enabled,
                     "price_toman": plan.price_toman,
                     "stock": len(available_slots(db, plan)),
                     "location_id": loc.id if loc else None,
                     "city": loc.city if loc else None,
                     "datacenter": dc.name if dc else None,
                     "min_vcpu": link.min_vcpu if link else None,
                     "min_ram_mb": link.min_ram_mb if link else None,
                     "min_traffic_gb": link.min_traffic_gb if link else None,
                     "os_family": link.os_family if link else None})
    return rows


@router.put("/plans/{plan_id}/placement")
def assign_plan(plan_id: str, body: PlanPlacementRequest,
                actor: int = Depends(permission_for("plans.manage")),
                db: Session = Depends(get_db)):
    plan = db.get(Plan, plan_id)
    if not plan: missing("پلن")
    loc = db.get(CatalogLocation, body.location_id)
    if not loc: missing("لوکیشن")
    prevent(plan.region.upper() == loc.country_code,
            "کشور پلن با کشور لوکیشن تطابق ندارد")
    existing = db.get(PlanCatalog, plan_id)
    if existing:
        for k, v in body.model_dump().items():
            setattr(existing, k, v)
    else:
        db.add(PlanCatalog(plan_id=plan_id, **body.model_dump()))
    audit(db, actor, "catalog.plan.placed", plan_id, location_id=loc.id)
    db.commit()
    return {"ok": True, "plan_id": plan_id, "location_id": loc.id,
            "note": "Catalog filters apply to subsequent orders only."}
