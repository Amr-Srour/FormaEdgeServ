"""
Forma Edge Licensing -- Owner Admin API
=======================================
Author: Amr Srour

Everything here requires the X-Admin-Key header. This is the owner's surface:
create licences for anyone, on any terms, and change them at any time.

Deliberate design choices:

- Nothing is ever hard-deleted. Revoke/suspend are state changes, so the app can
  be told WHY access stopped and the history survives.

- Every mutating call writes an audit row. Six months from now, "why does this
  customer say their licence stopped working?" has an answer.

- Expiry extension is absolute (set a new date), not relative (+N days).
  Relative extension compounds mistakes silently when applied twice.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_db, settings
from .models import (
    AuditLog, Customer, Device, License, LicenseStatus, LicenseType, Plan,
    TrialRecord, as_utc, utcnow,
)

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------- Schemas ----------

class CustomerCreate(BaseModel):
    email: EmailStr
    name: str | None = None
    company: str | None = None
    notes: str | None = None


class LicenseCreate(BaseModel):
    customer_email: EmailStr
    customer_name: str | None = None
    company: str | None = None
    plan_id: str = "professional"
    license_type: LicenseType = LicenseType.SUBSCRIPTION
    duration_days: int | None = 365      # None = perpetual
    max_devices: int | None = None       # None = use the plan's default
    features_override: list[str] | None = None
    notes: str | None = None


class LicenseUpdate(BaseModel):
    """All optional -- send only what you want changed."""
    plan_id: str | None = None
    expires_at: datetime | None = None
    max_devices: int | None = None
    features_override: list[str] | None = None
    status: LicenseStatus | None = None
    status_reason: str | None = None


# ---------- Helpers ----------

def _license_out(lic: License, db: Session) -> dict:
    active_devices = db.query(func.count(Device.id)).filter(
        Device.license_id == lic.id, Device.is_active.is_(True)).scalar()
    return {
        "license_id": lic.id,
        "activation_key": lic.activation_key,
        "customer": {
            "id": lic.customer.id, "email": lic.customer.email,
            "name": lic.customer.name, "company": lic.customer.company,
        } if lic.customer else None,
        "plan_id": lic.plan_id,
        "edition": lic.plan.name if lic.plan else None,
        "license_type": lic.license_type.value,
        "status": lic.status.value,
        "effective_status": lic.effective_status().value,
        "status_reason": lic.status_reason,
        "starts_at": lic.starts_at,
        "expires_at": lic.expires_at,
        "max_devices": lic.max_devices,
        "active_devices": active_devices,
        "features": lic.effective_features,
        "created_at": lic.created_at,
    }


def _audit(db, action, request, **kw):
    db.add(AuditLog(actor="admin", action=action,
                     ip_address=(request.client.host if request and request.client else None), **kw))


# ---------- Dashboard ----------

@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    """Headline numbers for the dashboard."""
    all_licenses = db.query(License).all()
    effective = [l.effective_status() for l in all_licenses]
    soon = utcnow() + timedelta(days=30)
    expiring = sum(
        1 for l in all_licenses
        if l.expires_at and l.effective_status() is LicenseStatus.ACTIVE
        and as_utc(l.expires_at) <= soon
    )
    return {
        "licenses_total": len(all_licenses),
        "active": sum(1 for s in effective if s is LicenseStatus.ACTIVE),
        "expired": sum(1 for s in effective if s is LicenseStatus.EXPIRED),
        "suspended": sum(1 for s in effective if s is LicenseStatus.SUSPENDED),
        "revoked": sum(1 for s in effective if s is LicenseStatus.REVOKED),
        "expiring_within_30_days": expiring,
        "customers": db.query(func.count(Customer.id)).scalar(),
        "devices_active": db.query(func.count(Device.id)).filter(Device.is_active.is_(True)).scalar(),
        "trials_started": db.query(func.count(TrialRecord.id)).scalar(),
    }


# ---------- Customers ----------

@router.post("/customers")
def create_customer(body: CustomerCreate, request: Request, db: Session = Depends(get_db)):
    if db.query(Customer).filter(Customer.email == body.email).first():
        raise HTTPException(409, "A customer with that email already exists.")
    cust = Customer(**body.model_dump())
    db.add(cust)
    _audit(db, "customer.created", request, customer_id=cust.id, detail={"email": body.email})
    db.commit()
    db.refresh(cust)
    return {"id": cust.id, "email": cust.email, "name": cust.name, "company": cust.company}


@router.get("/customers")
def list_customers(db: Session = Depends(get_db), q: str | None = None):
    query = db.query(Customer)
    if q:
        like = f"%{q}%"
        query = query.filter((Customer.email.ilike(like)) | (Customer.name.ilike(like))
                              | (Customer.company.ilike(like)))
    return [{"id": c.id, "email": c.email, "name": c.name, "company": c.company,
             "licenses": len(c.licenses), "created_at": c.created_at}
            for c in query.order_by(Customer.created_at.desc()).all()]


# ---------- Licenses ----------

@router.post("/licenses")
def create_license(body: LicenseCreate, request: Request, db: Session = Depends(get_db)):
    """Issue a licence to anyone, on any terms. Creates the customer if new."""
    plan = db.query(Plan).filter(Plan.id == body.plan_id).first()
    if not plan:
        raise HTTPException(404, f"Unknown plan '{body.plan_id}'.")

    cust = db.query(Customer).filter(Customer.email == body.customer_email).first()
    if not cust:
        cust = Customer(email=body.customer_email, name=body.customer_name,
                         company=body.company, notes=body.notes)
        db.add(cust)
        db.flush()

    lic = License(
        customer_id=cust.id,
        plan_id=plan.id,
        license_type=body.license_type,
        status=LicenseStatus.ACTIVE,
        expires_at=(utcnow() + timedelta(days=body.duration_days)) if body.duration_days else None,
        max_devices=body.max_devices if body.max_devices is not None else plan.default_max_devices,
        features_override=body.features_override,
    )
    db.add(lic)
    db.flush()
    _audit(db, "license.created", request, license_id=lic.id, customer_id=cust.id,
           detail={"plan": plan.id, "type": body.license_type.value,
                   "duration_days": body.duration_days, "max_devices": lic.max_devices})
    db.commit()
    db.refresh(lic)
    return _license_out(lic, db)


@router.get("/licenses")
def list_licenses(db: Session = Depends(get_db), status: LicenseStatus | None = None,
                   q: str | None = None, limit: int = Query(100, le=500)):
    query = db.query(License).join(Customer)
    if q:
        like = f"%{q}%"
        query = query.filter((Customer.email.ilike(like)) | (Customer.company.ilike(like))
                              | (License.id.ilike(like)))
    licenses = query.order_by(License.created_at.desc()).limit(limit).all()
    out = [_license_out(l, db) for l in licenses]
    if status:
        out = [l for l in out if l["effective_status"] == status.value]
    return out


@router.get("/licenses/{license_id}")
def get_license(license_id: str, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")
    data = _license_out(lic, db)
    data["devices"] = [{
        "id": d.id, "fingerprint": d.fingerprint, "hostname": d.hostname,
        "os_info": d.os_info, "app_version": d.app_version, "is_active": d.is_active,
        "activated_at": d.activated_at, "last_seen_at": d.last_seen_at,
        "deactivated_at": d.deactivated_at,
    } for d in lic.devices]
    return data


@router.patch("/licenses/{license_id}")
def update_license(license_id: str, body: LicenseUpdate, request: Request,
                    db: Session = Depends(get_db)):
    """Change anything about a licence: plan, expiry, device limit, features,
    or status. Send only the fields you want changed."""
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")

    changes = {}
    for field in ("plan_id", "expires_at", "max_devices", "features_override",
                   "status", "status_reason"):
        value = getattr(body, field)
        if value is not None:
            old = getattr(lic, field)
            if field == "plan_id" and not db.query(Plan).filter(Plan.id == value).first():
                raise HTTPException(404, f"Unknown plan '{value}'.")
            setattr(lic, field, value)
            changes[field] = {"from": str(old), "to": str(value)}

    if changes:
        _audit(db, "license.updated", request, license_id=lic.id,
               customer_id=lic.customer_id, detail=changes)
    db.commit()
    db.refresh(lic)
    return _license_out(lic, db)


@router.post("/licenses/{license_id}/revoke")
def revoke_license(license_id: str, request: Request, reason: str = "",
                    db: Session = Depends(get_db)):
    """Permanent. Use for refunds or abuse. Every device stops working as soon as
    its current offline token expires (or immediately on next check-in)."""
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")
    lic.status = LicenseStatus.REVOKED
    lic.status_reason = reason or "Revoked by owner"
    _audit(db, "license.revoked", request, license_id=lic.id, customer_id=lic.customer_id,
           detail={"reason": lic.status_reason})
    db.commit()
    return {"license_id": lic.id, "status": lic.status.value}


@router.post("/licenses/{license_id}/suspend")
def suspend_license(license_id: str, request: Request, reason: str = "",
                     db: Session = Depends(get_db)):
    """Reversible -- use for payment issues rather than revoking outright."""
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")
    lic.status = LicenseStatus.SUSPENDED
    lic.status_reason = reason or "Suspended by owner"
    _audit(db, "license.suspended", request, license_id=lic.id, customer_id=lic.customer_id,
           detail={"reason": lic.status_reason})
    db.commit()
    return {"license_id": lic.id, "status": lic.status.value}


@router.post("/licenses/{license_id}/reactivate")
def reactivate_license(license_id: str, request: Request, db: Session = Depends(get_db)):
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")
    if lic.status is LicenseStatus.REVOKED:
        # Guard rail: revocation is meant to be final. Forcing an explicit
        # different action avoids undoing a deliberate decision by reflex.
        raise HTTPException(409, (
            "This licence was revoked, which is permanent. Issue a new licence "
            "for this customer instead, or use PATCH to set the status explicitly "
            "if you're certain."))
    lic.status = LicenseStatus.ACTIVE
    lic.status_reason = None
    _audit(db, "license.reactivated", request, license_id=lic.id, customer_id=lic.customer_id)
    db.commit()
    return {"license_id": lic.id, "status": lic.status.value}


@router.post("/licenses/{license_id}/renew")
def renew_license(license_id: str, request: Request, days: int = 365,
                   db: Session = Depends(get_db)):
    """Extends from whichever is later: today, or the current expiry. This means
    renewing early doesn't silently lose the customer their remaining time."""
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")
    base = utcnow()
    current = as_utc(lic.expires_at)
    if current and current > base:
        base = current
    old = lic.expires_at
    lic.expires_at = base + timedelta(days=days)
    if lic.status is LicenseStatus.EXPIRED:
        lic.status = LicenseStatus.ACTIVE
    _audit(db, "license.renewed", request, license_id=lic.id, customer_id=lic.customer_id,
           detail={"from": str(old), "to": str(lic.expires_at), "days": days})
    db.commit()
    return _license_out(lic, db)


# ---------- Devices ----------

@router.get("/devices")
def list_devices(db: Session = Depends(get_db), active_only: bool = False,
                  limit: int = Query(200, le=1000)):
    query = db.query(Device)
    if active_only:
        query = query.filter(Device.is_active.is_(True))
    devices = query.order_by(Device.last_seen_at.desc()).limit(limit).all()
    return [{
        "id": d.id, "license_id": d.license_id, "fingerprint": d.fingerprint,
        "hostname": d.hostname, "os_info": d.os_info, "app_version": d.app_version,
        "is_active": d.is_active, "activated_at": d.activated_at,
        "last_seen_at": d.last_seen_at,
        "customer_email": d.license.customer.email if d.license and d.license.customer else None,
    } for d in devices]


@router.post("/devices/{device_id}/deactivate")
def admin_deactivate_device(device_id: str, request: Request, db: Session = Depends(get_db)):
    """Frees a seat on the customer's behalf -- e.g. they lost a laptop and
    can't release it themselves."""
    dev = db.query(Device).filter(Device.id == device_id).first()
    if not dev:
        raise HTTPException(404, "Device not found.")
    dev.is_active = False
    dev.deactivated_at = utcnow()
    _audit(db, "device.deactivated", request, license_id=dev.license_id,
           device_fingerprint=dev.fingerprint)
    db.commit()
    return {"device_id": dev.id, "is_active": False}


# ---------- Plans ----------

@router.get("/plans")
def list_plans(db: Session = Depends(get_db)):
    return [{"id": p.id, "name": p.name, "features": p.features,
             "default_max_devices": p.default_max_devices, "is_active": p.is_active}
            for p in db.query(Plan).all()]


# ---------- Trials ----------

@router.get("/trials")
def list_trials(db: Session = Depends(get_db), limit: int = Query(200, le=1000)):
    trials = db.query(TrialRecord).order_by(TrialRecord.started_at.desc()).limit(limit).all()
    return [{"id": t.id, "fingerprint": t.fingerprint, "email": t.email,
             "license_id": t.license_id, "started_at": t.started_at,
             "expires_at": t.expires_at,
             "is_expired": as_utc(t.expires_at) < utcnow()}
            for t in trials]


@router.delete("/trials/{trial_id}")
def reset_trial(trial_id: str, request: Request, db: Session = Depends(get_db)):
    """Lets a machine trial again. Genuinely useful: a prospect whose trial
    expired during a holiday, or your own test machines."""
    trial = db.query(TrialRecord).filter(TrialRecord.id == trial_id).first()
    if not trial:
        raise HTTPException(404, "Trial record not found.")
    fp = trial.fingerprint
    db.delete(trial)
    _audit(db, "trial.reset", request, device_fingerprint=fp)
    db.commit()
    return {"reset": True, "fingerprint": fp}


# ---------- Audit ----------

@router.get("/audit")
def audit_log(db: Session = Depends(get_db), license_id: str | None = None,
               action: str | None = None, limit: int = Query(200, le=1000)):
    query = db.query(AuditLog)
    if license_id:
        query = query.filter(AuditLog.license_id == license_id)
    if action:
        query = query.filter(AuditLog.action == action)
    rows = query.order_by(AuditLog.at.desc()).limit(limit).all()
    return [{"at": r.at, "actor": r.actor, "action": r.action, "license_id": r.license_id,
             "customer_id": r.customer_id, "device_fingerprint": r.device_fingerprint,
             "detail": r.detail, "ip_address": r.ip_address} for r in rows]
