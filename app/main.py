"""
Forma Edge Licensing API
========================
Author: Amr Srour

Two surfaces on one service:

  /api/v1/*   -- called by the desktop app and License Manager. No auth header;
                 the activation key IS the credential. Rate-limited by nature of
                 needing a valid key.
  /admin/*    -- owner only. Requires the X-Admin-Key header. Never exposed to
                 customers.

Design rule followed throughout: the CLIENT is never trusted to decide anything.
It reports a fingerprint and a key; the server decides status, seat counts, and
expiry, then hands back a signed token stating the verdict. The app can only
verify and obey that token -- it cannot construct one.
"""
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import engine, get_db, settings
from .models import (
    AuditLog, Base, Customer, Device, License, LicenseStatus, LicenseType,
    Plan, TrialRecord, utcnow,
)
from cryptography.hazmat.primitives import serialization
from .signing import load_private_key, sign_entitlement

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Forma Edge Licensing API", version="1.0.0")

# CORS -- required because the admin dashboard is a static page served from a
# different origin than this API (or opened from disk), so the browser blocks
# its fetch() calls without this. Desktop clients are unaffected either way.
#
# ADMIN_DASHBOARD_ORIGINS should list your real dashboard origin in production,
# e.g. "https://admin.formaedge.com". The "*" default is for local use only:
# it is safe here ONLY because every admin route also requires the X-Admin-Key
# header, so a permissive origin alone grants nothing.
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

_origins = os.environ.get("ADMIN_DASHBOARD_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Helpers
# ============================================================

def _private_key():
    if not settings.LICENSE_PRIVATE_KEY:
        # Fail loudly and early. A server running without a signing key would
        # otherwise appear healthy and only break at the moment a real customer
        # tries to activate.
        raise HTTPException(500, "Server signing key is not configured.")
    return load_private_key(settings.LICENSE_PRIVATE_KEY)


def audit(db: Session, actor: str, action: str, *, license_id=None, customer_id=None,
          fingerprint=None, detail=None, request: Request = None):
    db.add(AuditLog(
        actor=actor, action=action, license_id=license_id, customer_id=customer_id,
        device_fingerprint=fingerprint, detail=detail,
        ip_address=(request.client.host if request and request.client else None),
    ))


def require_admin(x_admin_key: str = Header(None)):
    if not settings.ADMIN_API_KEY:
        raise HTTPException(500, "Admin API key is not configured on the server.")
    if x_admin_key != settings.ADMIN_API_KEY:
        raise HTTPException(401, "Invalid admin credentials.")
    return True


def build_entitlement(lic: License, fingerprint: str) -> dict:
    return {
        "license_id": lic.id,
        "customer_id": lic.customer_id,
        "customer_email": lic.customer.email if lic.customer else None,
        "product": settings.PRODUCT_NAME,
        "edition": lic.plan.name if lic.plan else None,
        "license_type": lic.license_type.value,
        "status": lic.effective_status().value,
        "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
        "features": lic.effective_features,
        "device_fingerprint": fingerprint,
        "max_devices": lic.max_devices,
    }


# ============================================================
# Client-facing schemas
# ============================================================

class ActivateRequest(BaseModel):
    activation_key: str
    fingerprint: str
    hostname: str | None = None
    os_info: str | None = None
    app_version: str | None = None


class ValidateRequest(BaseModel):
    license_id: str
    fingerprint: str
    app_version: str | None = None


class DeactivateRequest(BaseModel):
    license_id: str
    fingerprint: str


class TrialRequest(BaseModel):
    fingerprint: str
    email: EmailStr | None = None
    hostname: str | None = None
    os_info: str | None = None


# ============================================================
# Client endpoints
# ============================================================

@app.post("/api/v1/activate")
def activate(body: ActivateRequest, request: Request, db: Session = Depends(get_db)):
    """Binds a license to a device and returns a signed entitlement token."""
    lic = db.query(License).filter(License.activation_key == body.activation_key.strip()).first()
    if not lic:
        # Deliberately vague: don't confirm whether a key exists, to avoid
        # turning this endpoint into a key-guessing oracle.
        audit(db, "app", "activate.failed", fingerprint=body.fingerprint,
              detail={"reason": "unknown_key"}, request=request)
        db.commit()
        raise HTTPException(404, "That licence key wasn't recognised.")

    status = lic.effective_status()
    if status is LicenseStatus.REVOKED:
        audit(db, "app", "activate.denied", license_id=lic.id, fingerprint=body.fingerprint,
              detail={"reason": "revoked"}, request=request)
        db.commit()
        raise HTTPException(403, "This licence has been revoked. Please contact support.")
    if status is LicenseStatus.SUSPENDED:
        audit(db, "app", "activate.denied", license_id=lic.id, fingerprint=body.fingerprint,
              detail={"reason": "suspended"}, request=request)
        db.commit()
        raise HTTPException(403, "This licence is currently suspended. Please contact support.")
    if status is LicenseStatus.EXPIRED:
        audit(db, "app", "activate.denied", license_id=lic.id, fingerprint=body.fingerprint,
              detail={"reason": "expired"}, request=request)
        db.commit()
        raise HTTPException(403, "This licence has expired. Please renew to continue.")

    device = db.query(Device).filter(
        Device.license_id == lic.id, Device.fingerprint == body.fingerprint).first()

    if device:
        # Re-activating a machine that already has a seat (e.g. user reinstalled)
        # must NOT consume a second seat.
        device.is_active = True
        device.deactivated_at = None
        device.last_seen_at = utcnow()
        device.hostname = body.hostname or device.hostname
        device.app_version = body.app_version or device.app_version
    else:
        active_count = db.query(func.count(Device.id)).filter(
            Device.license_id == lic.id, Device.is_active.is_(True)).scalar()
        if active_count >= lic.max_devices:
            audit(db, "app", "activate.denied", license_id=lic.id, fingerprint=body.fingerprint,
                  detail={"reason": "device_limit", "limit": lic.max_devices}, request=request)
            db.commit()
            raise HTTPException(409, (
                f"This licence is already active on {lic.max_devices} "
                f"device{'s' if lic.max_devices != 1 else ''}. "
                f"Deactivate another device first, or contact support to raise the limit."))
        device = Device(
            license_id=lic.id, fingerprint=body.fingerprint, hostname=body.hostname,
            os_info=body.os_info, app_version=body.app_version,
        )
        db.add(device)

    audit(db, "app", "activate.success", license_id=lic.id, customer_id=lic.customer_id,
          fingerprint=body.fingerprint, request=request)
    db.commit()
    db.refresh(lic)

    token = sign_entitlement(_private_key(), build_entitlement(lic, body.fingerprint),
                              grace_days=settings.OFFLINE_GRACE_DAYS)
    return {"token": token, "license_id": lic.id, "entitlement": build_entitlement(lic, body.fingerprint)}


@app.post("/api/v1/validate")
def validate(body: ValidateRequest, request: Request, db: Session = Depends(get_db)):
    """Periodic check-in. Returns a refreshed token, or an error the app should
    act on. This is how revocation actually reaches a running install."""
    lic = db.query(License).filter(License.id == body.license_id).first()
    if not lic:
        raise HTTPException(404, "Licence not found.")

    device = db.query(Device).filter(
        Device.license_id == lic.id, Device.fingerprint == body.fingerprint).first()
    if not device or not device.is_active:
        # Covers the "owner deactivated this device from admin" case -- the app
        # finds out here and stops working after its current token expires.
        raise HTTPException(403, "This device is no longer activated for this licence.")

    status = lic.effective_status()
    if status is not LicenseStatus.ACTIVE:
        audit(db, "app", "validate.denied", license_id=lic.id, fingerprint=body.fingerprint,
              detail={"status": status.value}, request=request)
        db.commit()
        messages = {
            LicenseStatus.REVOKED: "This licence has been revoked.",
            LicenseStatus.SUSPENDED: "This licence is currently suspended.",
            LicenseStatus.EXPIRED: "This licence has expired.",
        }
        raise HTTPException(403, messages.get(status, "This licence is not active."))

    device.last_seen_at = utcnow()
    device.app_version = body.app_version or device.app_version
    db.commit()
    db.refresh(lic)

    token = sign_entitlement(_private_key(), build_entitlement(lic, body.fingerprint),
                              grace_days=settings.OFFLINE_GRACE_DAYS)
    return {"token": token, "entitlement": build_entitlement(lic, body.fingerprint)}


@app.post("/api/v1/deactivate")
def deactivate(body: DeactivateRequest, request: Request, db: Session = Depends(get_db)):
    """Customer releasing their own seat -- e.g. before wiping a laptop. Frees
    the seat immediately so they can activate elsewhere without contacting you."""
    device = db.query(Device).filter(
        Device.license_id == body.license_id, Device.fingerprint == body.fingerprint).first()
    if not device:
        raise HTTPException(404, "That device isn't activated on this licence.")

    device.is_active = False
    device.deactivated_at = utcnow()
    audit(db, "app", "deactivate.self", license_id=body.license_id,
          fingerprint=body.fingerprint, request=request)
    db.commit()
    return {"deactivated": True}


@app.post("/api/v1/trial/start")
def start_trial(body: TrialRequest, request: Request, db: Session = Depends(get_db)):
    """Starts a 14-day trial for a machine that has never had one.

    Server-side fingerprint record is what makes this real -- reinstalling the
    app, clearing AppData, or using a new email will NOT grant a second trial."""
    existing = db.query(TrialRecord).filter(TrialRecord.fingerprint == body.fingerprint).first()
    if existing:
        audit(db, "app", "trial.denied", fingerprint=body.fingerprint,
              detail={"reason": "already_used", "started_at": str(existing.started_at)},
              request=request)
        db.commit()
        raise HTTPException(409, (
            "A trial has already been used on this computer. "
            "Purchase a licence to continue using Forma Edge."))

    trial_plan = db.query(Plan).filter(Plan.id == "trial").first()
    if not trial_plan:
        raise HTTPException(500, "Trial plan is not configured on the server.")

    # Resolve (or create) the customer record for this trial.
    #
    # The placeholder-email path matters more than it looks: if the owner RESETS
    # a trial and that machine trials again, a naive create would collide with
    # the placeholder customer left over from the first trial and blow up with a
    # unique-constraint error -- meaning a reset trial could never actually be
    # used. So the lookup below covers the placeholder address too, not just
    # user-supplied emails.
    email = body.email or f"trial+{body.fingerprint[:12]}@local.invalid"
    customer = db.query(Customer).filter(Customer.email == email).first()
    if not customer:
        customer = Customer(email=email, name="Trial user")
        db.add(customer)
        db.flush()

    expires = utcnow() + timedelta(days=settings.TRIAL_DAYS)
    lic = License(
        customer_id=customer.id, plan_id=trial_plan.id,
        license_type=LicenseType.TRIAL, status=LicenseStatus.ACTIVE,
        expires_at=expires, max_devices=1,
    )
    db.add(lic)
    db.flush()

    db.add(Device(license_id=lic.id, fingerprint=body.fingerprint,
                   hostname=body.hostname, os_info=body.os_info))
    db.add(TrialRecord(fingerprint=body.fingerprint, email=body.email,
                        license_id=lic.id, expires_at=expires))
    audit(db, "app", "trial.started", license_id=lic.id, customer_id=customer.id,
          fingerprint=body.fingerprint, request=request)
    db.commit()
    db.refresh(lic)

    token = sign_entitlement(_private_key(), build_entitlement(lic, body.fingerprint),
                              grace_days=min(settings.OFFLINE_GRACE_DAYS, settings.TRIAL_DAYS))
    return {"token": token, "license_id": lic.id, "expires_at": expires.isoformat(),
            "entitlement": build_entitlement(lic, body.fingerprint)}


@app.get("/api/v1/public-key")
def public_key():
    """Serves the PEM public half of the signing keypair. Deliberately
    unauthenticated -- this is the public half by definition, safe to hand to
    anyone. Exists so sync_signing_key.py can fetch it directly instead of a
    human copying a PEM block by hand into the app's source."""
    if not settings.LICENSE_PRIVATE_KEY:
        raise HTTPException(500, "Server signing key is not configured.")
    private_key = load_private_key(settings.LICENSE_PRIVATE_KEY)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"public_key_pem": public_pem.decode()}


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "product": settings.PRODUCT_NAME}


# ============================================================
# Admin routes -- mounted last, auth enforced for every route in the router
# ============================================================
from .admin import router as admin_router  # noqa: E402

app.include_router(admin_router, dependencies=[Depends(require_admin)])

# Stripe webhook -- NOT admin-protected: Stripe authenticates itself by signing
# the payload, which the route verifies. An admin key here would be pointless
# (Stripe cannot send one) and would break the integration.
from .payments import router as payments_router  # noqa: E402

app.include_router(payments_router)
