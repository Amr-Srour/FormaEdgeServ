"""
Forma Edge Licensing -- Database Models
=======================================
Author: Amr Srour

Schema design notes:

- Licenses are never hard-deleted. State transitions only (see LicenseStatus).
  A revoked license must remain in the DB so the app can be TOLD it's revoked;
  deleting the row would make the app fall back to "unknown license" which is a
  different (and less clear) error for the customer.

- Devices are rows, not a counter. A counter can't tell you WHICH machine to
  deactivate when a customer says "I replaced my laptop", and can drift out of
  sync. One row per machine, deactivated in place.

- Trials are tracked by machine fingerprint in their own table, SEPARATE from
  licenses. This is deliberate: a trial must survive the user deleting their
  local files. If trial state lived only on the client, uninstall/reinstall
  would reset the 14 days forever. Server-side fingerprint record prevents that.

- audit_log is append-only. Every state change writes a row. This is what makes
  "why is this customer's license not working?" answerable six months later.
"""
import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, String, Text, JSON, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(dt: datetime | None):
    """Normalises a datetime read back from the database to timezone-aware UTC.

    Necessary because storage backends differ: PostgreSQL with TIMESTAMPTZ
    returns aware datetimes, but SQLite (and TIMESTAMP columns generally) return
    NAIVE ones. Comparing a naive to an aware datetime raises TypeError in
    Python -- which, in an expiry check, means a crash instead of an access
    decision. Everything this system stores is UTC, so attaching UTC to a naive
    value is correct rather than a guess."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def new_id(prefix: str) -> str:
    """Human-readable IDs. When a customer emails "my license LIC-3F2A81 won't
    activate", you can find it instantly -- far better than a raw UUID."""
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


class LicenseStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"       # past expiry date; may be renewed back to ACTIVE
    SUSPENDED = "SUSPENDED"   # temporary, reversible (e.g. payment issue)
    REVOKED = "REVOKED"       # permanent, deliberate (e.g. refund, abuse)


class LicenseType(str, enum.Enum):
    SUBSCRIPTION = "SUBSCRIPTION"  # has expiry, renewable
    PERPETUAL = "PERPETUAL"        # no expiry
    TRIAL = "TRIAL"                # time-boxed, machine-bound, not renewable


class Customer(Base):
    __tablename__ = "customers"

    id = Column(String, primary_key=True, default=lambda: new_id("CUS"))
    email = Column(String, nullable=False, unique=True, index=True)
    name = Column(String, nullable=True)
    company = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    licenses = relationship("License", back_populates="customer", cascade="all, delete-orphan")


class Plan(Base):
    """Editions (Trial / Professional / Enterprise). A license references a plan
    rather than duplicating a feature list per license -- so changing what
    'Professional' includes updates every Professional license at once."""
    __tablename__ = "plans"

    id = Column(String, primary_key=True)          # e.g. "professional"
    name = Column(String, nullable=False)          # e.g. "Professional"
    features = Column(JSON, nullable=False, default=list)
    default_max_devices = Column(Integer, nullable=False, default=1)
    is_active = Column(Boolean, nullable=False, default=True)


class License(Base):
    __tablename__ = "licenses"

    id = Column(String, primary_key=True, default=lambda: new_id("LIC"))

    # The secret the CUSTOMER actually types to activate. Deliberately separate
    # from `id`: the id is short and quotable in support emails ("license
    # LIC-3F2A81 is suspended"), while this is long and random so knowing an id
    # never lets anyone activate. Never show this in logs or error messages.
    activation_key = Column(String, nullable=False, unique=True, index=True,
                             default=lambda: f"FE-{uuid.uuid4().hex.upper()}{uuid.uuid4().hex[:8].upper()}")

    customer_id = Column(String, ForeignKey("customers.id"), nullable=False, index=True)
    plan_id = Column(String, ForeignKey("plans.id"), nullable=False)

    license_type = Column(Enum(LicenseType), nullable=False, default=LicenseType.SUBSCRIPTION)
    status = Column(Enum(LicenseStatus), nullable=False, default=LicenseStatus.ACTIVE, index=True)

    starts_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # NULL = perpetual

    max_devices = Column(Integer, nullable=False, default=1)

    # Per-license feature override. NULL means "use the plan's features".
    # Exists so you can grant one customer an extra feature without inventing
    # a whole new plan for them.
    features_override = Column(JSON, nullable=True)

    # Why a license was suspended/revoked -- shown to you in admin, never to the
    # customer (they get a generic message; the detail is for your records).
    status_reason = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    customer = relationship("Customer", back_populates="licenses")
    plan = relationship("Plan")
    devices = relationship("Device", back_populates="license", cascade="all, delete-orphan")

    @property
    def effective_features(self):
        if self.features_override is not None:
            return self.features_override
        return self.plan.features if self.plan else []

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return as_utc(self.expires_at) < utcnow()

    def effective_status(self) -> LicenseStatus:
        """Computed status. A license can be stored ACTIVE but be past its expiry
        date -- we never want a stale stored value to be the source of truth for
        an access decision, so expiry is evaluated at read time."""
        if self.status in (LicenseStatus.REVOKED, LicenseStatus.SUSPENDED):
            return self.status
        if self.is_expired():
            return LicenseStatus.EXPIRED
        return self.status


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        # Same machine can't occupy two seats on one license.
        UniqueConstraint("license_id", "fingerprint", name="uq_license_fingerprint"),
    )

    id = Column(String, primary_key=True, default=lambda: new_id("DEV"))
    license_id = Column(String, ForeignKey("licenses.id"), nullable=False, index=True)

    fingerprint = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=True)     # so you can tell devices apart in admin
    os_info = Column(String, nullable=True)
    app_version = Column(String, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True)
    activated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    deactivated_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    license = relationship("License", back_populates="devices")


class TrialRecord(Base):
    """One row per machine that has EVER started a trial.

    Deliberately not tied to a customer or email: the whole point is to stop the
    same machine starting a fresh 14 days repeatedly under new emails. The
    fingerprint is the identity here."""
    __tablename__ = "trial_records"

    id = Column(String, primary_key=True, default=lambda: new_id("TRL"))
    fingerprint = Column(String, nullable=False, unique=True, index=True)
    email = Column(String, nullable=True)        # captured if offered, not required
    license_id = Column(String, ForeignKey("licenses.id"), nullable=True)
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    """Append-only. Never updated, never deleted."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    actor = Column(String, nullable=False)        # "admin", "app", "system"
    action = Column(String, nullable=False, index=True)
    license_id = Column(String, nullable=True, index=True)
    customer_id = Column(String, nullable=True, index=True)
    device_fingerprint = Column(String, nullable=True)
    detail = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
