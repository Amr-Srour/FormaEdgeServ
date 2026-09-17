"""
Forma Edge Licensing -- Configuration
====================================
Author: Amr Srour

Everything secret comes from environment variables, never from a file in the
repo. On a deployed host you set these in the platform's dashboard.
"""
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class Settings:
    # PostgreSQL in production. Falls back to a local SQLite file so the backend
    # can be run and tested without a database server -- the SQLAlchemy models
    # are identical either way.
    DATABASE_URL: str = os.environ.get(
        "DATABASE_URL", "sqlite:///./forma_edge_licensing.db"
    )

    # Ed25519 private key PEM for signing entitlement tokens.
    LICENSE_PRIVATE_KEY: str = os.environ.get("LICENSE_PRIVATE_KEY", "")

    # Shared secret for the admin API. The owner tools send this as a header.
    ADMIN_API_KEY: str = os.environ.get("ADMIN_API_KEY", "")

    # How long an issued entitlement token stays valid offline before the app
    # must check in again. Business decision -- 14 days balances site-office
    # connectivity reality against how fast a revocation takes effect.
    OFFLINE_GRACE_DAYS: int = int(os.environ.get("OFFLINE_GRACE_DAYS", "14"))

    TRIAL_DAYS: int = int(os.environ.get("TRIAL_DAYS", "14"))

    PRODUCT_NAME: str = "Forma Edge"


settings = Settings()

_connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=_connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
