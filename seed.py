"""
Forma Edge Licensing -- First-time setup
========================================
Author: Amr Srour

Run once against a fresh database:
    python seed.py

Creates the default plans and, if no signing keypair exists yet, generates one
and prints both halves with instructions on where each goes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import engine, SessionLocal
from app.models import Base, Plan
from app.signing import generate_keypair

DEFAULT_PLANS = [
    {
        "id": "trial", "name": "Trial",
        "features": ["files_log", "issues", "members", "activity_log", "midp", "health_check"],
        "default_max_devices": 1,
    },
    {
        "id": "professional", "name": "Professional",
        "features": ["files_log", "issues", "members", "add_members", "activity_log",
                      "midp", "health_check", "forma_attributes", "dashboard"],
        "default_max_devices": 1,
    },
    {
        "id": "enterprise", "name": "Enterprise",
        "features": ["files_log", "issues", "members", "add_members", "activity_log",
                      "midp", "health_check", "forma_attributes", "dashboard",
                      "bulk_onboarding", "api_access"],
        "default_max_devices": 5,
    },
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        created = []
        for spec in DEFAULT_PLANS:
            if not db.query(Plan).filter(Plan.id == spec["id"]).first():
                db.add(Plan(**spec))
                created.append(spec["id"])
        db.commit()
        print(f"Plans created: {created or 'none (already present)'}")
    finally:
        db.close()

    if not os.environ.get("LICENSE_PRIVATE_KEY"):
        private_pem, public_pem = generate_keypair()
        print("\n" + "=" * 68)
        print("NO SIGNING KEY FOUND -- generated a new pair.")
        print("=" * 68)
        print("\n1. Set this as the LICENSE_PRIVATE_KEY environment variable on your")
        print("   server. Keep it secret; it never goes in the desktop app.\n")
        print(private_pem.decode())
        print("2. Paste this public key into the desktop app's source as")
        print("   LICENSE_PUBLIC_KEY_PEM, then rebuild the exe.\n")
        print(public_pem.decode())


if __name__ == "__main__":
    main()
