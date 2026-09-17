"""
Forma Edge Licensing -- Payments
================================
Author: Amr Srour

Stripe webhook. When a customer completes checkout, this issues a real licence
in the database and emails them the activation key -- no manual step.

This lives INSIDE the licensing backend rather than as a separate serverless
function, because it needs the same database and the same licence-creation
logic. Splitting it out would mean duplicating both.

SETUP
-----
1. Create a Payment Link (or Checkout) in the Stripe dashboard.

2. In Stripe > Developers > Webhooks, add an endpoint pointing at:
       https://<your-server>/payments/stripe-webhook
   Subscribe it to: checkout.session.completed

3. Environment variables:
       STRIPE_SECRET_KEY        sk_live_... (or sk_test_... while testing)
       STRIPE_WEBHOOK_SECRET    whsec_...  (from the webhook page)
       RESEND_API_KEY           for sending the licence email
       LICENSE_FROM_EMAIL       e.g. "Forma Edge <licence@formaedge.com>"

4. Map your Stripe Price IDs to plans in STRIPE_PRICE_TO_PLAN below, so buying
   the Enterprise price issues an Enterprise licence.

IDEMPOTENCY: Stripe retries webhooks on any non-2xx response, and can deliver
the same event more than once. Issuing a duplicate licence for one payment
would be a real (if minor) financial mess, so every event id is recorded and
replays are ignored.
"""
import os
from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .config import get_db, settings
from .models import AuditLog, Customer, License, LicenseStatus, LicenseType, Plan, utcnow

router = APIRouter(prefix="/payments", tags=["payments"])

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
LICENSE_FROM_EMAIL = os.environ.get("LICENSE_FROM_EMAIL", "Forma Edge <licence@formaedge.com>")

# Stripe Price ID -> (plan_id, duration_days, max_devices)
# duration_days None = perpetual.
STRIPE_PRICE_TO_PLAN = {
    # "price_1AbCdEfGhIjKlMn": ("professional", 365, 1),
    # "price_2XyZ...":         ("enterprise",   365, 5),
}

DEFAULT_PURCHASE = ("professional", 365, 1)


def _send_license_email(to_email: str, activation_key: str, plan_name: str,
                         expires_at) -> bool:
    """Best-effort. A failure here must NOT fail the webhook -- the licence is
    already created, and failing would make Stripe retry and risk duplicates.
    The key is always recoverable from the admin dashboard."""
    if not RESEND_API_KEY:
        return False
    try:
        import requests
        expiry_line = (f"Valid until: {expires_at:%d %B %Y}" if expires_at
                       else "This licence does not expire.")
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                     "Content-Type": "application/json"},
            json={
                "from": LICENSE_FROM_EMAIL,
                "to": [to_email],
                "subject": "Your Forma Edge licence key",
                "text": (
                    "Thanks for purchasing Forma Edge.\n\n"
                    f"Edition: {plan_name}\n{expiry_line}\n\n"
                    f"Your licence key:\n{activation_key}\n\n"
                    "To get started:\n"
                    "  1. Download Forma Edge and run it\n"
                    "  2. Paste the key above into the Activation screen and click Activate\n"
                    "  3. Sign in with your own Autodesk account\n\n"
                    "Your licence activates on the machine you enter it on. If you move to a "
                    "new computer, deactivate the old one from inside the app first, then "
                    "enter the same key on the new machine.\n"
                ),
            },
            timeout=15,
        )
        return resp.status_code < 300
    except Exception:
        return False


@router.post("/stripe-webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None),
                          db: Session = Depends(get_db)):
    payload = await request.body()

    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(500, "Stripe webhook secret is not configured.")

    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe library is not installed on the server.")

    try:
        event = stripe.Webhook.construct_event(payload, stripe_signature, STRIPE_WEBHOOK_SECRET)
    except Exception:
        # Covers both a malformed body and a bad signature. Never distinguish
        # them in the response -- that would help an attacker probe the endpoint.
        raise HTTPException(400, "Invalid webhook signature.")

    if event["type"] != "checkout.session.completed":
        return {"ignored": event["type"]}

    event_id = event["id"]

    # Idempotency: Stripe retries, and duplicate delivery is normal. The audit
    # log doubles as the processed-event ledger, so no extra table is needed.
    already = db.query(AuditLog).filter(
        AuditLog.action == "payment.license_issued",
        AuditLog.detail.isnot(None),
    ).all()
    for row in already:
        if isinstance(row.detail, dict) and row.detail.get("stripe_event_id") == event_id:
            return {"status": "already_processed", "license_id": row.license_id}

    session = event["data"]["object"]
    email = (session.get("customer_details") or {}).get("email")
    if not email:
        raise HTTPException(400, "Checkout session had no customer email.")

    # Work out what they bought.
    plan_id, duration_days, max_devices = DEFAULT_PURCHASE
    try:
        line_items = session.get("line_items", {}).get("data", [])
        if line_items:
            price_id = line_items[0].get("price", {}).get("id")
            if price_id in STRIPE_PRICE_TO_PLAN:
                plan_id, duration_days, max_devices = STRIPE_PRICE_TO_PLAN[price_id]
    except Exception:
        pass  # fall back to the default purchase rather than failing the sale

    plan = db.query(Plan).filter(Plan.id == plan_id).first()
    if not plan:
        raise HTTPException(500, f"Plan '{plan_id}' is not configured on the server.")

    customer = db.query(Customer).filter(Customer.email == email).first()
    if not customer:
        customer = Customer(email=email,
                             name=(session.get("customer_details") or {}).get("name"))
        db.add(customer)
        db.flush()

    lic = License(
        customer_id=customer.id, plan_id=plan.id,
        license_type=LicenseType.SUBSCRIPTION if duration_days else LicenseType.PERPETUAL,
        status=LicenseStatus.ACTIVE,
        expires_at=(utcnow() + timedelta(days=duration_days)) if duration_days else None,
        max_devices=max_devices or plan.default_max_devices,
    )
    db.add(lic)
    db.flush()

    emailed = _send_license_email(email, lic.activation_key, plan.name, lic.expires_at)

    db.add(AuditLog(
        actor="system", action="payment.license_issued",
        license_id=lic.id, customer_id=customer.id,
        detail={"stripe_event_id": event_id, "email": email, "plan": plan.id,
                "amount_total": session.get("amount_total"),
                "currency": session.get("currency"), "emailed": emailed},
    ))
    db.commit()

    # Always 200 once the licence exists, even if the email failed -- otherwise
    # Stripe retries and we issue the licence twice.
    return {"status": "issued", "license_id": lic.id, "emailed": emailed}
