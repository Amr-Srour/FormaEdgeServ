"""
Forma Edge Licensing -- Token Signing
=====================================
Author: Amr Srour

The server issues SIGNED ENTITLEMENT TOKENS, not bare license keys.

Why this matters for offline support: the desktop app cannot phone home on
every launch (engineering sites have bad connectivity, and a licensing server
outage must not stop paying customers from working). So the app needs to make
an access decision locally, from a file on disk -- which means that file must be
tamper-proof. A signed token is: the app verifies the signature with a public
key baked into the exe, and if a single byte was edited, verification fails.

The private key NEVER leaves the server. An attacker with the exe has only the
public key, which can verify but not forge.

Tokens carry their own short expiry (`not_after`) independent of the license
expiry. That's the offline grace period: a token good for 14 days means the app
works offline for up to 14 days, then must re-check in. So a revoked license
stops working within the grace window even if the machine never came online
again -- without the app needing a live connection every launch.
"""
import base64
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    """Run ONCE. Private key goes in the server's environment; public key gets
    baked into the desktop app."""
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(pem: str | bytes) -> Ed25519PrivateKey:
    if isinstance(pem, str):
        pem = pem.encode()
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(pem: str | bytes) -> Ed25519PublicKey:
    if isinstance(pem, str):
        pem = pem.encode()
    return serialization.load_pem_public_key(pem)


def sign_entitlement(private_key: Ed25519PrivateKey, payload: dict,
                      grace_days: int = 14) -> str:
    """Returns a signed token string: base64(payload).base64(signature)

    `not_after` is stamped in here -- the app refuses a token past this even if
    the signature is valid, which is what bounds offline use."""
    body = dict(payload)
    body["issued_at"] = datetime.now(timezone.utc).isoformat()
    body["not_after"] = (datetime.now(timezone.utc) + timedelta(days=grace_days)).isoformat()

    payload_bytes = json.dumps(body, sort_keys=True, default=str).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    return (base64.urlsafe_b64encode(payload_bytes).decode() + "." +
            base64.urlsafe_b64encode(signature).decode())


def verify_entitlement(public_key: Ed25519PublicKey, token: str) -> dict:
    """Verifies signature AND token freshness. Raises ValueError with a
    user-facing reason on failure.

    This same function is what ships inside the desktop app -- kept here so the
    server can verify its own tokens in tests, guaranteeing the two never drift
    apart."""
    try:
        payload_b64, sig_b64 = token.strip().split(".")
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        signature = base64.urlsafe_b64decode(sig_b64)
    except Exception:
        raise ValueError("Malformed licence token.")

    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        raise ValueError("Licence token failed verification -- it may have been altered.")

    payload = json.loads(payload_bytes)

    not_after = payload.get("not_after")
    if not_after:
        if datetime.fromisoformat(not_after) < datetime.now(timezone.utc):
            raise ValueError("Licence token has gone stale -- reconnect to refresh it.")

    return payload
