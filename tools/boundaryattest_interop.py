#!/usr/bin/env python3
"""BoundaryAttest Interop Profile v0.1 <-> consent-receipt bridge.

BoundaryAttest's interop-receipt (cullenmeyers/BoundaryAttest,
docs/schemas/interop-receipt-v0.1.schema.json) proves ACTION provenance: a
signer attested "action X happened with result R, and it has not changed." Its
own profile doc lists "authorization, grant, or policy validity" as a
policy-layer check it deliberately does NOT perform.

The consent receipt (`consent_receipt_check.py` + `sign_consent_receipt.py`)
proves AUTHORIZATION: a human signed a grant of amount/cap/purpose/expiry
before the payment fired.

This module composes the two. It:

  * implements BoundaryAttest v0.1's canonical claim bytes (`stableJson`),
  * signs/verifies a v0.1 receipt (Ed25519 + `sha256:<spki-der>` key id),
  * and checks the binding `claim.authorization_ref == content_sha256` of a
    consent grant, plus a scope/cap/expiry containment predicate.

Because `claim` allows additional properties, `authorization_ref` is a
zero-breaking drop-in: it lives inside the signed claim, so it inherits the
receipt's signature, and it is a plain digest pointer so the two formats'
different canonicalizations (stableJson vs RFC 8785 JCS) never mix — each side
verifies only its own bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Synthetic "server" signer seed for reproducible fixtures (distinct from the
# synthetic human-authorizer key in sign_consent_receipt.py). Never sign real
# receipts with this.
SYNTHETIC_SERVER_SEED = hashlib.sha256(
    b"nightshift-labs synthetic BoundaryAttest server key (test fixtures only)"
).digest()

AUTHORIZATION_REF = "authorization_ref"


def stable_json(value: object) -> bytes:
    """BoundaryAttest v0.1 canonical claim bytes.

    Their profile: "Encode JSON primitives compactly as JSON, preserve array
    order, and recursively sort object member names with the current JavaScript
    comparator ``a.localeCompare(b)``, with no insignificant whitespace."

    All defined field names are lowercase ASCII snake_case, and
    ``localeCompare`` is lexicographic on ASCII, so Python's ``sort_keys``
    (code-point order) is identical for every field the profile defines. Adapter
    extensions using non-ASCII keys would need the locale-aware comparator.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def spki_public_key_id(public_key: Ed25519PublicKey) -> str:
    """BoundaryAttest v0.1 ``public_key_id`` = sha256 over the DER SPKI bytes."""
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(der).hexdigest()


def compose_receipt(claim: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign a BoundaryAttest v0.1 claim and return the full receipt envelope."""
    pub = private_key.public_key()
    signature = private_key.sign(stable_json(claim))
    return {
        "claim": claim,
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_id": spki_public_key_id(pub),
    }


def verify_receipt(receipt: dict, public_key: Ed25519PublicKey) -> tuple[bool, str]:
    """Verify a BoundaryAttest v0.1 receipt envelope.

    Returns ``(ok, detail)``. Checks the key id, then the Ed25519 signature over
    the canonical claim — the same precedence the profile's shared verifier uses
    (key identifier before signature).
    """
    if not isinstance(receipt, dict):
        return False, "invalid_receipt: not an object"
    claim = receipt.get("claim")
    signature = receipt.get("signature")
    key_id = receipt.get("public_key_id")
    if not isinstance(claim, dict):
        return False, "claim_not_object"
    if not isinstance(signature, str) or not signature:
        return False, "invalid_signature: missing signature"
    if not isinstance(key_id, str):
        return False, "invalid_receipt: missing public_key_id"
    if key_id != spki_public_key_id(public_key):
        return False, "public_key_id_mismatch"
    try:
        raw = base64.b64decode(signature, validate=True)
    except Exception:  # noqa: BLE001 - base64 binascii error
        return False, "invalid_signature: signature is not standard base64"
    try:
        public_key.verify(raw, stable_json(claim))
    except InvalidSignature:
        return False, "invalid_signature: does not verify over the canonical claim"
    return True, "valid ed25519 signature over the canonical claim"


def _grant_expired(grant: dict, now: datetime) -> bool:
    expires = grant.get("expires_at")
    if not isinstance(expires, str):
        return True
    try:
        parsed = datetime.fromisoformat(expires.strip().replace("Z", "+00:00"))
    except ValueError:
        return True
    if parsed.tzinfo is None:
        return True
    return parsed.astimezone(timezone.utc) <= now


def check_authorization_binding(
    interop_receipt: dict,
    public_key: Ed25519PublicKey,
    consent_grant: dict,
    now: datetime | None = None,
) -> dict:
    """Verify both halves and confirm the action stayed inside the grant.

    Returns a report dict: ``ok`` (bool), ``interop`` (bool), ``grant`` (bool),
    ``binding`` (bool), ``contained`` (bool), and a human ``detail``.
    """
    now = now or datetime.now(timezone.utc)
    interop_ok, interop_detail = verify_receipt(interop_receipt, public_key)
    grant_ok, grant_detail = _grant_signature_ok(consent_grant)
    claim = interop_receipt.get("claim") if isinstance(interop_receipt, dict) else {}

    declared_ref = claim.get(AUTHORIZATION_REF)
    grant_digest = consent_grant.get("content_sha256") if isinstance(consent_grant, dict) else None
    binding = (
        isinstance(declared_ref, str)
        and isinstance(grant_digest, str)
        and declared_ref.lower() == grant_digest.lower()
    )

    contained = False
    contain_detail = "not evaluated"
    if binding and isinstance(consent_grant, dict):
        scope = consent_grant.get("scope") or []
        action = claim.get("action_type")
        in_scope = isinstance(action, str) and action in scope
        within_cap = _amount_within_cap(consent_grant)
        unexpired = not _grant_expired(consent_grant, now)
        contained = in_scope and within_cap and unexpired
        parts = []
        parts.append(f"action {action!r} " + ("in" if in_scope else "NOT in") + " grant scope")
        parts.append("amount within cap" if within_cap else "amount exceeds cap (or malformed)")
        parts.append("grant unexpired" if unexpired else "grant expired")
        contain_detail = "; ".join(parts)

    ok = interop_ok and grant_ok and binding and contained
    return {
        "ok": ok,
        "interop": interop_ok,
        "interop_detail": interop_detail,
        "grant": grant_ok,
        "grant_detail": grant_detail,
        "binding": binding,
        "contained": contained,
        "contain_detail": contain_detail,
    }


def _grant_signature_ok(grant: dict) -> tuple[bool, str]:
    from sign_consent_receipt import verify_receipt as verify_grant

    if not isinstance(grant, dict):
        return False, "grant is not an object"
    return verify_grant(grant)


def _amount_within_cap(grant: dict) -> bool:
    from decimal import Decimal, InvalidOperation

    try:
        amount = Decimal(str(grant.get("amount")))
        cap = Decimal(str(grant.get("amount_cap")))
    except (InvalidOperation, ValueError):
        return False
    return amount <= cap
