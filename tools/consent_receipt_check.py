#!/usr/bin/env python3
"""Validate an AI-agent payment consent receipt (structure + integrity, no crypto).

A consent receipt is the human-authorized record that SHOULD accompany an
AI-agent-initiated payment: who authorized what, for what purpose, up to what
cap, until when. This checker is deterministic and offline. It validates
structure, scope/cap consistency, expiry, nonce, and content integrity (SHA-256
over a canonical serialization). It does NOT verify cryptographic signatures,
contact a chain, sign, settle, or move funds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

SCHEMA_VERSION = 1
_SCOPE_RE = re.compile(r"^[a-zA-Z0-9_]{1,64}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_RESERVED_KEYS = ("content_sha256", "signatures")

# Well-known NIP-47 / NWC capability scopes. Unknown-but-syntactically-valid
# scopes are allowed and reported as a warning, not an error, because the scope
# vocabulary is still evolving.
KNOWN_SCOPES = {
    "pay_invoice",
    "pay_keysend",
    "get_balance",
    "get_info",
    "make_invoice",
    "lookup_invoice",
    "list_transactions",
    "sign_message",
}

# Reference types that describe artifacts produced by the interaction the grant
# authorizes (receipts, settlements, trails, payments, attestations, decisions).
# A consent grant is issued BEFORE that interaction, so it cannot reference
# them; those artifacts bind back to the consent instead. Present as a forward
# reference, they are a temporal error and are reported as a warning (not a
# flag, to stay compatible with older fixtures) — the reference direction is
# documented in the spec.
_FORWARD_REFERENCE_TYPES = {
    "air_receipt",
    "authz_attestation",
    "risk_decision",
    "settlement_receipt",
    "settlement_tx",
    "trail_record",
    "x402_payment",
}


def _check(checks: list[dict[str, str]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if passed else "review", "detail": detail})


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty ISO-8601 timestamp")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _parse_money(value: object, field: str) -> Decimal:
    """Parse a money value to an exact ``Decimal``.

    The canonical form is a **decimal string** (float-free, so the canonical
    body and its digest never depend on IEEE-754 rounding). Integers are
    accepted for backward compatibility; JSON floats are accepted but the
    caller reports them as a deprecation warning.
    """
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative decimal string")
    if isinstance(value, str):
        if not value.strip():
            raise ValueError(f"{field} must be a non-negative decimal string")
        try:
            number = Decimal(value.strip())
        except InvalidOperation as exc:
            raise ValueError(f"{field} must be a non-negative decimal string") from exc
    elif isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError(f"{field} must be a non-negative decimal string")
        number = Decimal(str(value))
    else:
        raise ValueError(f"{field} must be a non-negative decimal string")
    if number < 0:
        raise ValueError(f"{field} must be a non-negative decimal string")
    return number


def canonical_bytes(receipt: dict) -> bytes:
    """Return the JCS (RFC 8785) canonical serialization of the receipt body.

    This is the exact byte string whose SHA-256 is ``content_sha256`` and which
    the authorizer signs. ``content_sha256`` and ``signatures`` are excluded so
    the digest covers the authorization facts, not the fields that wrap them.

    Canonicalization — RFC 8785 "JSON Canonicalization Scheme":
      * UTF-8 output, no insignificant whitespace.
      * Object keys sorted by Unicode code point.
      * Strings: escape only ``"``, ``\\`` and U+0000..U+001F (short escapes
        ``\\b \\t \\n \\f \\r``, otherwise ``\\u00xx``); every other character,
        including non-ASCII, is emitted verbatim.
      * Numbers: the consent schema is float-free by construction (money is
        decimal strings; the only numeric types are non-negative integers
        ``schema_version``/``chain_id``), so integer serialization is plain
        decimal with no leading zeros — identical to JCS.

    For the types this schema permits, Python's ``json.dumps(sort_keys=True,
    separators=(",", ":"), ensure_ascii=False)`` is byte-identical to RFC 8785.
    """
    body = {key: value for key, value in receipt.items() if key not in _RESERVED_KEYS}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_receipt(receipt: object, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    flags: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []

    if not isinstance(receipt, dict):
        return {
            "status": "invalid",
            "flags": ["receipt_must_be_object"],
            "warnings": [],
            "checks": [{"name": "receipt-object", "status": "review", "detail": "input is not a JSON object"}],
        }

    # schema version
    if receipt.get("schema_version") != SCHEMA_VERSION:
        flags.append("schema_version_mismatch")
        _check(checks, "schema-version", False, f"expected integer {SCHEMA_VERSION}")
    else:
        _check(checks, "schema-version", True, f"schema_version is {SCHEMA_VERSION}")

    # agent and authorizer identities
    agent = receipt.get("agent")
    authorizer = receipt.get("authorizer")
    if not isinstance(agent, str) or not agent.strip():
        flags.append("agent_missing")
        _check(checks, "agent-identity", False, "agent must be a non-empty string")
    else:
        _check(checks, "agent-identity", True, "agent identity present")
    if not isinstance(authorizer, str) or not authorizer.strip():
        flags.append("authorizer_missing")
        _check(checks, "authorizer-identity", False, "authorizer must be a non-empty string")
    else:
        _check(checks, "authorizer-identity", True, "authorizer identity present")
    if isinstance(agent, str) and isinstance(authorizer, str) and agent and authorizer and agent == authorizer:
        flags.append("agent_equals_authorizer")
        _check(checks, "distinct-identities", False, "agent and authorizer must differ")
    else:
        _check(checks, "distinct-identities", True, "agent and authorizer are distinct")

    # scope
    scope = receipt.get("scope")
    if not isinstance(scope, list) or not scope or not all(isinstance(s, str) for s in scope):
        flags.append("scope_invalid")
        _check(checks, "scope", False, "scope must be a non-empty list of strings")
    else:
        bad = [s for s in scope if not _SCOPE_RE.fullmatch(s)]
        if bad:
            flags.append("scope_syntax_invalid")
            _check(checks, "scope", False, f"invalid scope token(s): {', '.join(bad)}")
        else:
            unknown = sorted(set(scope) - KNOWN_SCOPES)
            if unknown:
                warnings.append(f"unrecognized scope(s), accepted as valid syntax: {', '.join(unknown)}")
            _check(checks, "scope", True, f"{len(scope)} scope(s), least-privilege list required")

    # amount and cap — exact decimal-string money (float-free canonical form).
    try:
        amount = _parse_money(receipt.get("amount"), "amount")
        amount_cap = _parse_money(receipt.get("amount_cap"), "amount_cap")
        if isinstance(receipt.get("amount"), float) or isinstance(receipt.get("amount_cap"), float):
            warnings.append("amount/amount_cap as JSON floats is deprecated — use decimal strings so the canonical body and digest are float-free")
        if amount > amount_cap:
            flags.append("amount_exceeds_cap")
            _check(checks, "amount-within-cap", False, "amount exceeds amount_cap")
        else:
            _check(checks, "amount-within-cap", True, "amount is within amount_cap")
    except ValueError as exc:
        flags.append("amount_invalid")
        _check(checks, "amount-within-cap", False, str(exc))

    # asset and chain
    asset = receipt.get("asset")
    if not isinstance(asset, str) or not asset.strip():
        flags.append("asset_missing")
        _check(checks, "asset", False, "asset must be a non-empty string")
    else:
        _check(checks, "asset", True, "asset present")
    chain_id = receipt.get("chain_id")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        flags.append("chain_id_invalid")
        _check(checks, "chain-id", False, "chain_id must be an integer")
    else:
        _check(checks, "chain-id", True, f"chain_id {chain_id}")

    # expiry
    try:
        expires = _parse_timestamp(receipt.get("expires_at"), "expires_at")
        if expires <= now:
            flags.append("expired")
            _check(checks, "expiry", False, "receipt has already expired")
        else:
            _check(checks, "expiry", True, "receipt is unexpired")
    except ValueError as exc:
        flags.append("expiry_invalid")
        _check(checks, "expiry", False, str(exc))

    # issued_at — OPTIONAL signing/issuance timestamp. Present to give the
    # receipt a precedence anchor (an AIR authorizations[] binding maps its
    # `precedence` axis to this field); absent, the authorizer signature is
    # the only existence anchor and precedence cannot be declared.
    issued_at = receipt.get("issued_at")
    if issued_at is None:
        _check(checks, "issued-at", True, "no issued_at (precedence axis undeclarable)")
    else:
        try:
            issued = _parse_timestamp(issued_at, "issued_at")
            if issued > now:
                flags.append("issued_at_in_future")
                _check(checks, "issued-at", False, "issued_at must not be in the future")
            elif "expires_at" in receipt and issued >= _parse_timestamp(receipt["expires_at"], "expires_at"):
                flags.append("issued_at_not_before_expiry")
                _check(checks, "issued-at", False, "issued_at must precede expires_at")
            else:
                _check(checks, "issued-at", True, "issued_at present and consistent with expiry")
        except ValueError as exc:
            flags.append("issued_at_invalid")
            _check(checks, "issued-at", False, str(exc))

    # nonce
    nonce = receipt.get("nonce")
    if not isinstance(nonce, str) or not nonce.strip():
        flags.append("nonce_missing")
        _check(checks, "nonce", False, "nonce must be a non-empty string")
    else:
        _check(checks, "nonce", True, "nonce present")

    # purpose
    purpose = receipt.get("purpose")
    if not isinstance(purpose, str) or not purpose.strip():
        flags.append("purpose_missing")
        _check(checks, "purpose", False, "purpose must be a non-empty human-readable string")
    else:
        _check(checks, "purpose", True, "purpose present")

    # references — optional binding to PRIOR artifacts (a governing policy, a
    # parent capability grant, a trust anchor) that existed before this grant
    # was issued. The proof-of-delivery records the grant authorizes (AIR
    # receipt, settlement, trail, payment) are produced AFTER it and bind BACK
    # to it on their own side — they are never referenced here.
    references = receipt.get("references")
    if references is None:
        _check(checks, "references", True, "no external references (standalone grant)")
    elif not isinstance(references, list) or not references:
        flags.append("references_invalid")
        _check(checks, "references", False, "references, if present, must be a non-empty list")
    else:
        malformed = 0
        for ref in references:
            if not isinstance(ref, dict):
                malformed += 1
                continue
            if not isinstance(ref.get("type"), str) or not ref["type"].strip():
                malformed += 1
            if not isinstance(ref.get("id"), str) or not ref["id"].strip():
                malformed += 1
            digest = ref.get("content_sha256")
            if digest is not None and (not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest)):
                malformed += 1
        if malformed:
            flags.append("references_invalid")
            _check(checks, "references", False, f"{malformed} reference(s) missing type/id or with a malformed digest")
        else:
            forward = sorted({r.get("type") for r in references if isinstance(r, dict) and r.get("type") in _FORWARD_REFERENCE_TYPES})
            if forward:
                warnings.append(
                    f"forward reference(s) {forward}: a consent grant is issued before the interaction it "
                    "authorizes, so it cannot reference the receipts that result — those bind back to this consent"
                )
            _check(checks, "references", True, f"{len(references)} reference(s) bound to this consent (prior artifacts only)")

    # content integrity
    declared = receipt.get("content_sha256")
    if not isinstance(declared, str) or not _SHA256_RE.fullmatch(declared):
        flags.append("content_integrity_missing")
        _check(checks, "content-integrity", False, "content_sha256 must be a 64-hex-char SHA-256 digest")
    else:
        actual = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
        if actual != declared.lower():
            flags.append("content_integrity_mismatch")
            _check(checks, "content-integrity", False, "declared digest does not match canonical body")
        else:
            _check(checks, "content-integrity", True, "content digest matches canonical body")

    # signatures — the core gap this spec exists to close. The authorizer
    # signature may be (a) an opaque non-empty string (legacy placeholder) or
    # (b) a really-signed object `{alg, public_key, signature}` produced by
    # `tools/sign_consent_receipt.py`. Cryptographic verification of (b) is
    # available through that tool; this checker stays dependency-free and
    # verifies presence/shape only.
    signatures = receipt.get("signatures")
    if not isinstance(signatures, dict):
        flags.append("authorizer_signature_missing")
        _check(checks, "authorizer-signature", False, "no signatures object; receipt is unsigned")
    else:
        auth = signatures.get("authorizer")
        if isinstance(auth, str) and auth.strip():
            _check(checks, "authorizer-signature", True, "authorizer signature present (opaque string; not cryptographically verified)")
            warnings.append("authorizer signature is an opaque string — a really-signed instance carries {alg, public_key, signature} (see tools/sign_consent_receipt.py)")
        elif isinstance(auth, dict) and auth.get("alg") and auth.get("public_key") and auth.get("signature"):
            _check(checks, "authorizer-signature", True, f"authorizer signature present ({auth.get('alg')}); verify with tools/sign_consent_receipt.py")
        else:
            flags.append("authorizer_signature_missing")
            _check(checks, "authorizer-signature", False, "authorizer signature is missing or malformed")

    status = "ready-for-human-review" if not flags else "review-candidate"
    return {
        "schema_version": receipt.get("schema_version"),
        "status": status,
        "flag_count": len(flags),
        "flags": flags,
        "warnings": warnings,
        "checks": checks,
        "signature_verification": "out-of-scope",
    }


def render_text(report: dict) -> str:
    lines = [
        f"Consent receipt: status={report['status']} flags={report['flag_count']}",
        "Flags: " + (", ".join(report["flags"]) if report["flags"] else "none"),
    ]
    if report["warnings"]:
        lines.append("Warnings: " + "; ".join(report["warnings"]))
    lines.append("Checks:")
    lines.extend(f"- {check['name']}: {check['status']} ({check['detail']})" for check in report["checks"])
    lines.append("Cryptographic signature verification is out of scope for this checker.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path, help="JSON consent receipt fixture")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--fail-on", choices=("review", "never"), default="never")
    args = parser.parse_args(argv)
    try:
        report = validate_receipt(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 1 if args.fail_on == "review" and report["flag_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
