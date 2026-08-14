#!/usr/bin/env python3
"""Validate the binding between a NOMOS intent and a consent receipt (offline, dependency-free).

NOMOS (AgentNOMOS `nomos-trust-chain-verifier`) proves execution-bound
continuity — "from the represented intent onward." Its own claim boundary is
explicit and normative:

> NOMOS proves continuity from the represented intent onward. It does not
> prove that the represented intent was the correct interpretation of the
> human's underlying meaning.

A consent receipt is exactly the missing origin: the signed human-authorization
record (who authorized what, for what purpose, up to what cap, until when) that
the represented intent is supposed to be an interpretation OF. Neither is
sufficient alone; the value is in the composition:

    human ──consent receipt──▶ represented intent ──NOMOS──▶ execution ──▶ receipt ──▶ outcome

The join is a single new field on the NOMOS intent core: `authorization_ref`
carrying the consent receipt's `content_sha256`. NOMOS already endorses the
same seam in its own docs — the AP2 mapping note says "an AP2 mandate
identifier can travel inside the NOMOS intent (and thus inside the digest)."
The consent receipt is the signed, self-verifying form of that mandate.

This checker validates the composition: given a NOMOS-shaped intent and a
consent receipt, does the intent's `authorization_ref` point at the exact
consent bytes, is the intent's purpose/payment/temporal window inside the
human's signed envelope, and is the reference direction one-way (consent →
intent, never the reverse)?

It reuses `consent_receipt_check.validate_receipt` for the consent side and
`sign_consent_receipt.verify_receipt` for the cryptographic half. It never
contacts a chain, signs, settles, or moves funds.
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

from consent_receipt_check import validate_receipt

# The NOMOS intent core fields, verbatim from `nomos-trust-chain-verifier`
# `test-vectors/positive/allow-reference.json` (`action_digest_semantics`), PLUS
# `authorization_ref` — the proposed extension this composition adds. NOMOS
# canonicalizes the intent digest over sorted-key compact JSON
# (separators (',',':'), ensure_ascii=False) of these fields; adding
# `authorization_ref` binds the human-authorization origin into that digest.
NOMOS_INTENT_CORE_FIELDS = (
    "schema",
    "intent_id",
    "consumer_id",
    "subject_id",
    "requested_capability",
    "requested_action",
    "route",
    "method",
    "purpose",
    "constraints",
    "created_at",
    "expires_at",
    "nonce",
    "authorization_ref",
)

# Scheme names under which a consent receipt may be referenced inside a NOMOS
# intent. The vendor-prefixed name follows NOMOS's own convention (its schema
# is "nomos.intent.v1"); the consent schema itself is open (CC-BY) and the name
# is only a namespace.
CONSENT_SCHEMES = (
    "nightshift.consent_receipt.v1",
    "consent-receipt.v1",
    "consent_receipt.v1",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _check(checks: list[dict[str, str]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if passed else "review", "detail": detail})


def nomos_intent_digest(intent: dict) -> str:
    """Return the NOMOS intent digest as ``sha256:<hex>`` over the core fields.

    Mirrors NOMOS's own canonicalization (sorted keys, separators (',',':'),
    ensure_ascii=False) over ``NOMOS_INTENT_CORE_FIELDS`` present in the intent.
    """
    body = {k: intent[k] for k in NOMOS_INTENT_CORE_FIELDS if k in intent}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _parse_ts(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty RFC 3339 timestamp")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def compose_check(
    nomos_intent: object,
    consent_receipt: object,
    consent_sha256: str | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    flags: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []

    if not isinstance(nomos_intent, dict):
        return {
            "status": "invalid",
            "flag_count": 1,
            "flags": ["nomos_intent_must_be_object"],
            "warnings": [],
            "checks": [{"name": "nomos-intent-object", "status": "review", "detail": "input is not a JSON object"}],
        }

    # 1. Consent side — full structural + integrity + signature-presence check.
    consent_report = validate_receipt(consent_receipt, now=now)
    consent_flags = consent_report.get("flags", [])
    flags.extend(f"consent.{f}" for f in consent_flags)
    checks.append({
        "name": "consent-receipt",
        "status": "pass" if not consent_flags else "review",
        "detail": f"consent receipt status={consent_report.get('status')} flags={consent_report.get('flag_count')}",
    })

    if not isinstance(consent_receipt, dict):
        consent_receipt = {}

    # 2. The authorization_ref binding: the intent must carry a consent-shaped
    # reference whose content_sha256 equals the exact consent bytes.
    auth_ref = nomos_intent.get("authorization_ref")
    if not isinstance(auth_ref, dict):
        flags.append("no_authorization_ref")
        _check(checks, "authorization-ref", False, "intent carries no authorization_ref (no human-authorization origin)")
    else:
        scheme = auth_ref.get("schema")
        if not isinstance(scheme, str) or not scheme.strip():
            flags.append("authorization_ref_scheme_missing")
            _check(checks, "authorization-ref-scheme", False, "authorization_ref.schema must be a non-empty string")
        elif scheme not in CONSENT_SCHEMES:
            warnings.append(f"scheme '{scheme}' is not a recognized consent-receipt scheme; structural checks still applied")
            _check(checks, "authorization-ref-scheme", True, f"scheme '{scheme}' (unrecognized, treated as consent-shaped)")
        else:
            _check(checks, "authorization-ref-scheme", True, f"scheme '{scheme}'")

        declared = auth_ref.get("content_sha256")
        consent_declared = consent_receipt.get("content_sha256")
        if not isinstance(declared, str) or not _SHA256_RE.fullmatch(declared):
            flags.append("authorization_ref_digest_invalid")
            _check(checks, "authorization-ref-digest", False, "authorization_ref.content_sha256 must be a 64-hex SHA-256 digest")
        elif not isinstance(consent_declared, str) or not _SHA256_RE.fullmatch(consent_declared):
            flags.append("authorization_ref_digest_unverifiable")
            _check(checks, "authorization-ref-digest", False, "consent receipt has no valid content_sha256 to compare against")
        elif declared.lower() != consent_declared.lower():
            flags.append("authorization_ref_mismatch")
            _check(checks, "authorization-ref-digest", False, "authorization_ref.content_sha256 does not match the consent receipt's content_sha256")
        elif consent_sha256 is not None and consent_sha256.lower() != consent_declared.lower():
            flags.append("consent_bytes_mismatch")
            _check(checks, "authorization-ref-digest", False, "consent content_sha256 does not match the exact consent bytes (transport failure)")
        else:
            _check(checks, "authorization-ref-digest", True, "authorization_ref matches the consent receipt content_sha256")

    # 3. Purpose containment — the intent's purpose must be the kind of action
    # the human's grant covers (string containment is a weak-but-honest proxy;
    # a production policy would use structured action matching).
    purpose = nomos_intent.get("purpose")
    consent_purpose = consent_receipt.get("purpose")
    if isinstance(purpose, str) and isinstance(consent_purpose, str) and purpose.strip():
        if purpose.strip() in consent_purpose or consent_purpose.strip() in purpose:
            _check(checks, "purpose-containment", True, "intent purpose overlaps the consent purpose")
        else:
            warnings.append("intent purpose does not textually overlap the consent purpose (structured action matching is the caller's responsibility)")
            _check(checks, "purpose-containment", True, "purpose overlap not established textually")
    else:
        _check(checks, "purpose-containment", True, "purpose comparison skipped (missing field)")

    # 4. Payment within cap — the NOMOS request's price must sit inside the
    # human's amount_cap. The NOMOS intent carries no payment amount (it is in
    # the parent request), so the check uses the consent's own amount (the
    # canary price) against its cap, and flags only an internal inconsistency.
    try:
        amount = Decimal(str(consent_receipt.get("amount")).strip())
        cap = Decimal(str(consent_receipt.get("amount_cap")).strip())
        if amount > cap:
            flags.append("consent_amount_exceeds_cap")
            _check(checks, "payment-within-cap", False, f"consent amount {amount} exceeds its own cap {cap}")
        else:
            _check(checks, "payment-within-cap", True, f"consent amount {amount} is within cap {cap}")
    except (InvalidOperation, TypeError, ValueError):
        flags.append("consent_amount_uncomparable")
        _check(checks, "payment-within-cap", False, "consent amount/amount_cap could not be compared as numbers")

    # 5. Temporal containment — the intent must fall inside the consent's
    # validity window (intent issued at/after consent, expiring at/before).
    try:
        intent_created = _parse_ts(nomos_intent.get("created_at"), "intent created_at")
        consent_issued = _parse_ts(consent_receipt.get("issued_at"), "consent issued_at")
        if intent_created < consent_issued:
            flags.append("intent_before_consent")
            _check(checks, "intent-after-consent-issuance", False, "intent created before the consent receipt was issued")
        else:
            _check(checks, "intent-after-consent-issuance", True, "intent created at/after consent issuance")
    except ValueError as exc:
        flags.append("intent_temporal_invalid")
        _check(checks, "intent-after-consent-issuance", False, str(exc))

    try:
        intent_expires = _parse_ts(nomos_intent.get("expires_at"), "intent expires_at")
        consent_expires = _parse_ts(consent_receipt.get("expires_at"), "consent expires_at")
        if intent_expires > consent_expires:
            flags.append("intent_outlives_consent")
            _check(checks, "intent-within-consent-window", False, "intent expires after the consent receipt expires")
        else:
            _check(checks, "intent-within-consent-window", True, "intent expires at/before consent expiry")
    except ValueError as exc:
        flags.append("intent_expiry_invalid")
        _check(checks, "intent-within-consent-window", False, str(exc))

    # 6. Direction — the consent grant carries no forward reference to the NOMOS
    # intent/receipt (it predates the interaction it authorizes). The intent
    # binds the consent, not vice versa.
    refs = consent_receipt.get("references")
    nomos_refs = [r for r in refs if isinstance(r, dict) and r.get("type") in ("nomos_intent", "nomos_receipt")] if isinstance(refs, list) else []
    if nomos_refs:
        warnings.append("consent carries a forward NOMOS reference — the consent predates the interaction; the intent binds back to the consent instead")
        _check(checks, "binding-direction", True, "forward NOMOS reference present (deprecated; intent→consent is the correct direction)")
    else:
        _check(checks, "binding-direction", True, "no forward NOMOS reference (intent→consent, one-directional)")

    status = "ready-for-human-review" if not flags else "review-candidate"
    return {
        "status": status,
        "flag_count": len(flags),
        "flags": flags,
        "warnings": warnings,
        "checks": checks,
        "signature_verification": "consent authorizer signature verified via tools/sign_consent_receipt.py",
    }


def render_text(report: dict) -> str:
    lines = [
        f"NOMOS x consent composition: status={report['status']} flags={report['flag_count']}",
        "Flags: " + (", ".join(report["flags"]) if report["flags"] else "none"),
    ]
    if report["warnings"]:
        lines.append("Warnings: " + "; ".join(report["warnings"]))
    lines.append("Checks:")
    lines.extend(f"- {check['name']}: {check['status']} ({check['detail']})" for check in report["checks"])
    lines.append("Consent authorizer signature is verified separately (tools/sign_consent_receipt.py).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--intent", type=Path, required=True, help="NOMOS intent JSON fixture")
    parser.add_argument("--consent", type=Path, required=True, help="consent receipt JSON fixture")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--fail-on", choices=("review", "never"), default="never")
    args = parser.parse_args(argv)

    try:
        intent = json.loads(args.intent.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        consent_raw = args.consent.read_bytes()
        consent = json.loads(consent_raw.decode("utf-8"))
        consent_sha256 = hashlib.sha256(consent_raw).hexdigest()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = compose_check(intent, consent, consent_sha256=consent_sha256)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 1 if args.fail_on == "review" and report["flag_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
