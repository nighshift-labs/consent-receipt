#!/usr/bin/env python3
"""Validate the binding between an AIR entry and a consent receipt (offline, dependency-free).

AIR (Agent Interaction Receipt — `crisnovillo1991/agent-receipt-spec`) is the
machine-to-machine proof-of-delivery layer: request digest, response digest,
payment, chain position. A consent receipt is the human-authorization layer:
who authorized what, for what purpose, up to what cap, until when. Neither is
sufficient alone; the value is in the composition.

This checker validates that composition: given an AIR entry and a consent
receipt, does the AIR entry correctly bind to the consent receipt via the
first-class `authorizations[]` field (AIR v0.3 draft §2) or the v0.2
`meta.authorization` extension point (AIR v0.2 §9), and is the payment inside
the human's signed consent envelope?

It reuses `consent_receipt_check.validate_receipt` for the consent side and
adds the binding-side checks. It does NOT verify AIR's own Ed25519 signature
or JCS entry hash — that is the AIR verifier's job, and this module stays
dependency-free. It never contacts a chain, signs, settles, or moves funds.
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

# Scheme names under which a consent receipt may be bound in an AIR
# authorizations[] element. The vendor-prefixed name follows AIR's own
# convention (e.g. `invinoveritas.verdict_proof.v1`); the schema itself is
# open (CC-BY) and the name is only a namespace.
CONSENT_SCHEMES = (
    "nightshift.consent_receipt.v1",
    "consent-receipt.v1",
    "consent_receipt.v1",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_DECISION_REF_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$", re.IGNORECASE)

# The three epistemic axes every bound artifact MUST declare (§2.4). "Was this
# authorized" is not a fourth axis — it is what the artifact IS, and `scheme`
# names it. All three keys must be present; an absent key is a different
# canonical form and a different entry hash.
_AXIS_KEYS = ("precedence", "freshness", "correctness")


def _check(checks: list[dict[str, str]], name: str, passed: bool, detail: str) -> None:
    checks.append({"name": name, "status": "pass" if passed else "review", "detail": detail})


def _normalize_decision_ref(ref: object) -> str | None:
    if not isinstance(ref, str):
        return None
    match = _DECISION_REF_RE.fullmatch(ref.strip())
    return match.group(1).lower() if match else None


def find_consent_bindings(air_entry: object) -> list[dict]:
    """Return every consent-receipt-shaped binding object in an AIR entry.

    Covers the v0.3 `authorizations[]` array and the v0.2 `meta.authorization`
    extension point. Bindings for other artifact classes (verdicts, trust
    snapshots) are skipped.
    """
    bindings: list[dict] = []
    if not isinstance(air_entry, dict):
        return bindings
    auths = air_entry.get("authorizations")
    if isinstance(auths, list):
        for binding in auths:
            if isinstance(binding, dict):
                bindings.append(binding)
    meta = air_entry.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("authorization"), dict):
        bindings.append(meta["authorization"])
    return bindings


def _binding_checks(
    binding: dict,
    consent: dict,
    consent_sha256: str | None,
    checks: list[dict[str, str]],
    flags: list[str],
    warnings: list[str],
) -> None:
    scheme = binding.get("scheme")
    if not isinstance(scheme, str) or not scheme.strip():
        flags.append("binding_scheme_missing")
        _check(checks, "binding-scheme", False, "binding scheme must be a non-empty string")
    elif scheme not in CONSENT_SCHEMES:
        warnings.append(f"scheme '{scheme}' is not a recognized consent-receipt scheme; structural checks still applied")
        _check(checks, "binding-scheme", True, f"scheme '{scheme}' (unrecognized, treated as consent-shaped)")
    else:
        _check(checks, "binding-scheme", True, f"scheme '{scheme}'")

    # decision_ref must equal the consent receipt's own content address.
    decision_ref = _normalize_decision_ref(binding.get("decision_ref"))
    declared_content = consent.get("content_sha256")
    if decision_ref is None:
        flags.append("binding_decision_ref_invalid")
        _check(checks, "binding-decision-ref", False, "decision_ref must be a 64-hex digest (optional 'sha256:' prefix)")
    elif not isinstance(declared_content, str) or not _SHA256_RE.fullmatch(declared_content):
        flags.append("binding_decision_ref_unverifiable")
        _check(checks, "binding-decision-ref", False, "consent receipt has no valid content_sha256 to compare against")
    elif decision_ref != declared_content.lower():
        flags.append("binding_decision_ref_mismatch")
        _check(checks, "binding-decision-ref", False, "decision_ref does not match the consent receipt's content_sha256")
    else:
        _check(checks, "binding-decision-ref", True, "decision_ref matches consent content_sha256")

    # authorization_sha256 — the bytes the binding party verified at bind time.
    auth_sha = binding.get("authorization_sha256")
    if not isinstance(auth_sha, str) or not _SHA256_RE.fullmatch(auth_sha):
        flags.append("binding_authorization_sha256_invalid")
        _check(checks, "binding-authorization-sha256", False, "authorization_sha256 must be a 64-hex SHA-256 digest")
    elif consent_sha256 is None:
        _check(checks, "binding-authorization-sha256", True, "authorization_sha256 well-formed (byte comparison not requested)")
    elif auth_sha.lower() != consent_sha256.lower():
        flags.append("binding_authorization_sha256_mismatch")
        _check(checks, "binding-authorization-sha256", False, "authorization_sha256 does not match the exact consent bytes (transport failure)")
    else:
        _check(checks, "binding-authorization-sha256", True, "authorization_sha256 matches the exact consent bytes")

    # transport / retrieval pointer shape.
    transport = binding.get("transport_hint")
    if transport is None:
        _check(checks, "binding-transport", True, "no transport_hint (not required to be present)")
    elif transport not in ("raw_url", "relay_event", "bundle", "onchain", "other"):
        flags.append("binding_transport_invalid")
        _check(checks, "binding-transport", False, f"transport_hint '{transport}' is not a recognized value")
    else:
        _check(checks, "binding-transport", True, f"transport_hint '{transport}'")

    # trust_model + authority_ref (draft-2 common core). `verifier_key_ref` is
    # the draft-1 name, accepted as a deprecated alias during migration.
    trust_model = binding.get("trust_model")
    if trust_model is None:
        warnings.append("binding has no trust_model; draft-2 requires it (issuer_signed|qtsp_qualified|chain_anchored)")
        _check(checks, "binding-trust-model", True, "trust_model absent (draft-1 shape accepted during migration)")
    elif trust_model not in ("issuer_signed", "qtsp_qualified", "chain_anchored"):
        flags.append("binding_trust_model_invalid")
        _check(checks, "binding-trust-model", False, f"trust_model '{trust_model}' is not a recognized value")
    else:
        _check(checks, "binding-trust-model", True, f"trust_model '{trust_model}'")

    # authority_ref — identification/discovery, never an authority claim (§2.6).
    authority_ref = binding.get("authority_ref", binding.get("verifier_key_ref"))
    if authority_ref is not None and (not isinstance(authority_ref, str) or not authority_ref.strip()):
        flags.append("binding_authority_ref_invalid")
        _check(checks, "binding-authority-ref", False, "authority_ref, if present, must be a non-empty string")
    elif binding.get("authority_ref") is None and binding.get("verifier_key_ref") is not None:
        warnings.append("verifier_key_ref is the draft-1 name; draft-2 renames it authority_ref")
        _check(checks, "binding-authority-ref", True, "authority_ref present (via legacy verifier_key_ref)")
    else:
        _check(checks, "binding-authority-ref", True, "authority_ref present" if authority_ref else "no authority_ref (key discovery deferred)")

    # axes — the three epistemic axes (§2.4). All three keys MUST be present.
    # "Was this authorized" is not a fourth axis: it is what the artifact IS,
    # and `scheme` names it.
    axes = binding.get("axes")
    if not isinstance(axes, dict):
        flags.append("binding_axes_missing")
        _check(checks, "binding-axes", False, "axes declaration object is required")
    else:
        missing_axes = [k for k in _AXIS_KEYS if k not in axes]
        if missing_axes:
            flags.append("binding_axes_incomplete")
            _check(checks, "binding-axes", False, f"axes missing required key(s): {missing_axes} (§2.4: all three keys MUST be present)")
        else:
            _check(checks, "binding-axes", True, "all three axes declared (precedence/freshness/correctness)")
        if "authorization" in axes:
            warnings.append("axes carries an 'authorization' key — not a §2.4 axis; authorization is what the artifact is, named by scheme")
        # freshness encoding — relative cadence or absolute deadline.
        freshness = axes.get("freshness")
        if isinstance(freshness, dict):
            has_relative = "observed_at_field" in freshness and "max_age_field" in freshness
            has_absolute = "expires_at_field" in freshness
            if has_absolute:
                _check(checks, "binding-freshness", True, "freshness uses {expires_at_field} (absolute deadline — the consent-receipt form)")
            elif has_relative:
                _check(checks, "binding-freshness", True, "freshness uses {observed_at_field, max_age_field} (relative cadence)")
            else:
                warnings.append("freshness axis shape is not a recognized computable encoding")


def compose_check(
    air_entry: object,
    consent_receipt: object,
    consent_sha256: str | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    flags: list[str] = []
    warnings: list[str] = []
    checks: list[dict[str, str]] = []

    if not isinstance(air_entry, dict):
        return {
            "status": "invalid",
            "flag_count": 1,
            "flags": ["air_entry_must_be_object"],
            "warnings": [],
            "checks": [{"name": "air-entry-object", "status": "review", "detail": "AIR entry is not a JSON object"}],
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

    # 2. Binding side.
    bindings = find_consent_bindings(air_entry)
    if not bindings:
        flags.append("no_consent_binding")
        _check(checks, "binding-present", False, "AIR entry carries no authorizations[]/meta.authorization binding to a consent receipt")
    else:
        _check(checks, "binding-present", True, f"{len(bindings)} binding object(s) found")
        for index, binding in enumerate(bindings):
            _binding_checks(binding, consent_receipt, consent_sha256, checks, flags, warnings)

    # 3. Payment inside the consent envelope.
    payment = air_entry.get("payment")
    if not isinstance(payment, dict) or not payment:
        _check(checks, "payment-coherence", True, "no payment on this entry (free/unpaid call); nothing to bound to a cap")
    else:
        _payment_coherence(payment, consent_receipt, air_entry, checks, flags, warnings, now)

    # 4. Direction — the consent grant carries no forward reference to the AIR
    # entry (it predates the interaction it authorizes). The AIR entry binds
    # the consent, not vice versa.
    refs = consent_receipt.get("references")
    air_refs = [r for r in refs if isinstance(r, dict) and r.get("type") == "air_receipt"] if isinstance(refs, list) else []
    if air_refs:
        warnings.append("consent carries a forward air_receipt reference — the consent predates the interaction; the AIR entry binds back to the consent instead")
        _check(checks, "binding-direction", True, "forward air_receipt reference present (deprecated; AIR→consent is the correct direction)")
    else:
        _check(checks, "binding-direction", True, "no forward air_receipt reference (AIR→consent, one-directional)")

    status = "ready-for-human-review" if not flags else "review-candidate"
    return {
        "status": status,
        "flag_count": len(flags),
        "flags": flags,
        "warnings": warnings,
        "checks": checks,
        "signature_verification": "out-of-scope",
    }


def _payment_coherence(
    payment: dict,
    consent: dict,
    air_entry: dict,
    checks: list[dict[str, str]],
    flags: list[str],
    warnings: list[str],
    now: datetime,
) -> None:
    # Asset match (case-insensitive).
    pay_asset = payment.get("asset")
    con_asset = consent.get("asset")
    if isinstance(pay_asset, str) and isinstance(con_asset, str) and pay_asset.strip().lower() == con_asset.strip().lower():
        _check(checks, "payment-asset", True, f"payment asset '{pay_asset}' matches consent asset '{con_asset}'")
    else:
        flags.append("payment_asset_mismatch")
        _check(checks, "payment-asset", False, f"payment asset '{pay_asset}' does not match consent asset '{con_asset}'")

    # Amount within cap — a binding-coherence predicate (field-table doc §4).
    # Both specs differ on unit semantics (AIR uses atomic units as a decimal
    # string; the consent receipt uses whole units as a decimal string), so
    # unit normalization is the caller's responsibility — this compares the raw
    # decimal values exactly and flags only an unambiguous over-cap.
    try:
        pay_amount = Decimal(str(payment.get("amount")).strip())
        cap = Decimal(str(consent.get("amount_cap")).strip())
        if pay_amount > cap:
            flags.append("payment_exceeds_consent_cap")
            _check(checks, "payment-within-cap", False, f"payment amount {pay_amount} exceeds consent cap {cap}")
        else:
            _check(checks, "payment-within-cap", True, f"payment amount {pay_amount} is within consent cap {cap}")
            warnings.append("amount compared as raw decimal values; atomic-unit vs whole-unit normalization is the caller's responsibility")
    except (InvalidOperation, TypeError, ValueError):
        flags.append("payment_amount_uncomparable")
        _check(checks, "payment-within-cap", False, "payment.amount and/or consent amount_cap could not be compared as numbers")

    # Temporal: the paid interaction must fall inside the consent's validity window.
    issued_raw = air_entry.get("issued_at")
    try:
        issued = _parse_ts(issued_raw, "air issued_at")
        expires = _parse_ts(consent.get("expires_at"), "consent expires_at")
        if expires <= issued:
            flags.append("payment_after_consent_expiry")
            _check(checks, "payment-within-validity", False, "AIR entry issued after the consent receipt expired")
        else:
            _check(checks, "payment-within-validity", True, "AIR entry issued before consent expiry")
        con_issued_raw = consent.get("issued_at")
        if con_issued_raw is not None:
            con_issued = _parse_ts(con_issued_raw, "consent issued_at")
            if issued < con_issued:
                flags.append("payment_before_consent_issuance")
                _check(checks, "payment-after-consent-issuance", False, "AIR entry issued before the consent receipt was issued")
            else:
                _check(checks, "payment-after-consent-issuance", True, "AIR entry issued at/after consent issuance")
    except ValueError as exc:
        flags.append("payment_temporal_invalid")
        _check(checks, "payment-within-validity", False, str(exc))


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


def render_text(report: dict) -> str:
    lines = [
        f"AIR x consent composition: status={report['status']} flags={report['flag_count']}",
        "Flags: " + (", ".join(report["flags"]) if report["flags"] else "none"),
    ]
    if report["warnings"]:
        lines.append("Warnings: " + "; ".join(report["warnings"]))
    lines.append("Checks:")
    lines.extend(f"- {check['name']}: {check['status']} ({check['detail']})" for check in report["checks"])
    lines.append("AIR signature / JCS entry-hash verification is out of scope for this checker.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--air", type=Path, required=True, help="AIR entry JSON fixture")
    parser.add_argument("--consent", type=Path, required=True, help="consent receipt JSON fixture")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--fail-on", choices=("review", "never"), default="never")
    args = parser.parse_args(argv)

    try:
        air_raw = args.air.read_bytes()
        air_entry = json.loads(air_raw.decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        consent_raw = args.consent.read_bytes()
        consent_receipt = json.loads(consent_raw.decode("utf-8"))
        consent_sha256 = hashlib.sha256(consent_raw).hexdigest()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = compose_check(air_entry, consent_receipt, consent_sha256=consent_sha256)
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return 1 if args.fail_on == "review" and report["flag_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
