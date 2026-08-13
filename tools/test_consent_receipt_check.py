#!/usr/bin/env python3
"""Focused tests for the agent-payment consent receipt checker."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone

from consent_receipt_check import canonical_bytes, validate_receipt


def _receipt(**overrides):
    base = {
        "schema_version": 1,
        "agent": "agent-pubkey-abc123",
        "authorizer": "human-pubkey-xyz789",
        "scope": ["pay_invoice", "get_balance"],
        "asset": "USDC",
        "chain_id": 8453,
        "amount": "5.00",
        "amount_cap": "50.00",
        "purpose": "Pay 5 USDC for a one-time data look-up on Base.",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "nonce": "nonce-0001",
        "signatures": {"authorizer": _REAL_SIG},
    }
    base.update(overrides)
    # Attach a correct content digest for the final body.
    body = {k: v for k, v in base.items() if k not in ("content_sha256", "signatures")}
    # RFC 8785 (JCS) canonical form: sorted keys, compact separators,
    # non-ASCII emitted verbatim (ensure_ascii=False).
    base["content_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return base


_REAL_SIG = {
    "alg": "ed25519",
    "public_key": "3d8998727276cc1d60b08eec034865f692962822fd499d0a7b8f532ff222a0da",
    "signature": "cd" * 64,
}


class ValidReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_clean(self):
        report = validate_receipt(_receipt())
        self.assertEqual(report["status"], "ready-for-human-review")
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(all(c["status"] == "pass" for c in report["checks"]))

    def test_canonical_hash_excludes_reserved_keys(self):
        base = _receipt(signatures={"authorizer": "aaaa"})
        a = dict(base)
        b = dict(base)
        b["signatures"] = {"authorizer": "bbbb"}
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))

    def test_unknown_scope_is_warning_not_error(self):
        report = validate_receipt(_receipt(scope=["pay_invoice", "custom_scope"]))
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any("unrecognized scope" in w for w in report["warnings"]))

    def test_references_bind_prior_artifact_cleanly(self):
        receipt = _receipt(references=[{
            "type": "policy",
            "id": "org-payment-policy-v3",
            "content_sha256": "ab" * 32,
        }])
        report = validate_receipt(receipt)
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any(c["name"] == "references" and c["status"] == "pass" for c in report["checks"]))

    def test_forward_reference_warns(self):
        # A consent grant predates the interaction it authorizes, so an
        # air_receipt reference is a forward reference and must be surfaced.
        receipt = _receipt(references=[{"type": "air_receipt", "id": "air-8f2a1c"}])
        report = validate_receipt(receipt)
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any("forward reference" in w for w in report["warnings"]))

    def test_all_forward_reference_types_warn(self):
        # Every produced-after type is a forward reference — including the
        # attestation and decision records added after the AIR direction fix.
        for t in (
            "air_receipt",
            "authz_attestation",
            "risk_decision",
            "settlement_receipt",
            "settlement_tx",
            "trail_record",
            "x402_payment",
        ):
            report = validate_receipt(_receipt(references=[{"type": t, "id": "x"}]))
            self.assertEqual(report["flag_count"], 0, t)
            self.assertTrue(any("forward reference" in w for w in report["warnings"]), t)

    def test_float_money_warns(self):
        receipt = _receipt(amount=5.0, amount_cap=50.0)
        report = validate_receipt(receipt)
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any("float" in w and "decimal" in w for w in report["warnings"]))

    def test_standalone_receipt_without_references_is_clean(self):
        report = validate_receipt(_receipt())
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any(c["name"] == "references" and c["status"] == "pass" for c in report["checks"]))

    def test_reference_missing_id_is_flagged(self):
        receipt = _receipt(references=[{"type": "settlement_tx"}])
        report = validate_receipt(receipt)
        self.assertIn("references_invalid", report["flags"])

    def test_reference_bad_digest_is_flagged(self):
        receipt = _receipt(references=[{"type": "air_receipt", "id": "x", "content_sha256": "not-a-sha256"}])
        report = validate_receipt(receipt)
        self.assertIn("references_invalid", report["flags"])

    def test_references_included_in_content_digest(self):
        a = _receipt(references=[{"type": "air_receipt", "id": "air-1"}])
        b = _receipt(references=[{"type": "air_receipt", "id": "air-2"}])
        self.assertNotEqual(canonical_bytes(a), canonical_bytes(b))

    def test_settlement_trail_fixture_is_standalone_clean(self):
        fixture = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt" / "receipt-with-settlement-trail-reference.json"
        receipt = json.loads(fixture.read_text(encoding="utf-8"))
        # A grant predates the settlement/trail it authorizes, so the fixture is
        # standalone (no forward references) and validates clean.
        report = validate_receipt(receipt)
        self.assertEqual(report["flag_count"], 0, report)
        self.assertTrue(any(c["name"] == "references" and c["status"] == "pass" for c in report["checks"]))
        self.assertTrue(any(c["name"] == "content-integrity" and c["status"] == "pass" for c in report["checks"]))


class GapTests(unittest.TestCase):
    def test_missing_authorizer_signature_is_flagged(self):
        report = validate_receipt(_receipt(signatures={}))
        self.assertIn("authorizer_signature_missing", report["flags"])

    def test_unsigned_receipt_is_flagged(self):
        receipt = _receipt()
        receipt.pop("signatures")
        report = validate_receipt(receipt)
        self.assertIn("authorizer_signature_missing", report["flags"])
        self.assertEqual(report["status"], "review-candidate")

    def test_tampered_body_fails_integrity(self):
        receipt = _receipt()
        receipt["amount_cap"] = 5000.0  # tamper without updating the digest
        report = validate_receipt(receipt)
        self.assertIn("content_integrity_mismatch", report["flags"])


class ConstraintTests(unittest.TestCase):
    def test_amount_exceeding_cap_is_flagged(self):
        report = validate_receipt(_receipt(amount="60.00", amount_cap="50.00"))
        self.assertIn("amount_exceeds_cap", report["flags"])

    def test_expired_receipt_is_flagged(self):
        receipt = _receipt(expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        report = validate_receipt(receipt)
        self.assertIn("expired", report["flags"])

    def test_agent_equal_authorizer_is_flagged(self):
        report = validate_receipt(_receipt(agent="same", authorizer="same"))
        self.assertIn("agent_equals_authorizer", report["flags"])

    def test_invalid_scope_token_is_flagged(self):
        report = validate_receipt(_receipt(scope=["bad scope!", "pay_invoice"]))
        self.assertIn("scope_syntax_invalid", report["flags"])

    def test_missing_required_fields_are_flagged(self):
        report = validate_receipt(_receipt(nonce="", purpose=""))
        self.assertIn("nonce_missing", report["flags"])
        self.assertIn("purpose_missing", report["flags"])

    def test_non_object_input_is_invalid(self):
        report = validate_receipt(["not", "an", "object"])
        self.assertEqual(report["status"], "invalid")

    def test_issued_at_in_future_is_flagged(self):
        report = validate_receipt(_receipt(issued_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()))
        self.assertIn("issued_at_in_future", report["flags"])

    def test_issued_at_not_before_expiry_is_flagged(self):
        now = datetime.now(timezone.utc)
        report = validate_receipt(_receipt(
            issued_at=(now - timedelta(minutes=30)).isoformat(),
            expires_at=(now - timedelta(hours=1)).isoformat(),
        ))
        self.assertIn("issued_at_not_before_expiry", report["flags"])

    def test_issued_at_before_expiry_is_clean(self):
        report = validate_receipt(_receipt(
            issued_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        ))
        self.assertEqual(report["flag_count"], 0)
        self.assertTrue(any(c["name"] == "issued-at" and c["status"] == "pass" for c in report["checks"]))


if __name__ == "__main__":
    unittest.main()
