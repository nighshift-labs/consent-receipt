#!/usr/bin/env python3
"""Focused tests for the AIR-entry x consent-receipt composition checker."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from air_consent_compose import compose_check, find_consent_bindings
from consent_receipt_check import canonical_bytes


def _consent_bytes(consent: dict) -> bytes:
    return json.dumps(consent, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _consent(**overrides) -> dict:
    base = {
        "schema_version": 1,
        "agent": "agent-pubkey-abc123",
        "authorizer": "human-pubkey-xyz789",
        "scope": ["pay_invoice"],
        "asset": "USDC",
        "chain_id": 8453,
        "amount": "5.00",
        "amount_cap": "50.00",
        "purpose": "Pay up to 50 USDC for data look-ups via the x402 gateway.",
        "issued_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "nonce": "nonce-0001",
        "signatures": {"authorizer": _REAL_SIG},
    }
    base.update(overrides)
    body = {k: v for k, v in base.items() if k not in ("content_sha256", "signatures")}
    base["content_sha256"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return base


_REAL_SIG = {
    "alg": "ed25519",
    "public_key": "3d8998727276cc1d60b08eec034865f692962822fd499d0a7b8f532ff222a0da",
    "signature": "cd" * 64,
}


def _binding(consent: dict, consent_sha256: str, **overrides) -> dict:
    binding = {
        "scheme": "nightshift.consent_receipt.v1",
        "decision_ref": consent["content_sha256"],
        "trust_model": "issuer_signed",
        "authority_ref": "ed25519:3d8998727276cc1d60b08eec034865f692962822fd499d0a7b8f532ff222a0da",
        "authorization_uri": "https://blossom.primal.net/example.txt",
        "authorization_sha256": consent_sha256,
        "transport_hint": "raw_url",
        "axes": {
            "precedence": {"field": "issued_at"},
            "freshness": {"expires_at_field": "expires_at", "flavor": "computable"},
            "correctness": None,
        },
    }
    binding.update(overrides)
    return binding


def _air_entry(binding: dict | None, payment: dict | None = None, **overrides) -> dict:
    entry = {
        "spec": "agent-interaction-receipt",
        "spec_version": "0.3-draft-1",
        "entry_type": "receipt",
        "session_id": "vidainf-prices:0xA1b2",
        "seq": 0,
        "prev_entry_hash": None,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "capability_id": "vidainf-prices",
        "parties": [],
        "request": {},
        "response": {},
        "payment": payment,
        "meta": {},
        "signatures": [],
    }
    if binding is not None:
        entry["authorizations"] = [binding]
    entry.update(overrides)
    return entry


def _payment(**overrides) -> dict:
    payment = {
        "protocol": "x402",
        "scheme": "exact",
        "network": "base",
        "asset": "USDC",
        "amount": "5",
        "pay_to": "0xProvider",
        "payer": "0xA1b2",
        "payment_payload_sha256": "ab" * 32,
        "settlement_status": "pending",
        "settlement_ref": None,
    }
    payment.update(overrides)
    return payment


class CompositionTests(unittest.TestCase):
    def test_valid_composition_is_clean(self):
        consent = _consent()
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha), payment=_payment())
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertEqual(report["status"], "ready-for-human-review", report["flags"])
        self.assertEqual(report["flag_count"], 0, report["checks"])

    def test_missing_binding_is_flagged(self):
        consent = _consent()
        air = _air_entry(None, payment=_payment())
        report = compose_check(air, consent)
        self.assertIn("no_consent_binding", report["flags"])

    def test_authorization_sha256_mismatch_is_transport_failure(self):
        consent = _consent()
        good = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        wrong = "0" * 64
        air = _air_entry(_binding(consent, good, authorization_sha256=wrong), payment=_payment())
        report = compose_check(air, consent, consent_sha256=good)
        self.assertIn("binding_authorization_sha256_mismatch", report["flags"])

    def test_decision_ref_mismatch_is_flagged(self):
        consent = _consent()
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha, decision_ref="ab" * 32), payment=_payment())
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertIn("binding_decision_ref_mismatch", report["flags"])

    def test_payment_exceeding_cap_is_flagged(self):
        consent = _consent(amount_cap="50.00")
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha), payment=_payment(amount="5000"))
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertIn("payment_exceeds_consent_cap", report["flags"])

    def test_payment_asset_mismatch_is_flagged(self):
        consent = _consent(asset="USDC")
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha), payment=_payment(asset="WETH"))
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertIn("payment_asset_mismatch", report["flags"])

    def test_payment_after_expiry_is_flagged(self):
        consent = _consent(expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha), payment=_payment(), issued_at="2026-09-01T00:00:00Z")
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertIn("payment_after_consent_expiry", report["flags"])

    def test_v02_meta_authorization_binding_is_found(self):
        consent = _consent()
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        binding = _binding(consent, sha)
        air = _air_entry(None, payment=_payment(), meta={"authorization": binding})
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertEqual(report["flag_count"], 0, report["flags"])

    def test_consent_flags_are_prefixed_and_propagated(self):
        consent = _consent(signatures={})  # unsigned — authorizer_signature_missing
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        air = _air_entry(_binding(consent, sha), payment=_payment())
        report = compose_check(air, consent, consent_sha256=sha)
        self.assertTrue(any(f.startswith("consent.") for f in report["flags"]))
        self.assertIn("consent.authorizer_signature_missing", report["flags"])

    def test_non_object_air_entry_is_invalid(self):
        report = compose_check(["not", "an", "object"], _consent())
        self.assertEqual(report["status"], "invalid")

    def test_find_consent_bindings_covers_both_shapes(self):
        consent = _consent()
        sha = hashlib.sha256(_consent_bytes(consent)).hexdigest()
        binding = _binding(consent, sha)
        air = _air_entry(binding, meta={"authorization": binding})
        bindings = find_consent_bindings(air)
        self.assertEqual(len(bindings), 2)


if __name__ == "__main__":
    unittest.main()
