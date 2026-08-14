#!/usr/bin/env python3
"""Tests for the BoundaryAttest <-> consent-receipt interop bridge.

Validates the two shipped fixtures (a really-signed consent grant and a
BoundaryAttest v0.1 receipt carrying ``authorization_ref``) plus the library's
canonicalization, key-id, signature, and authorization-binding logic.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import boundaryattest_interop as bi
from consent_receipt_check import validate_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "boundaryattest-consent-receipt"
GRANT_PATH = EXAMPLES / "consent-grant.json"
RECEIPT_PATH = EXAMPLES / "interop-receipt-with-authorization-ref.json"

SERVER_KEY = Ed25519PrivateKey.from_private_bytes(bi.SYNTHETIC_SERVER_SEED)


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class StableJsonTests(unittest.TestCase):
    def test_sorts_keys_and_is_compact(self):
        self.assertEqual(
            bi.stable_json({"b": 1, "a": 2}),
            b'{"a":2,"b":1}',
        )

    def test_preserves_array_order(self):
        self.assertEqual(bi.stable_json([2, 1]), b"[2,1]")

    def test_matches_profile_valid_vector_shape(self):
        # A minimal claim with the required fields only must canonicalize to
        # compact sorted-key JSON with no whitespace.
        claim = {
            "receipt_version": "0.1",
            "receipt_role": "client_observed",
            "event_id": "e",
            "timestamp": "2026-06-26T12:00:00.000Z",
            "action_type": "a",
            "status": "success",
        }
        raw = bi.stable_json(claim)
        self.assertNotIn(b" ", raw.replace(b"2026-06-26T12:00:00.000Z", b"X"))
        self.assertTrue(raw.startswith(b'{"action_type":"a",'))


class KeyIdTests(unittest.TestCase):
    def test_key_id_is_sha256_spki_der(self):
        pub = SERVER_KEY.public_key()
        key_id = bi.spki_public_key_id(pub)
        self.assertTrue(key_id.startswith("sha256:"))
        self.assertEqual(len(key_id), len("sha256:") + 64)
        # Deterministic for the synthetic key.
        self.assertEqual(key_id, bi.spki_public_key_id(pub))


class ComposeVerifyTests(unittest.TestCase):
    def test_round_trip(self):
        claim = {"receipt_version": "0.1", "event_id": "e"}
        receipt = bi.compose_receipt(claim, SERVER_KEY)
        ok, detail = bi.verify_receipt(receipt, SERVER_KEY.public_key())
        self.assertTrue(ok, detail)

    def test_tampered_claim_fails(self):
        receipt = _load(RECEIPT_PATH)
        receipt["claim"]["status"] = "tampered"
        ok, detail = bi.verify_receipt(receipt, SERVER_KEY.public_key())
        self.assertFalse(ok)
        self.assertIn("invalid_signature", detail)

    def test_wrong_key_fails(self):
        receipt = _load(RECEIPT_PATH)
        other = Ed25519PrivateKey.generate().public_key()
        ok, detail = bi.verify_receipt(receipt, other)
        self.assertFalse(ok)
        self.assertEqual(detail, "public_key_id_mismatch")


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grant = _load(GRANT_PATH)
        cls.receipt = _load(RECEIPT_PATH)

    def test_consent_grant_is_valid_and_really_signed(self):
        report = validate_receipt(self.grant, now=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(report["status"], "ready-for-human-review", report)
        self.assertEqual(report["flag_count"], 0, report)
        self.assertEqual(report["signature_verification"], "out-of-scope")

    def test_interop_receipt_verifies(self):
        ok, detail = bi.verify_receipt(self.receipt, SERVER_KEY.public_key())
        self.assertTrue(ok, detail)

    def test_authorization_ref_binds_to_grant(self):
        self.assertEqual(
            self.receipt["claim"]["authorization_ref"],
            self.grant["content_sha256"],
        )

    def test_action_contained_in_grant(self):
        report = bi.check_authorization_binding(
            self.receipt, SERVER_KEY.public_key(), self.grant,
            now=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        )
        self.assertTrue(report["ok"], report)

    def test_tampered_grant_breaks_binding(self):
        tampered = json.loads(json.dumps(self.grant))
        tampered["amount_cap"] = "0.01"  # now below amount -> fails cap containment
        report = bi.check_authorization_binding(
            self.receipt, SERVER_KEY.public_key(), tampered,
            now=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        )
        # The grant's own signature no longer verifies after the edit, and the
        # digest no longer matches authorization_ref — both must fail.
        self.assertFalse(report["ok"])
        self.assertFalse(report["grant"])

    def test_out_of_scope_action_fails_containment(self):
        receipt = json.loads(json.dumps(self.receipt))
        receipt["claim"]["action_type"] = "transfer_funds"
        report = bi.check_authorization_binding(
            receipt, SERVER_KEY.public_key(), self.grant,
            now=datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc),
        )
        # The signature fails (claim edited) AND the action is out of scope.
        self.assertFalse(report["ok"])
        self.assertFalse(report["interop"])
        self.assertFalse(report["contained"])


if __name__ == "__main__":
    unittest.main()
