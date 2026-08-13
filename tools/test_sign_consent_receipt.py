#!/usr/bin/env python3
"""Focused tests for the consent-receipt sign/verify tool."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone

from sign_consent_receipt import (
    SYNTHETIC_AUTHORIZER_SEED,
    sign_receipt,
    verify_receipt,
)


def _grant(**overrides) -> dict:
    grant = {
        "schema_version": 1,
        "agent": "agent-pubkey-abc123",
        "authorizer": "human-pubkey-xyz789",
        "scope": ["pay_invoice"],
        "asset": "USDC",
        "chain_id": 8453,
        "amount": "5.00",
        "amount_cap": "50.00",
        "purpose": "Pay up to 50 USDC for data look-ups.",
        "issued_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "nonce": "nonce-0001",
    }
    grant.update(overrides)
    return grant


class SignVerifyTests(unittest.TestCase):
    def test_sign_produces_verifiable_signature(self):
        signed = sign_receipt(_grant())
        self.assertTrue(verify_receipt(signed)[0], verify_receipt(signed))

    def test_signature_is_ed25519_over_canonical_body(self):
        signed = sign_receipt(_grant())
        auth = signed["signatures"]["authorizer"]
        self.assertEqual(auth["alg"], "ed25519")
        self.assertEqual(len(auth["public_key"]), 64)  # 32 bytes hex
        self.assertEqual(len(auth["signature"]), 128)  # 64 bytes hex
        self.assertEqual(len(signed["content_sha256"]), 64)

    def test_content_sha256_covers_canonical_body(self):
        signed = sign_receipt(_grant())
        body = {k: v for k, v in signed.items() if k not in ("content_sha256", "signatures")}
        # RFC 8785 (JCS) canonical form: sorted keys, compact separators,
        # non-ASCII emitted verbatim (ensure_ascii=False).
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.assertEqual(signed["content_sha256"], hashlib.sha256(canonical).hexdigest())

    def test_tampered_body_fails_verification(self):
        signed = sign_receipt(_grant())
        signed["amount_cap"] = "5000.00"
        self.assertFalse(verify_receipt(signed)[0])

    def test_tampered_signature_fails_verification(self):
        signed = sign_receipt(_grant())
        signed["signatures"]["authorizer"]["signature"] = "0" * 128
        self.assertFalse(verify_receipt(signed)[0])

    def test_wrong_key_fails_verification(self):
        signed = sign_receipt(_grant())
        # Re-sign with a different seed, then swap the public key — signature
        # no longer validates against the swapped key.
        other = sign_receipt(_grant(), seed=hashlib.sha256(b"other").digest())
        signed["signatures"]["authorizer"]["public_key"] = other["signatures"]["authorizer"]["public_key"]
        self.assertFalse(verify_receipt(signed)[0])

    def test_unsigned_grant_fails_verification(self):
        self.assertFalse(verify_receipt(_grant())[0])

    def test_synthetic_key_is_deterministic(self):
        a = sign_receipt(_grant(), seed=SYNTHETIC_AUTHORIZER_SEED)
        b = sign_receipt(_grant(), seed=SYNTHETIC_AUTHORIZER_SEED)
        self.assertEqual(a["signatures"]["authorizer"]["public_key"], b["signatures"]["authorizer"]["public_key"])


if __name__ == "__main__":
    unittest.main()
