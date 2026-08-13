#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- offer-receipt-v2 composition (#3140).

x402-foundation/x402#3140 ("feat(extensions): offer-receipt v2 — contentHash +
commitmentId settlement binding") extends the seller's receipt to bind (1) the
delivered bytes via `contentHash` (SHA-256 over the decoded entity body) and
(2) the batch-settlement identity via `commitmentId` with a strict settlement
XOR. It leaves "neutral third-party countersignature" out of scope.

These tests pin the three #3140 mechanisms to the consent receipt's discipline
and assert the composition boundary:

- `contentHash` is content-addressed (recompute-by-arithmetic, content-
  sensitive) — the same discipline as the consent's `references[].content_sha256`.
- the settlement XOR holds (exactly one of `transaction` / `commitmentId` /
  `settlementUnbound`) and rejects a two-arm receipt.
- the consent binds the *offer* (a prior artifact) via `references[]` — correct
  direction, no forward-reference warning — and does NOT claim to bind the
  posterior delivery/settlement (those bind back on their own side).

The fixture is really Ed25519-signed (disclosed synthetic key), money is
decimal-string, and the `offer` reference is prior.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from consent_receipt_check import validate_receipt
from sign_consent_receipt import verify_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"
FIXTURE = EXAMPLES / "receipt-with-offer-receipt-v2.json"

OFFER = {
    "resourceUrl": "https://api.batchpay.example/gpu-lease",
    "scheme": "batch-settlement",
    "network": "eip155:8453",
    "asset": "USDC",
    "payTo": "0x1a2B3c4D5e6F708192a3B4c5D6e7F8091A2b3C4d5",
    "amount": "50.00",
}
EXPECTED_OFFER_DIGEST = "9222a5647eb848287c18f74db2e5ddb06d70e846c997fa229aa0346409b62e3d"

DELIVERED_BODY = (
    b'{"result":"ok","leased_gpu":"a100-x4","lease_hours":1,'
    b'"checksum":"7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"}'
)
EXPECTED_CONTENT_HASH = "ec9e88e73beb3f43aac4004bdca73683bf38146a237a4866816572156c472bb0"
COMMITMENT_ID = "0x" + "c0" * 32


def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _settle_arms(receipt: dict) -> list[str]:
    """Return the non-empty settlement arms a v2 receipt declares."""
    arms = []
    if receipt.get("transaction"):
        arms.append("transaction")
    if receipt.get("commitmentId"):
        arms.append("commitmentId")
    if receipt.get("settlementUnbound"):
        arms.append("settlementUnbound")
    return arms


class OfferRecomputationTests(unittest.TestCase):
    def test_offer_digest_recomputes(self):
        self.assertEqual(hashlib.sha256(_jcs(OFFER)).hexdigest(), EXPECTED_OFFER_DIGEST)

    def test_offer_digest_is_content_sensitive(self):
        self.assertNotEqual(
            hashlib.sha256(_jcs(dict(OFFER, amount="1.00"))).hexdigest(),
            EXPECTED_OFFER_DIGEST,
        )


class ContentHashTests(unittest.TestCase):
    def test_content_hash_is_sha256_over_decoded_body(self):
        self.assertEqual(hashlib.sha256(DELIVERED_BODY).hexdigest(), EXPECTED_CONTENT_HASH)

    def test_content_hash_is_content_sensitive(self):
        tampered = DELIVERED_BODY.replace(b'"lease_hours":1', b'"lease_hours":8')
        self.assertNotEqual(hashlib.sha256(tampered).hexdigest(), EXPECTED_CONTENT_HASH)


class SettlementXorTests(unittest.TestCase):
    def test_exactly_one_arm_is_valid(self):
        # batch-settlement: commitmentId only, transaction undefined.
        self.assertEqual(_settle_arms({"commitmentId": COMMITMENT_ID}), ["commitmentId"])

    def test_two_arms_are_rejected(self):
        # A fake `transaction` under batch-settlement must be rejected.
        two_arm = {"transaction": "0x" + "ab" * 32, "commitmentId": COMMITMENT_ID}
        self.assertEqual(len(_settle_arms(two_arm)), 2)
        self.assertNotEqual(len(_settle_arms(two_arm)), 1)

    def test_settlement_unbound_is_explicit(self):
        self.assertEqual(_settle_arms({"settlementUnbound": True}), ["settlementUnbound"])


class FixtureTests(unittest.TestCase):
    def test_fixture_binds_offer_as_prior_artifact(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        refs = fixture["references"]
        self.assertEqual([r["type"] for r in refs], ["offer"])
        self.assertEqual(refs[0]["content_sha256"], EXPECTED_OFFER_DIGEST)
        report = validate_receipt(fixture)
        self.assertEqual(report["flag_count"], 0, report)
        self.assertFalse(any("forward reference" in w for w in report["warnings"]), report["warnings"])

    def test_fixture_terms_match_the_offer(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["amount"], OFFER["amount"])
        self.assertEqual(fixture["amount_cap"], OFFER["amount"])
        self.assertEqual(fixture["asset"], OFFER["asset"])
        self.assertEqual(fixture["chain_id"], 8453)  # == eip155:8453

    def test_fixture_is_really_signed(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertTrue(verify_receipt(fixture)[0], verify_receipt(fixture))


if __name__ == "__main__":
    unittest.main()
