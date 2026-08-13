#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- accepted-offer binding (#3006).

x402-foundation/x402#3006 ("Privacy-minimal receipt does not bind the payment
terms of the accepted offer") is the receipt-side gap: the privacy-minimal
receipt omits `amount`/`asset`/`payTo`/`scheme` and cannot prove which offer it
paid. The thread's convergence is a single content-addressed `offerDigest`
field (wowlegend / Tersign, 08-02).

The consent receipt is the *payer-side* complement: it carries the terms the
receipt omits (`amount`, `amount_cap`, `asset`, `purpose`, `expires_at`) and
binds the accepted offer as a **prior** artifact in `references[]` (the offer
exists before the human grants consent, so this is the correct direction —
unlike the settlement/trail/attestation/decision records, which bind back to
the consent on their own side).

These tests recompute the offer's canonical digest (RFC 8785 JCS approximation)
and assert the fixture's `offer` reference maps onto it, and that `offer` is
correctly treated as a prior (not forward) reference.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from consent_receipt_check import validate_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"
FIXTURE = EXAMPLES / "receipt-with-offer-reference.json"

OFFER = {
    "resourceUrl": "https://api.coo-icp.example/agent-consult",
    "scheme": "exact",
    "network": "eip155:8453",
    "asset": "USDC",
    "payTo": "0x9a1B2c3D4e5F60718293A4b5C6d7E8f90a1B2c3D4",
    "amount": "50.00",
}
EXPECTED_OFFER_DIGEST = "9d40ae1bf0fea0065f042fadb39420b718182a797da9c4d4263e49a1ed7c7c09"


def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class RecomputationTests(unittest.TestCase):
    def test_offer_digest_recomputes(self):
        self.assertEqual(hashlib.sha256(_jcs(OFFER)).hexdigest(), EXPECTED_OFFER_DIGEST)

    def test_offer_digest_is_content_sensitive_to_amount(self):
        cheaper = dict(OFFER, amount="1.00")
        self.assertNotEqual(hashlib.sha256(_jcs(cheaper)).hexdigest(), EXPECTED_OFFER_DIGEST)

    def test_offer_digest_is_content_sensitive_to_payto(self):
        other_payee = dict(OFFER, payTo="0x" + "ab" * 20)
        self.assertNotEqual(hashlib.sha256(_jcs(other_payee)).hexdigest(), EXPECTED_OFFER_DIGEST)


class FixtureTests(unittest.TestCase):
    def test_fixture_binds_offer_as_prior_artifact(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        refs = fixture["references"]
        self.assertEqual([r["type"] for r in refs], ["offer"])
        self.assertEqual(refs[0]["content_sha256"], EXPECTED_OFFER_DIGEST)
        # The offer predates the grant, so this is a PRIOR reference — no
        # forward-reference warning.
        report = validate_receipt(fixture)
        self.assertEqual(report["flag_count"], 0, report)
        self.assertFalse(any("forward reference" in w for w in report["warnings"]), report["warnings"])

    def test_fixture_terms_match_the_offer(self):
        # The grant carries the payment terms the privacy-minimal receipt omits,
        # and they agree with the referenced offer (amount, asset, network).
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["amount"], OFFER["amount"])
        self.assertEqual(fixture["amount_cap"], OFFER["amount"])
        self.assertEqual(fixture["asset"], OFFER["asset"])
        self.assertEqual(fixture["chain_id"], 8453)  # == eip155:8453


if __name__ == "__main__":
    unittest.main()
