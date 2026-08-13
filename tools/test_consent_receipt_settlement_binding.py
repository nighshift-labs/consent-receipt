#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- settlement-record binding.

These tests recompute, from the Settlement-Receipt Binding Extension's pinned
§3.5 Polygon fee-split bytes (x402-foundation/x402 PR #2666), the exact
`actionRef` join key and the two per-leg settlement digests, and then assert
the binding direction is **downstream -> consent**: the settlement's action
tuple (`agentId`, `scope`, amount) is checked for *containment* inside the
consent grant's authorization. The consent fixture itself is standalone — a
grant is issued before the settlement it authorizes, so it carries no forward
`references[]`.

RFC 8785 JCS is approximated here by Python's sorted-key compact JSON, which is
byte-identical for the ASCII-string / integer / boolean field sets of the
pinned records — the case the extension itself notes is the *only* one where
the approximation is safe (non-ASCII strings and non-integer numbers diverge).
"""

from __future__ import annotations

import hashlib
import json
import unittest
from decimal import Decimal
from pathlib import Path

from consent_receipt_check import validate_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"

ACTION_TUPLE_JCS = (
    '{"actionType":"purchase.fulfill",'
    '"agentId":"agent:claude/openpay-x402-mcp",'
    '"scope":"merchant:0x52d4901142e2B5680027da5EB47C86CB02a3cA81'
    '/resource:coo-icp-agent-consult/amount:2.00JPYC",'
    '"seq":1,"terminal":true,"timestampMs":1784168218000}'
)
PINNED_ACTION_REF = "08d26a534dbbaa6653f088fe943ef7bfa129d01f612198939605c99af8a66169"
MERCHANT_DIGEST = "f59cdf0520f1038835f0b4111ca4a84e63b8b433cdad7f169b6325cb7f1eeb91"
FEE_DIGEST = "e2d8825bfc2b7217964d66e3279ba0cc2e38a245036a3dd54bdb543344f9ba4a"


def _jcs(obj) -> bytes:
    """RFC 8785 approximation — valid for ASCII strings / ints / bools only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _merchant_leg() -> dict:
    return {
        "actionRef": "sha256:" + PINNED_ACTION_REF,
        "actionType": "purchase.fulfill",
        "agentId": "agent:claude/openpay-x402-mcp",
        "schema": "x402.settlement.evm/v0",
        "scope": "merchant:0x52d4901142e2B5680027da5EB47C86CB02a3cA81/resource:coo-icp-agent-consult/amount:2.00JPYC",
        "seq": 1,
        "settlement": {
            "amount": "1000000000000000000",
            "assertedFrom": "net-balance-change-to-payTo",
            "asset": "0xE7C3D8C9a439feDe00D2600032D5dB0Be71C3c29",
            "decimals": 18,
            "network": "eip155:137",
            "payTo": "0x52d4901142e2B5680027da5EB47C86CB02a3cA81",
            "rail": "evm",
            "scheme": "exact",
            "txDigest": "0xa9e6c6a9ce10fd26ec2fab0d367de31d7fb0918c79d5e932b8566816ecda3249",
            "verifiedBy": "facilitator://open-pay.jp",
        },
        "terminal": True,
        "timestampMs": 1784168218000,
    }


def _fee_leg() -> dict:
    fee = _merchant_leg()
    fee["settlement"] = dict(fee["settlement"])
    fee["settlement"]["payTo"] = "0x428483FbA62eDCef1E3a100d3799F6d71759c560"
    return fee


class RecomputationTests(unittest.TestCase):
    def test_action_tuple_recomputes_pinned_action_ref(self):
        digest = hashlib.sha256(ACTION_TUPLE_JCS.encode("utf-8")).hexdigest()
        self.assertEqual(digest, PINNED_ACTION_REF)

    def test_merchant_leg_digest_recomputes(self):
        digest = hashlib.sha256(_jcs(_merchant_leg())).hexdigest()
        self.assertEqual(digest, MERCHANT_DIGEST)

    def test_fee_leg_differs_by_digest_only(self):
        fee = _fee_leg()
        fee_digest = hashlib.sha256(_jcs(fee)).hexdigest()
        self.assertEqual(fee_digest, FEE_DIGEST)
        self.assertNotEqual(fee_digest, MERCHANT_DIGEST)
        self.assertEqual(fee["actionRef"], "sha256:" + PINNED_ACTION_REF)


class FixtureTests(unittest.TestCase):
    def test_fixture_is_a_standalone_consent_grant(self):
        fixture = json.loads(
            (EXAMPLES / "receipt-with-settlement-binding.json").read_text(encoding="utf-8")
        )
        # No forward references: the grant predates the settlement it authorizes.
        self.assertNotIn("references", fixture)
        report = validate_receipt(fixture)
        self.assertEqual(report["status"], "ready-for-human-review")
        self.assertEqual(report["flag_count"], 0)


class ContainmentTests(unittest.TestCase):
    """The binding is by containment: the settlement's action tuple must sit
    inside the consent grant's authorization (agent + amount cap)."""

    def _consent(self):
        return json.loads(
            (EXAMPLES / "receipt-with-settlement-binding.json").read_text(encoding="utf-8")
        )

    def test_settlement_agent_matches_consent_agent(self):
        consent = self._consent()
        self.assertEqual(_merchant_leg()["agentId"], consent["agent"])

    def test_settlement_amount_sum_is_within_consent_cap(self):
        consent = self._consent()
        # Each leg is 1.0 JPYC (1e18 atomic units / 18 decimals); two legs sum
        # to 2.0 JPYC, which must not exceed the grant's amount_cap.
        leg_amount = Decimal(_merchant_leg()["settlement"]["amount"]) / Decimal(
            10 ** _merchant_leg()["settlement"]["decimals"]
        )
        self.assertEqual(leg_amount, Decimal("1"))
        total = leg_amount + leg_amount
        self.assertTrue(total <= Decimal(consent["amount_cap"]), (total, consent["amount_cap"]))
        self.assertEqual(total, Decimal(consent["amount_cap"]))

    def test_settlement_window_is_within_consent_validity(self):
        from datetime import datetime, timezone
        consent = self._consent()
        issued = datetime.fromisoformat(consent["issued_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        expires = datetime.fromisoformat(consent["expires_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        settled = datetime.fromtimestamp(_merchant_leg()["timestampMs"] / 1000, tz=timezone.utc)
        self.assertTrue(issued <= settled <= expires, (issued, settled, expires))


if __name__ == "__main__":
    unittest.main()
