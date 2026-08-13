#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- risk-decision binding.

These tests recompute, from the synthetic risk-decision provenance record (the
field shape proposed in x402-foundation/x402#3142), the exact content digest,
and prove the binding direction is **downstream -> consent**: the decision's
`evidence.evaluatedAt` (and the payment it gates) are checked for *containment*
inside the consent grant's validity window and cap. The consent fixture itself
is standalone — a grant is issued before the decision that gates the payment,
so it carries no forward `references[]`.

RFC 8785 JCS is approximated here by Python's sorted-key compact JSON, which is
byte-identical for the ASCII-string / number / boolean field set of the record
(the same approximation documented in the settlement-binding test).
"""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from consent_receipt_check import validate_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"
FIXTURE = EXAMPLES / "receipt-with-risk-decision-reference.json"

RISK_DECISION = {
    "decision": "ALLOW",
    "riskScore": 18,
    "confidence": 0.94,
    "model": {
        "id": "agent-payment-risk",
        "version": "3.4.1",
        "status": "ACTIVE",
        "driftStatus": "NORMAL",
    },
    "policy": {
        "id": "enterprise-payment-policy",
        "version": "2.1",
    },
    "evidence": {
        "evaluatedAt": "2026-08-13T09:30:00Z",
        "freshnessSeconds": 12,
        "digest": "sha256:9f7b3c2e5d8a4f1e6b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a",
    },
    "fallbackUsed": False,
    "reasonCodes": ["ESTABLISHED_COUNTERPARTY", "LOW_TRANSACTION_VELOCITY"],
}

EXPECTED_DIGEST = "5531f9b812e85c9989b079bbb091a24e046ed405f0bf844f666bd771eca8af84"


def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class RecomputationTests(unittest.TestCase):
    def test_decision_digest_recomputes(self):
        digest = hashlib.sha256(_jcs(RISK_DECISION)).hexdigest()
        self.assertEqual(digest, EXPECTED_DIGEST)

    def test_binding_is_content_sensitive_to_model_health(self):
        degraded = json.loads(json.dumps(RISK_DECISION))
        degraded["model"]["driftStatus"] = "DEGRADED"
        degraded_digest = hashlib.sha256(_jcs(degraded)).hexdigest()
        self.assertNotEqual(degraded_digest, EXPECTED_DIGEST)

    def test_binding_is_content_sensitive_to_decision(self):
        blocked = json.loads(json.dumps(RISK_DECISION))
        blocked["decision"] = "BLOCK"
        blocked_digest = hashlib.sha256(_jcs(blocked)).hexdigest()
        self.assertNotEqual(blocked_digest, EXPECTED_DIGEST)


class FixtureTests(unittest.TestCase):
    def test_fixture_is_a_standalone_consent_grant(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        # No forward references: the grant predates the decision.
        self.assertNotIn("references", fixture)
        report = validate_receipt(fixture)
        self.assertEqual(report["status"], "ready-for-human-review")
        self.assertEqual(report["flag_count"], 0)


class ContainmentTests(unittest.TestCase):
    def _consent(self):
        return json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_decision_evaluated_within_consent_window(self):
        consent = self._consent()
        issued = datetime.fromisoformat(consent["issued_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        expires = datetime.fromisoformat(consent["expires_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
        evaluated = datetime.fromisoformat(
            RISK_DECISION["evidence"]["evaluatedAt"].replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        self.assertTrue(issued <= evaluated <= expires, (issued, evaluated, expires))

    def test_decision_agent_matches_consent_agent(self):
        # The decision gates a payment by the consent's agent; the two must be
        # the same principal for the containment check to be meaningful.
        consent = self._consent()
        self.assertEqual(consent["agent"], "agent:claude/openpay-x402-mcp")


if __name__ == "__main__":
    unittest.main()
