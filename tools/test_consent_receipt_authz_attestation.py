#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- authz-attestation binding.

These tests recompute, from the synthetic `authz_attestation` object (the field
shape proposed in x402-foundation/x402#3086 — a human-anchored, ZK-attested
capability binding for PAYMENT-REQUIRED / PAYMENT-RESPONSE), the exact content
digest, and prove the binding direction is **downstream -> consent**: the
attestation's `human_anchor` commits to the consent grant's `content_sha256`,
so the delegation chain proves a valid delegation from a human who signed
*these terms* — not just "someone".

The consent fixture itself is a standalone grant (no forward `references[]`):
a grant is issued before the interaction it authorizes, so it cannot reference
the attestation that results from it.

RFC 8785 JCS is approximated here by Python's sorted-key compact JSON, which is
byte-identical for the ASCII-string / integer field set of the attestation (the
same approximation documented in the settlement-binding and risk-decision
tests).
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from consent_receipt_check import validate_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"
FIXTURE = EXAMPLES / "receipt-with-authz-attestation-reference.json"

SCOPE_BINDING = "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"


def _consent_content_sha256() -> str:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["content_sha256"]


def _human_anchor(consent_sha: str) -> str:
    """#3086's `human_anchor` should commit to the grant's digest, not just a
    person identifier: the chain then proves a valid delegation from a human who
    signed *these* terms."""
    return "sha256:" + hashlib.sha256(consent_sha.encode("utf-8")).hexdigest()


def _attestation() -> dict:
    return {
        "format": "spt-txn/1",
        "human_anchor": _human_anchor(_consent_content_sha256()),
        "scope_binding": SCOPE_BINDING,
        "delegation_depth": 2,
        "zk_proof": "groth16:bn254:opaque-proof-bytes-0123456789abcdef",
    }


def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class RecomputationTests(unittest.TestCase):
    def test_attestation_digest_is_deterministic(self):
        digest = hashlib.sha256(_jcs(_attestation())).hexdigest()
        self.assertEqual(digest, hashlib.sha256(_jcs(_attestation())).hexdigest())

    def test_human_anchor_commits_to_consent_grant(self):
        # The direction: downstream (attestation) -> consent. The anchor is a
        # one-way commitment to the exact grant terms, whose pre-image is the
        # consent receipt's content_sha256.
        self.assertEqual(
            _attestation()["human_anchor"],
            "sha256:" + hashlib.sha256(_consent_content_sha256().encode("utf-8")).hexdigest(),
        )
        # And the anchor is not just the person identifier — it is a function of
        # the grant terms, so two different grants yield two different anchors.
        self.assertNotEqual(
            _human_anchor(_consent_content_sha256()),
            _human_anchor("0" * 64),
        )

    def test_binding_is_content_sensitive_to_delegation_depth(self):
        wider = _attestation()
        wider["delegation_depth"] = 3
        self.assertNotEqual(
            hashlib.sha256(_jcs(wider)).hexdigest(),
            hashlib.sha256(_jcs(_attestation())).hexdigest(),
        )

    def test_binding_is_content_sensitive_to_scope_binding(self):
        rebound = _attestation()
        rebound["scope_binding"] = "f" * 64
        self.assertNotEqual(
            hashlib.sha256(_jcs(rebound)).hexdigest(),
            hashlib.sha256(_jcs(_attestation())).hexdigest(),
        )


class FixtureTests(unittest.TestCase):
    def test_fixture_is_a_standalone_consent_grant(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        # No forward references: the grant predates the attestation.
        self.assertNotIn("references", fixture)
        report = validate_receipt(fixture)
        self.assertEqual(report["status"], "ready-for-human-review")
        self.assertEqual(report["flag_count"], 0)


if __name__ == "__main__":
    unittest.main()
