#!/usr/bin/env python3
"""Focused tests for the consent-receipt <- auth-hints entitlement binding (#3009).

x402-foundation/x402#3009 ("auth-hints does not define how authentication
identity, payer identity, and entitlement are bound") is the
entitlement-binding gap: auth-hints validates authentication and payment
independently and permits the authenticated subject to differ from the payer
"subject to server policy", but never defines what that policy must express or
a binding record among subject, payer, resource fingerprint, and entitlement.
The comment thread converged on an "entitlement receipt" (0xbrainkid, 07-31).

The consent receipt is that binding record on the payer side: `authorizer`
binds the authenticated subject, `scope`/`purpose` bind the resource/request
fingerprint, and `references[]` commits the selected entitlement policy and the
payer-wallet delegation by digest (both prior artifacts — correct direction).

These tests recompute the policy and delegation digests (RFC 8785 JCS
approximation), assert the fixture commits them, and confirm the receipt
validates with zero flags and a really-signed (valid) authorizer signature.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from consent_receipt_check import validate_receipt
from sign_consent_receipt import verify_receipt

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "agent-payment-consent-receipt"
FIXTURE = EXAMPLES / "receipt-with-auth-hints-binding.json"

ENTITLEMENT_POLICY = {
    "policy_id": "policy:authhints/delegated-payer-v1",
    "policy": "third_party_payment_with_entitlement_ownership",
    "authenticated_subject": "human-pubkey-xyz789",
    "payer_wallet": "0x9a1B2c3D4e5F60718293A4b5C6d7E8f90a1B2c3D4",
    "entitlement_owner": "human-pubkey-xyz789",
    "issued_at": "2026-08-13T00:00:00Z",
}
DELEGATION = {
    "delegation_id": "delegation:authhints/wallet-delegation-2026-08-13",
    "delegator": "human-pubkey-xyz789",
    "delegatee_wallet": "0x9a1B2c3D4e5F60718293A4b5C6d7E8f90a1B2c3D4",
    "scope": ["pay_invoice"],
    "amount_cap": "25.00",
    "asset": "USDC",
    "chain_id": 8453,
    "expires_at": "2026-08-14T12:00:00Z",
}
EXPECTED_POLICY_DIGEST = "d8df59e3230c3796d5c33dac8c12fc4f7b42355907b0eef7e139ec2076242553"
EXPECTED_DELEGATION_DIGEST = "d9fba67a90a148b68e7dc791623a1743dd7e026a0f23cc0bcbe9bc0c3656c119"


def _jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class RecomputationTests(unittest.TestCase):
    def test_policy_digest_recomputes(self):
        self.assertEqual(hashlib.sha256(_jcs(ENTITLEMENT_POLICY)).hexdigest(), EXPECTED_POLICY_DIGEST)

    def test_delegation_digest_recomputes(self):
        self.assertEqual(hashlib.sha256(_jcs(DELEGATION)).hexdigest(), EXPECTED_DELEGATION_DIGEST)

    def test_policy_digest_is_content_sensitive(self):
        changed = dict(ENTITLEMENT_POLICY, policy="authenticated_subject_controls_wallet")
        self.assertNotEqual(hashlib.sha256(_jcs(changed)).hexdigest(), EXPECTED_POLICY_DIGEST)


class FixtureTests(unittest.TestCase):
    def test_fixture_commits_policy_and_delegation_as_prior_artifacts(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        refs = {(r["type"], r["content_sha256"]) for r in fixture["references"]}
        self.assertIn(("entitlement_policy", EXPECTED_POLICY_DIGEST), refs)
        self.assertIn(("delegation", EXPECTED_DELEGATION_DIGEST), refs)
        # Both predate the grant, so neither is a forward reference.
        report = validate_receipt(fixture)
        self.assertEqual(report["flag_count"], 0, report)
        self.assertFalse(any("forward reference" in w for w in report["warnings"]), report["warnings"])

    def test_fixture_binds_authenticated_subject_distinct_from_payer(self):
        # The case #3009 names: authenticated subject != payer wallet. The grant
        # authorizes the subject, and the delegation reference justifies the
        # distinct payer wallet.
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["authorizer"], "human-pubkey-xyz789")
        self.assertEqual(fixture["agent"], "agent:openpay/x402-mcp-authhints")
        self.assertNotEqual(fixture["authorizer"], fixture["agent"])

    def test_fixture_carries_entitlement_terms(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["amount"], "25.00")
        self.assertEqual(fixture["amount_cap"], "25.00")
        self.assertEqual(fixture["asset"], "USDC")
        self.assertEqual(fixture["chain_id"], 8453)
        self.assertIn("premium-data", fixture["purpose"])

    def test_fixture_is_really_signed_and_valid(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        ok, detail = verify_receipt(fixture)
        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()
