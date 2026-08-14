#!/usr/bin/env python3
"""Tests for the NOMOS-intent x consent-receipt composition checker."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from nomos_consent_compose import compose_check, nomos_intent_digest  # noqa: E402
from sign_consent_receipt import verify_receipt  # noqa: E402

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "nomos-consent-receipt"
# A deterministic instant inside the fixture's validity window (the canary
# interaction happened 2026-08-10T21:23Z→21:25Z). Pinning `now` keeps the
# fixture from rotting as wall-clock advances (same convention as the other
# consent-receipt composition fixtures).
NOW = datetime(2026, 8, 10, 21, 24, 0, tzinfo=timezone.utc)


def _load(name: str) -> dict:
    return json.loads((_EXAMPLES / name).read_text(encoding="utf-8"))


class NomosConsentCompositionTests(unittest.TestCase):
    def test_consent_grant_is_really_signed_and_valid(self) -> None:
        grant = _load("consent-grant.json")
        ok, detail = verify_receipt(grant)
        self.assertTrue(ok, detail)
        # A really-signed grant must carry a real Ed25519 authorizer object.
        auth = grant["signatures"]["authorizer"]
        self.assertEqual(auth["alg"], "ed25519")
        self.assertEqual(len(auth["public_key"]), 64)
        self.assertEqual(len(auth["signature"]), 128)

    def test_valid_composition_passes(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        grant = _load("consent-grant.json")
        report = compose_check(intent, grant, now=NOW)
        self.assertEqual(report["status"], "ready-for-human-review", report["flags"])
        self.assertEqual(report["flag_count"], 0)

    def test_authorization_ref_matches_consent_digest(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        grant = _load("consent-grant.json")
        self.assertEqual(
            intent["authorization_ref"]["content_sha256"].lower(),
            grant["content_sha256"].lower(),
        )

    def test_tampered_authorization_ref_is_flagged(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        grant = _load("consent-grant.json")
        intent["authorization_ref"]["content_sha256"] = "0" * 64
        report = compose_check(intent, grant, now=NOW)
        self.assertIn("authorization_ref_mismatch", report["flags"])

    def test_missing_authorization_ref_is_flagged(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        grant = _load("consent-grant.json")
        intent.pop("authorization_ref")
        report = compose_check(intent, grant, now=NOW)
        self.assertIn("no_authorization_ref", report["flags"])

    def test_intent_outliving_consent_is_flagged(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        grant = _load("consent-grant.json")
        intent["expires_at"] = "2026-08-11T00:00:00Z"
        report = compose_check(intent, grant, now=NOW)
        self.assertIn("intent_outlives_consent", report["flags"])

    def test_intent_digest_binds_authorization_ref(self) -> None:
        intent = _load("nomos-intent-with-consent-ref.json")
        with_ref = nomos_intent_digest(intent)
        self.assertEqual(with_ref, intent["intent_digest"])
        # Removing authorization_ref must change the digest — that is the whole
        # point: the digest binds the human-authorization origin.
        stripped = {k: v for k, v in intent.items() if k != "intent_digest"}
        stripped.pop("authorization_ref")
        without_ref = nomos_intent_digest(stripped)
        self.assertNotEqual(with_ref, without_ref)


if __name__ == "__main__":
    unittest.main()
