#!/usr/bin/env python3
"""Pin the consent receipt's canonical form to RFC 8785 (JCS).

``content_sha256`` is the SHA-256 of the JCS canonical serialization of the
receipt body (the receipt minus ``content_sha256`` and ``signatures``). The
authorizer signature signs those same bytes. These tests pin the observable
serialization rules so the canonicalizer cannot silently drift from JCS.
"""

from __future__ import annotations

import hashlib
import unittest

from consent_receipt_check import canonical_bytes


class JcsCanonicalizationTests(unittest.TestCase):
    def test_sorted_keys_compact_separators(self):
        self.assertEqual(
            canonical_bytes({"b": 1, "a": 2, "c": {"z": 3, "y": 4}}),
            b'{"a":2,"b":1,"c":{"y":4,"z":3}}',
        )

    def test_string_escaping_is_minimal_jcs(self):
        # Escape only '"', '\' and U+0000..U+001F; '/' is NOT escaped.
        value = '"/\\\b\f\n\r\t\x00\x1f'
        self.assertEqual(
            canonical_bytes({"s": value}),
            b'{"s":"\\"/\\\\\\b\\f\\n\\r\\t\\u0000\\u001f"}',
        )

    def test_non_ascii_emitted_verbatim_not_escaped(self):
        # RFC 8785 leaves non-ASCII raw (UTF-8). The old ensure_ascii=True form
        # escaped it as \uXXXX — a different (non-JCS) canonicalization.
        self.assertEqual(
            canonical_bytes({"purpose": "caf\u00e9 \u20ac"}),
            "caf\u00e9 \u20ac".join(('{"purpose":"', '"}')).encode("utf-8"),
        )

    def test_integers_plain_decimal_no_leading_zeros(self):
        self.assertEqual(
            canonical_bytes({"chain_id": 8453, "schema_version": 1}),
            b'{"chain_id":8453,"schema_version":1}',
        )

    def test_bool_and_null_literals(self):
        self.assertEqual(
            canonical_bytes({"t": True, "f": False, "n": None}),
            b'{"f":false,"n":null,"t":true}',
        )

    def test_reserved_keys_excluded_from_canonical_body(self):
        body = {"a": 1, "content_sha256": "0" * 64, "signatures": {"x": "y"}}
        self.assertEqual(canonical_bytes(body), b'{"a":1}')

    def test_content_sha256_is_sha256_of_canonical_bytes(self):
        body = {
            "schema_version": 1,
            "agent": "agent-pubkey-abc123",
            "authorizer": "human-pubkey-xyz789",
            "scope": ["pay_invoice"],
            "asset": "USDC",
            "chain_id": 8453,
            "amount": "5.00",
            "amount_cap": "50.00",
            "purpose": "Pay for a look-up.",
            "expires_at": "2026-09-01T00:00:00Z",
            "nonce": "nonce-0001",
        }
        self.assertEqual(
            hashlib.sha256(canonical_bytes(body)).hexdigest(),
            hashlib.sha256(
                b'{"agent":"agent-pubkey-abc123","amount":"5.00",'
                b'"amount_cap":"50.00","asset":"USDC","authorizer":'
                b'"human-pubkey-xyz789","chain_id":8453,"expires_at":'
                b'"2026-09-01T00:00:00Z","nonce":"nonce-0001","purpose":'
                b'"Pay for a look-up.","schema_version":1,"scope":'
                b'["pay_invoice"]}'
            ).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
