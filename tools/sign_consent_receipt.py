#!/usr/bin/env python3
"""Really sign (and verify) an AI-agent payment consent receipt.

The consent-receipt checker (`consent_receipt_check.py`) is dependency-free and
verifies structure, integrity and signature *presence* only. This tool does the
cryptographic half: it produces a **really-signed** Ed25519 `authorizer`
signature over the receipt's canonical body (the exact bytes whose SHA-256 is
`content_sha256`), and independently verifies one.

Signing uses the `cryptography` package. The signature object is:

    "signatures": {
      "authorizer": {
        "alg": "ed25519",
        "public_key": "<32-byte public key, hex>",
        "signature": "<64-byte signature, hex>"
      }
    }

The message signed is `canonical_bytes(receipt)` — sorted-key compact JSON,
`ensure_ascii`, excluding `content_sha256` and `signatures` — so the signature
binds the same authorization facts the content digest binds.

A **synthetic test authorizer key** is built in for generating/verifying the
shipped example fixtures reproducibly. It is NOT a real human authorizer and
MUST NOT be used to sign anything real. Real authorizers generate their own
keypair with `--gen-key`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from consent_receipt_check import canonical_bytes

# Synthetic test authorizer seed (RFC 8032 32-byte seed). Clearly synthetic;
# used only so the shipped fixtures are reproducible byte-for-byte. The seed is
# derived deterministically from a label so it can never be malformed.
SYNTHETIC_AUTHORIZER_SEED = hashlib.sha256(
    b"nightshift-labs synthetic test authorizer key (never sign real grants with this)"
).digest()


def _priv(seed: bytes | None) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed or SYNTHETIC_AUTHORIZER_SEED)


def _public_bytes(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def sign_receipt(receipt: dict, seed: bytes | None = None) -> dict:
    """Return a copy of ``receipt`` with a real authorizer signature attached.

    ``content_sha256`` is recomputed and ``signatures.authorizer`` replaced with
    ``{alg, public_key, signature}``. The signature is Ed25519 over
    ``canonical_bytes`` (the same bytes ``content_sha256`` covers).
    """
    body = {k: v for k, v in receipt.items() if k not in ("content_sha256", "signatures")}
    canonical = canonical_bytes(body)
    priv = _priv(seed)
    signature = priv.sign(canonical)
    return {
        **body,
        "content_sha256": hashlib.sha256(canonical).hexdigest(),
        "signatures": {
            "authorizer": {
                "alg": "ed25519",
                "public_key": _public_bytes(priv).hex(),
                "signature": signature.hex(),
            }
        },
    }


def verify_receipt(receipt: dict) -> tuple[bool, str]:
    """Verify the authorizer signature and content digest.

    Returns ``(ok, detail)``. ``ok`` is True only when the authorizer entry is a
    really-signed Ed25519 object whose signature validates over the canonical
    body, and whose ``content_sha256`` matches that body.
    """
    body = {k: v for k, v in receipt.items() if k not in ("content_sha256", "signatures")}
    canonical = canonical_bytes(body)
    declared = receipt.get("content_sha256")
    if not isinstance(declared, str) or declared.lower() != hashlib.sha256(canonical).hexdigest():
        return False, "content_sha256 does not match the canonical body"
    auth = (receipt.get("signatures") or {}).get("authorizer")
    if not isinstance(auth, dict):
        return False, "authorizer signature is not a really-signed object ({alg, public_key, signature})"
    if auth.get("alg") != "ed25519":
        return False, f"unsupported alg: {auth.get('alg')!r}"
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(auth["public_key"]))
        pub.verify(bytes.fromhex(auth["signature"]), canonical)
    except (ValueError, InvalidSignature) as exc:
        return False, f"authorizer signature invalid: {exc}"
    return True, "valid ed25519 authorizer signature over the canonical body"


def _gen_key(args) -> int:
    priv = _priv(args.seed)
    print(json.dumps({
        "seed_hex": (args.seed or SYNTHETIC_AUTHORIZER_SEED).hex(),
        "public_key_hex": _public_bytes(priv).hex(),
        "alg": "ed25519",
        "note": "synthetic or freshly generated test key — never sign real grants with it",
    }, indent=2))
    return 0


def _sign(args) -> int:
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    signed = sign_receipt(receipt, seed=args.seed)
    out = args.output or args.receipt
    out.write_text(json.dumps(signed, indent=2) + "\n", encoding="utf-8")
    print(f"signed: {out} (authorizer public_key {signed['signatures']['authorizer']['public_key'][:16]}…)")
    return 0


def _verify(args) -> int:
    try:
        receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    ok, detail = verify_receipt(receipt)
    print(f"{'VALID' if ok else 'INVALID'}: {detail}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("gen-key", help="generate a synthetic/fresh Ed25519 keypair")
    gen.add_argument("--seed", type=_hex_seed, default=None, help="optional 32-byte seed (hex); omit for the built-in synthetic key")

    sign = sub.add_parser("sign", help="attach a real authorizer signature to a receipt")
    sign.add_argument("receipt", type=Path)
    sign.add_argument("-o", "--output", type=Path, default=None)
    sign.add_argument("--seed", type=_hex_seed, default=None, help="optional 32-byte seed (hex); omit for the built-in synthetic key")

    ver = sub.add_parser("verify", help="verify a receipt's authorizer signature")
    ver.add_argument("receipt", type=Path)

    args = parser.parse_args(argv)
    if args.command == "gen-key":
        return _gen_key(args)
    if args.command == "sign":
        return _sign(args)
    return _verify(args)


def _hex_seed(text: str) -> bytes:
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seed must be hex") from exc
    if len(raw) != 32:
        raise argparse.ArgumentTypeError("seed must be exactly 32 bytes (64 hex chars)")
    return raw


if __name__ == "__main__":
    raise SystemExit(main())
