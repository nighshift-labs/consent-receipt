# Agent Payment Consent Receipt — a minimal spec + reference checker

## Why this exists

When an AI agent spends money on a human's behalf, the only durable answer to
"who authorized what, for what purpose, up to what cap, until when" is a
receipt that the human actually signed. Today the pieces exist separately —
NIP-47/NWC capability scopes, x402/L402 payment-required semantics, session
keys — but nothing ties them into a single, independently verifiable
authorization record. The result is the *unsigned consent receipt gap*: an
agent can spend within a broad capability grant and no artifact survives that
proves the specific payment matched the specific human intent.

This document proposes a minimal, implementation-neutral consent receipt and a
reference checker. It is a **shape and integrity check, not a security audit,
signature verifier, wallet, or payment processor.**

## The receipt

A consent receipt is a JSON object. Money values are **decimal strings** — the
float-free form, so the canonical body and its digest never depend on IEEE-754
rounding (the same rule AIR applies to its atomic-unit amounts). Required
fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | `1` |
| `agent` | string | Non-empty agent identity (e.g. its pubkey or instance id) |
| `authorizer` | string | Non-empty human authorizer identity, distinct from `agent` |
| `scope` | list[string] | Least-privilege capability list (NIP-47/NWC style), e.g. `["pay_invoice"]` |
| `asset` | string | Asset, e.g. `USDC` |
| `chain_id` | int | Network chain id, e.g. `8453` |
| `amount` | string (decimal) | Amount of the specific payment, e.g. `"5.00"` (`"0.00"` if the receipt is a standing cap) |
| `amount_cap` | string (decimal) | Maximum total spend this receipt authorizes; `amount <= amount_cap` (compared as exact decimals) |
| `purpose` | string | Human-readable purpose, non-empty |
| `issued_at` | string | OPTIONAL — RFC 3339 signing/issuance time; must precede `expires_at`. Present to give the receipt a precedence anchor for composition (see `docs/air-consent-receipt-composition.md`). |
| `expires_at` | string | ISO-8601 timestamp with timezone, in the future |
| `nonce` | string | Unique per receipt |
| `references` | list[object] | OPTIONAL — **prior** artifacts this consent is grounded in (see below) |
| `content_sha256` | string | SHA-256 of the canonical body (see below) |
| `signatures` | object | MUST include an `authorizer` signature over the canonical body |

### `references` — grounding the grant in prior artifacts

A consent receipt MAY carry a `references` list binding it to artifacts that
**predate** the grant: a governing policy, terms of service, a parent
capability grant, or a trust anchor the authorizer relied on. Each entry is an
object with a non-empty `type`, a non-empty `id` (the referenced artifact's
identifier or hash), and an optional `content_sha256` (the digest of the
referenced artifact, making the reference content-bound). `references` is part
of the canonical body, so tampering with it breaks `content_sha256`.

The direction matters and is one-way. A consent grant is issued **before** the
interaction it authorizes, so it cannot reference the receipts that result from
that interaction (an AIR receipt, a settlement record, a trail record) — those
do not exist yet at grant time. Those proof-of-delivery artifacts bind **back**
to the consent on their own side: an AIR receipt names this consent via its
`authorizations[]` field, a settlement record via `actionRef`, and so on. The
consent side stays a clean, immutable grant; the containment check ("was this
payment inside the human's signed cap/scope/expiry?") runs on the receipt side
as a binding-coherence predicate — see `docs/air-consent-receipt-composition.md`
and `docs/air-consent-receipt-field-table.md`.

### Canonical body and integrity

`content_sha256` is the SHA-256 of the receipt's **JCS (RFC 8785) canonical
form**, with `content_sha256` and `signatures` **excluded** (so the digest
covers the authorization facts, not the fields that wrap them). JCS means:
UTF-8 output, no insignificant whitespace, object keys sorted by Unicode code
point, and strings escaped minimally — only `"`, `\`, and U+0000–U+001F
(short escapes `\b \t \n \f \r`, otherwise `\u00xx`); every other character,
including non-ASCII, is emitted verbatim. The schema is float-free by
construction (money is decimal strings; the only numeric types are the
non-negative integers `schema_version`/`chain_id`), so number canonicalization
is plain decimal integers. This makes the receipt content-addressed and detects
tampering with any authorization fact; the authorizer signature covers these
same bytes.

### Signatures — the point of the spec

`signatures.authorizer` is a **real Ed25519 signature** over the canonical
body (the same bytes `content_sha256` covers), carried as:

```json
"signatures": {
  "authorizer": {
    "alg": "ed25519",
    "public_key": "<32-byte public key, hex>",
    "signature": "<64-byte signature, hex>"
  }
}
```

The shipped fixtures are really signed with a synthetic test authorizer key
(disclosed — not a real human). `tools/sign_consent_receipt.py` signs and
verifies them: `sign` attaches a real signature, `verify` checks it against the
canonical body. The reference checker itself stays dependency-free and verifies
presence/shape only; cryptographic verification is that tool's job. An
unsigned receipt, or one whose authorizer signature is absent, is the exact
failure mode this spec exists to close and is flagged as
`authorizer_signature_missing`.

## Reference checker

`tools/consent_receipt_check.py` is a dependency-free, offline, deterministic
validator. It checks schema version, identity distinctness, scope syntax,
amount-within-cap, asset/chain, expiry, nonce, purpose, content integrity, and
authorizer-signature presence. It returns a status
(`ready-for-human-review` / `review-candidate` / `invalid`) plus named flags.

Run it:

```sh
python3 tools/consent_receipt_check.py receipt.json --format text --fail-on review
```

Exit `1` means at least one review flag is present. It never contacts a chain,
signs, settles, or moves funds.

## Relationship to existing standards

- **NIP-47 / NWC** supply the *capability scope vocabulary* (`pay_invoice`,
  `get_balance`, etc.). The receipt reuses those tokens but binds them to one
  specific authorization with a cap, purpose, and expiry.
- **x402 / L402** describe the *payment-required* flow and disclosure. The
  receipt is the human-side authorization record that a compliant payment
  should reference, not a replacement for the payment flow.
- **Session keys** bound an agent to a key; the receipt binds that key's
  activity to a *human-auditable intent record*.

## Boundary

This is free, non-financial documentation and a read-only checker. It does not
custody funds, sign transactions, verify signatures, move money, issue tokens,
or provide trading/investment advice. It makes no claim that any specific
agent-payment product is safe or compliant.
