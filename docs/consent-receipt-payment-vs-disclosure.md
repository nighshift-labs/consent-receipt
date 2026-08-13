# Payment consent and disclosure consent — two sibling axes

A field-parallel mapping between the consent receipt
(`docs/agent-payment-consent-receipt.md`) and the disclosure-scoped consent
grant of [draft-morrison-consent-settlement-04] (§5.2 "Consent Grant Object",
§8 "Composition"). Written as the deliverable promised in the A7 convergence
note on [x402-foundation/x402#2734].

The two envelopes are the **same family, different subject and direction**: a
scoped, revocable, human-signed, content-addressed object with an expiry. The
I-D's grant is the *disclosure* axis — "which identity attribute, to which
reader, this moment", settled to the data subject. The consent receipt is the
orthogonal *payment* axis — "who authorized this agent to spend X, up to cap Y,
for purpose Z, until T".

## 1. Field-parallel table

| Concern | draft-morrison §5.2 (disclosure) | consent receipt (payment) |
|---|---|---|
| Who signs | the **subject** (Sovereign-tier signing key, bound in the attestation envelope §3) | the **authorizer** (the principal/payer) |
| Whose interest | the data subject's own attributes | the payer's own funds |
| What is granted | `reader_scope` (`mode`/`value`) + `attributes` + `tiers` — what may be *read* | `scope` (capability list) + `amount`/`amount_cap` + `purpose` — what may be *spent* |
| Ceiling | `conditions` (substrate-defined, e.g. a per-read ceiling) — optional | `amount_cap` — the spend ceiling |
| Validity | `inception` + `expiry` | `issued_at` + `expires_at` |
| Revocation | `revocation_commitment` (SHA-256 of a ≥256-bit preimage, published to the subject's identity log) | **absent — gap (see §2)** |
| Content address | SHA-256 of the complete COSE_Sign1 serialization (§5.2, RFC 8949 §4.2) | `content_sha256` over the canonical body |
| Signature | COSE_Sign1 [RFC 9052] | `signatures.authorizer` |

The directions are symmetric: disclosure is `subject → reader` (the subject
authorizes *reads of their own attributes*), payment is `principal → agent`
(the principal authorizes *spends of their own funds*). A reader-side `grant_ref`
echo (§5.3) corresponds to the payment-side `references[]` binding — both name
the envelope a downstream verification resolves against.

## 2. The one field the payment axis adds — and the one it is missing

**What the consent receipt adds that a disclosure grant does not need** is the
*binding to the spend itself*: `references[]` entries that point at the
machine-side records (an AIR receipt, a settlement record, an x402 payment), so
"was this specific payment inside the principal's signed envelope?" resolves as
a containment check with neither body exposed (see
`docs/air-consent-receipt-composition.md` and
`docs/consent-receipt-settlement-binding.md`).

**What the consent receipt is missing** — and the concrete field-table
recommendation this mapping produces — is `revocation_commitment`. The I-D's
§5.2 carries a commitment to a revocation token so a grant can be revoked after
the fact without a live channel; the consent receipt has only `expires_at`. To
compose as a clean sibling, the consent receipt should add:

```json
"revocation_commitment": "<sha256 hex of a >=256-bit preimage>"
```

mirroring §5.2's field, with revocation effected by publishing the preimage to
the authorizer's revocation log. This is the one change that makes the two
envelopes field-complete siblings rather than "same shape, one missing
revocation".

## 3. Composition (I-D §8)

The I-D's composition section is explicitly indifferent to the layer beneath it
(§8.1) and to the host payment protocol (§8.2), and it requires of the layer
beneath only that the signing key be bound to a credentialed unique human. The
consent receipt composes the same way:

- **§8.1 (attestation envelope)** — the consent receipt is equally indifferent
  to how the authorizer's key is bound to a person; it just requires an
  `authorizer` identity and a signature. The same §8.1 personhood requirement
  applies unchanged: "the key signing a consent grant is bound to a
  credentialed unique human."
- **§8.2 (HTTP-native payment)** — the consent receipt is carried as an
  authorization artifact a compliant x402/L402 flow should reference, not a
  replacement for the payment flow.
- **§8.4 (Identity Accord)** — the Accord is a *bilateral* standing envelope;
  the I-D's grant is a *unilateral per-read* envelope. The consent receipt is
  likewise *unilateral* (principal → agent). All three are siblings; none
  requires the others.

## 4. Open question for the I-D authors

Whether the payment axis should be specified as a **sibling axis in the same
document family** (a `consent-settlement-payment-v0` grant carrying `scope` +
`purpose: "pay"` + `amount_cap` + `expires_at` + `revocation_commitment`, the
subject re-named `principal`), or left as a separate spec that the settlement
instruction of §6 references by content address. The former keeps one
envelope family with two axes; the latter keeps the I-D disclosure-only. The
field-parallel table in §1 is the entire intersection either way — the payment
axis changes only `subject → principal` and `attributes/tiers →
scope/amount_cap`.

## 5. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures,
move money, issue tokens, or give trading/investment advice.

[draft-morrison-consent-settlement-04]: https://datatracker.ietf.org/doc/draft-morrison-consent-settlement/04/
[x402-foundation/x402#2734]: https://github.com/x402-foundation/x402/issues/2734
