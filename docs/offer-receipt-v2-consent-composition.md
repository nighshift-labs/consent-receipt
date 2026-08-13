# Consent receipt vs offer-receipt v2 — the authorization gap the delivery/settlement binding leaves open

A field table for how the consent receipt composes with
[x402-foundation/x402#3140] (`feat(extensions): offer-receipt v2 — contentHash +
commitmentId settlement binding`, `SteveScytalex`, 2026-08-13). #3140 is a PR
that adds receipt payload version 2 so a **seller's** receipt can bind (1)
*what was delivered* (`contentHash` = SHA-256 over the decoded entity body) and
(2) *how settlement is identified under batch schemes* (`commitmentId` + a
strict settlement XOR). It explicitly leaves "neutral third-party
countersignature / PQ dual-sign product envelopes" out of scope as a separate
permissionless extension key.

The finding: offer-receipt v2 closes the **delivery** and **settlement** gaps in
the seller's self-attestation, but it leaves the **authorization** gap open —
nothing in the offer or the v2 receipt proves a *human* authorized these payment
terms. The consent receipt is that origin record, and it composes with #3140 by
digest, with no new field on either side.

## 1. The three gaps, and which one #3140 does not close

The seller's receipt is self-attestation. #3140 identifies two of its gaps and
closes them:

| Gap | Closed by #3140? | Mechanism |
|---|---|---|
| receipt does not bind the delivered bytes | **yes** | `contentHash` (SHA-256 over decoded entity body) |
| `transaction` is undefined under `batch-settlement` | **yes** | `commitmentId` + settlement XOR (exactly one arm) |
| nothing proves a *human* authorized the terms | **no** | — (the consent receipt) |

The third gap is the one neither the offer nor the v2 receipt addresses: a
seller can prove *what it delivered* and *how it settled*, and still never show
*who authorized paying for it, up to what cap, for what purpose, until when*.
That is precisely the consent receipt's content.

## 2. Composition — three artifacts chained by digest

```
consent receipt (PAYER, prior)      offer (prior)          offer-receipt v2 (SELLER, posterior)
  references[].offer.content_sha256 ──▶ offerDigest           contentHash ──▶ delivered bytes
  amount / cap / purpose / expiry      amount / asset /       commitmentId ──▶ batch settlement
                                       payTo / scheme         settlement XOR (exactly one arm)
```

The consent references the offer (a **prior** artifact — it exists before the
human grants consent), so `references[]` is the correct direction. The v2
receipt is produced **after** payment, so it binds back to the consent on its
own side — that back-reference is the "separate permissionless extension key"
#3140 already names as out of scope.

## 3. Field table — #3140's fields on the consent side

| #3140 v2 field | Meaning | Consent-receipt counterpart |
|---|---|---|
| `contentHash` | SHA-256 over the decoded entity body (delivered bytes) | the same content-addressed discipline as `references[].content_sha256` — digest is the binding, recompute by arithmetic |
| `commitmentId` | batch-settlement identity (not a tx hash) | the settlement leg the consent deliberately leaves to the settlement side (A9's `settlement_receipt` reference, posterior → binds back) |
| `settlementUnbound: true` | explicit "not settled on-chain" arm | the consent's own degraded-semantics rule: a grant that binds no offer is a valid grant, but it is NOT evidence any specific offer was paid |
| settlement XOR | exactly one of `transaction` / `commitmentId` / `settlementUnbound` | the binding-coherence predicate class the AIR field table already defines (payment-within-cap / asset-match / within-validity) |

The settlement XOR is a **binding-coherence predicate** — a deterministic,
offline-checkable constraint over the receipt, exactly the class the AIR author
ruled in on #2922. It belongs to the same family as the consent receipt's
`amount <= amount_cap` and asset-match checks: all three are recompute-by-
arithmetic, no trusted third party.

## 4. The one gap left open — authorization provenance

#3140's out-of-scope note is the exact shape of the missing layer:

> Neutral third-party countersignature / PQ dual-sign product envelopes (can
> ship as a separate permissionless extension key).

A consent reference is **not** a countersignature. A countersignature vouches
for a signature that already exists; the consent is the **origin** grant that
the seller's receipt should point back at. The v2 receipt's `receiptRef` field
is documented as "transport-only; signed fields win on mismatch" — the natural
home for an optional `authorizationRef` that commits to the consent's
`content_sha256`, so a verifier can recompute both digests offline and confirm
the seller's delivery/settlement receipt binds to the human authorization that
preceded it.

## 5. Worked example

Fixture: `examples/agent-payment-consent-receipt/receipt-with-offer-receipt-v2.json`
— a human authorizes 50.00 USDC on Base for a 1-hour A100 x4 GPU lease under
`batch-settlement`, binding the offer by digest.

| Value | Digest |
|---|---|
| offer digest (`references[].content_sha256`) | `9222a5647eb848287c18f74db2e5ddb06d70e846c997fa229aa0346409b62e3d` |
| `contentHash` (delivered body, recomputed in `tools/test_consent_receipt_offer_receipt_v2.py`) | `ec9e88e73beb3f43aac4004bdca73683bf38146a237a4866816572156c472bb0` |
| `commitmentId` (batch-settlement arm) | `0xc0c0…c0` (32 bytes) |
| consent `content_sha256` | `d4db2e011fc527cc618e770ab074c4ca6416dd8c90c05a7819db4c735240d72d` |

All recomputed independently in the test file; the fixture is really Ed25519-
signed (disclosed synthetic authorizer key), money is decimal-string, and the
`offer` reference is a prior artifact (no forward-reference warning).

## 6. Regression criteria

1. **Binds the offer** — `sha256(JCS(offer)) == references[].content_sha256`,
   and the consent's `amount`/`asset`/`chain_id` match the offer.
2. **Settlement XOR holds** — exactly one of `transaction` / `commitmentId` /
   `settlementUnbound`; a two-arm receipt is rejected.
3. **`contentHash` is content-sensitive** — any change to the delivered body
   changes the digest, so a mismatched delivery cannot be passed off.
4. **Authorization is separable** — the v2 receipt proves delivery+settlement;
   it does not prove authorization. A receipt without an `authorizationRef`
   (consent digest) is valid delivery evidence but not authorization evidence.

## 7. Boundary

Free, non-financial documentation plus a read-only checker. No custody,
signing of real grants, transaction verification, funds movement, token
issuance, or trading advice. No claim that any agent-payment product is safe or
compliant. The Ed25519 fixture uses a disclosed synthetic key.

[x402-foundation/x402#3140]: https://github.com/x402-foundation/x402/issues/3140
