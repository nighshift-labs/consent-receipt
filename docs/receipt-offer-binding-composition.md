# Binding a consent receipt to the accepted offer

A field table for how a consent receipt closes the gap named in
[x402-foundation/x402#3006] ("Privacy-minimal receipt does not bind the payment
terms of the accepted offer", `johnakeke`, 2026-07-31; converged 08-02 by
`wowlegend`/Tersign to a single content-addressed `offerDigest` field).

This is the deliverable promised in the A13 convergence note on #3006. The
finding: #3006 is the *receipt-side* gap (the server-signed privacy-minimal
receipt omits `amount`/`asset`/`payTo`/`scheme` and cannot prove which offer it
paid), and the consent receipt is the *payer-side* complement — it carries the
terms the receipt omits **and** binds the accepted offer as a prior artifact.
The two compose by digest with no new field on either side.

## 1. The gap this closes

The extension's offer (§140–153) fully represents the proposed payment terms
(`resourceUrl`, `scheme`, `network`, `asset`, `payTo`, `amount`). The receipt
(§269–282) requires only `network`, `resourceUrl`, `payer`, `issuedAt` — the
privacy-minimal default omits the transaction reference, and the receipt
carries **no** `amount`, `asset`, `payTo`, `scheme`, offer digest, or payment
digest.

The impact the issue states precisely: a valid receipt signature proves only
that the resource server signed the fields *present* in the receipt, not the
payment terms deliberately omitted. A low-value receipt can be passed off as a
higher-priced offer, or a payment in another asset, or to another payee —
because nothing in the receipt distinguishes them.

The thread's convergence is the right minimal mechanism (wowlegend, 08-02): a
single `offerDigest` field — "the digest of the canonical bytes of the signed
offer it accepted" — so binding reduces to arithmetic a third party can run
offline (recompute the presented offer's canonical digest, compare to the
committed one). That is exactly the consent receipt's discipline:
**content-addressed, digest is the binding, recompute by arithmetic.**

## 2. What the consent receipt adds (payer side)

#3006 fixes the *server's* receipt so it proves which offer was paid. The
consent receipt is the *payer's* record, issued **before** the payment, that
proves a human authorized **these** terms. Its fields already cover the terms
the privacy-minimal receipt omits:

| Consent field | #3006 receipt gap | Meaning |
|---|---|---|
| `amount` / `amount_cap` | `amount` | the exact spend and its ceiling (decimal strings) |
| `asset` | `asset` | the asset authorized |
| `chain_id` | `network` | the network (e.g. `8453` = `eip155:8453`) |
| `scope` + `purpose` | `scheme` / `resourceUrl` | the capability and the human-readable purpose |
| `references[].offer` | offer digest | the accepted offer, bound by digest |

The offer is a **prior** artifact — it exists before the human grants consent —
so the consent references it via `references[]` (correct direction), unlike the
settlement/trail/attestation/decision records which bind **back** to the
consent on their own side.

## 3. The reference shape

A consent receipt's optional `references[]` list accepts a type-generic
`{type, id, content_sha256}` entry. The offer reference maps onto #3006's
`offerDigest` directly:

| `references[]` field | #3006 source | Meaning |
|---|---|---|
| `type` | (scheme constant) | `"offer"` |
| `id` | `resourceUrl` | the join key naming the accepted offer |
| `content_sha256` | `offerDigest` | `sha256(JCS(offer))` — the content binding |

This is the same §4 rule the settlement-receipt-binding extension already
lands: **digest is the binding, id is advisory.** A verifier recomputes
`sha256(JCS(offer))` and compares to `content_sha256`; any change to `amount`,
`asset`, `payTo`, `scheme`, or `resourceUrl` changes the canonical bytes and
breaks the binding — no per-field comparison logic needed.

## 4. Worked example

The fixture `examples/agent-payment-consent-receipt/receipt-with-offer-reference.json`
authorizes 50.00 USDC on Base for `coo-icp-agent-consult` and binds the offer:

```json
{
  "resourceUrl": "https://api.coo-icp.example/agent-consult",
  "scheme": "exact",
  "network": "eip155:8453",
  "asset": "USDC",
  "payTo": "0x9a1B2c3D4e5F60718293A4b5C6d7E8f90a1B2c3D4",
  "amount": "50.00"
}
```

Recomputed independently here (RFC 8785 JCS; see
`tools/test_consent_receipt_offer_reference.py`):

| Field | Value |
|---|---|
| offer digest (`offerDigest` / `references[].content_sha256`) | `9d40ae1bf0fea0065f042fadb39420b718182a797da9c4d4263e49a1ed7c7c09` |
| consent `amount` / `amount_cap` | `"50.00"` (matches the offer) |

## 5. The four regression criteria, restated on the consent side

#3006's acceptance bar survives into the consent receipt unchanged:

1. **Validates against offer A** — `sha256(JCS(offer A)) == references[].content_sha256`
   and the consent's `amount`/`asset`/`chain_id` match offer A's terms.
2. **Fails against offer B** — changing `amount`, `asset`, `payTo`, `scheme`, or
   `resourceUrl` changes the digest; the binding breaks.
3. **Privacy-minimal does not lose the binding** — the consent commits to the
   offer *digest*, not the terms, so the terms stay human-readable only on the
   consent side; the binding is a commitment, not a disclosure.
4. **Degraded semantics are explicit** — a consent receipt that binds no offer
   (standalone) is a valid grant, but it is NOT evidence that any specific
   offer was accepted; that distinction is the checker's job, not the receipt's.

## 6. Alignment notes (for the extension authors)

1. **Canonicalization.** The consent receipt uses sorted-key compact JSON
   (RFC 8785 JCS) for `content_sha256`; the offer digest must use the same
   canonicalizer, or the two sides will never agree. Pin JCS for `offerDigest`.
2. **EIP-712 vs JWS.** wowlegend's note applies verbatim: the EIP-712 path needs
   a versioned receipt type (the type hash changes); the JWS path can carry the
   digest additively. Either way the digest, not the transport, is load-bearing.
3. **Evaluator-side rule.** Adopt the §4.5.1-style statement: a receipt that
   does not commit to the accepted offer's terms MUST NOT be evaluated as proof
   that a specific offer was paid. The consent receipt is that commitment on
   the payer side.

## 7. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures,
move money, issue tokens, or give trading/investment advice. It makes no claim
that any agent-payment product is safe or compliant.

[x402-foundation/x402#3006]: https://github.com/x402-foundation/x402/issues/3006
