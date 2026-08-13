# Binding a consent receipt to a settlement record

A field table for how a consent receipt and a settlement record compose, written
against the [Settlement-Receipt Binding Extension] (`x402-foundation/x402` PR
#2666, `specs/extensions/extension-settlement-receipt-binding.md`, draft `v0`)
and the receipt format it commits to, `vaara.receipt/v1` (IETF
`draft-sirkkavaara-vaara-receipt`).

This is the deliverable promised in the A9 convergence note on PR #2666: the
consent receipt composes with the extension as a *sibling* — the extension
binds **what settled**, the consent receipt binds **who authorized it** — and
the two join by **containment**, with no new field on either side.

## 1. The gap this closes

The extension's conformance gate (§5) proves four things: the `action_ref`
recomputes, the settlement digest resolves against the receipt's
`evidenceRef`, the receipt signature verifies, and the lifecycle steps are
distinct. None of those answers *"did a human authorize this exact action, up
to this cap, for this purpose, until this time?"* — and the extension says so
explicitly (§9: "Signature authority is trusted, not recomputed… not that the
signer was honest or authorized to issue it").

The consent receipt (`docs/agent-payment-consent-receipt.md`) is that
authorization record. A verifier holding both answers:

- **"Did X settle?"** — the extension's `settlement_binding_resolves`.
- **"Was X inside a human's signed authorization?"** — the consent-side
  containment check below, which is *per-role* for exactly the reason the
  extension's §3.5 is per-role.

## 2. The binding direction (containment, no new field)

A consent grant is issued **before** the settlement it authorizes, so the
consent carries **no** forward `references[]` to the settlement — the settlement
does not exist yet at grant time. The direction is one-way, downstream →
consent: a verifier holds the (standalone) consent and the settlement record
together and checks that the settlement's action tuple sits **inside** the
grant's authorization.

| Settlement record field | Consent authorization | Containment check |
|---|---|---|
| `agentId` (§3.1 action tuple) | `agent` | must be equal |
| `scope` (§3.1 action tuple) | `scope` (least-privilege list) | the action's scope must be covered |
| `settlement.asset` / `amount` / `decimals` (§3) | `asset` / `amount_cap` | asset matches; `Σ amount/10^decimals ≤ amount_cap` |
| `timestampMs` (§3.1 action tuple) | `issued_at` / `expires_at` | `timestampMs ∈ [issued_at, expires_at]` |
| `actionRef` (§3.1 join key) | — | `sha256(JCS(action tuple)) == actionRef` (the extension's own `action_ref_recomputes`) |

This reuses the extension's own §4 distinction, mirrored: **`digest` is the
binding, `ref` is advisory.** The settlement's `actionRef` names the action and
is shared across the merchant leg and the fee leg; the per-leg digests
distinguish them, because the two records differ in `payTo` and therefore in
digest. A fee-leg record presented where a merchant-leg record is expected fails
the digest check, exactly as §4 requires of `evidenceRef.digest`.

## 3. Worked example — the real §3.5 Polygon fee-split

The extension's §3.5 records a production EVM `exact` settlement on Polygon
mainnet (tx `0xa9e6c6a9…3249`, block 90308815): one signed payer authorization
moved 2.0 JPYC through a split forwarder — 1.0 to the merchant, 1.0 to a fee
recipient. Both legs derive the **identical** `actionRef` from the same action
tuple; they differ only in `settlement.payTo`, so they differ in digest.

Recomputed independently here (RFC 8785 JCS over the pinned bytes; the action
tuple digest reproduces the extension's pinned `actionRef` byte-for-byte):

| Leg | `payTo` | `actionRef` (id) | settlement digest |
|---|---|---|---|
| merchant | `0x52d4…cA81` | `sha256:08d26a53…a66169` | `f59cdf0520f1…f1eeb91` |
| fee | `0x4284…c560` | `sha256:08d26a53…a66169` | `e2d8825bfc2b…344f9ba4a` |

The consent that authorizes this settlement is a **standalone** grant — same
`agent` as the action tuple, `asset: JPYC`, `amount`/`amount_cap: "2.00"` —
with no reference to either leg. See
`examples/agent-payment-consent-receipt/receipt-with-settlement-binding.json`
and `tools/test_consent_receipt_settlement_binding.py` (which recomputes the
legs and asserts the containment holds).

## 4. The containment check (per-role)

Given the consent and the settlement record(s), a verifier answers "was this
settlement inside the human's signed authorization" by:

1. **Join recomputes** — `sha256(JCS(action tuple)) == actionRef` (the
   extension's own `action_ref_recomputes`).
2. **Binding resolves** — `sha256(JCS(settlement record)) == evidenceRef.digest`
   (the extension's `settlement_binding_resolves`).
3. **Asset match** — `settlement.asset` is within the consent's authorized
   `asset`.
4. **Amount within cap** — `settlement.amount / 10^settlement.decimals ≤
   consent.amount_cap`, summed over all legs of one action.
5. **Within the validity window** — `settlement.timestampMs ∈ [issued_at,
   expires_at]`.
6. **Scope covered** — the settlement's `actionType`/`scope` is within the
   consent's `scope` capability list.

Steps 1–2 are the extension's own gate, restated here so the join carries real
resolving power; steps 3–6 are the consent-side containment that the extension
deliberately does not state.

## 5. Alignment notes (for the extension authors)

1. **Canonicalization.** The consent receipt's `content_sha256` uses sorted-key
   compact JSON excluding `content_sha256`/`signatures`; the extension mandates
   RFC 8785 JCS. The two canonicalizers agree on the §3.5 records (ASCII
   strings, integers, booleans — verified above), but they are not the same
   function. The consent is content-addressed on its own side, so they never
   collide; aligning the consent receipt to JCS would let one canonicalizer
   serve both (mirrors `docs/air-consent-receipt-composition.md` §8.1).
2. **Decimal strings.** The extension stores money as atomic-integer strings +
   `decimals` (§3.1); the consent receipt uses decimal strings for
   `amount`/`amount_cap`. Step 4 therefore divides by `10^decimals`, and the
   float-free decimal-string form makes the comparison exact (mirrors the AIR
   composition §8.2).
3. **`ref` pointer form.** The extension's §4 `evidenceRef.ref` is the
   `x402:action_ref/<actionRef>` pointer. That pointer names the action on the
   settlement side; the consent side needs no pointer because the containment
   check runs by value (agent + scope + amount within the grant).

## 6. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures,
move money, issue tokens, or give trading/investment advice. It makes no claim
that any agent-payment product is safe or compliant.

[Settlement-Receipt Binding Extension]: https://github.com/x402-foundation/x402/pull/2666
