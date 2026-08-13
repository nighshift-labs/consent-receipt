# Binding a consent receipt to a human-anchored authorization attestation

A field table for how a consent receipt and an authorization attestation
compose, written against the authorization-provenance extension proposed in
[x402-foundation/x402#3086] ("Proposal: Authorization-provenance extension,
human-anchored, ZK-attested capability binding for PAYMENT-REQUIRED /
PAYMENT-RESPONSE", `rudizee007` = Rudolf J. Coetzee, Violet Sky Security SEZC,
2026-08-08). The proposal adds an opt-in `authz_attestation` to the payment
payload so a merchant or facilitator can verify, offline and without PII, that
the agent held authority for exactly this action and that a human ultimately
anchored it.

This doc is the deliverable promised in the A11 convergence note on #3086. The
finding: the consent receipt and the proposal occupy **two layers of the same
axis**, and they compose by digest with no new field on either side. The
proposal proves the *delegation chain* (the agent's authority is a valid
strict-subset of a human-rooted chain, revealed as a Groth16 proof); the
consent receipt proves the *human's actual grant* (a signed, cleartext
amount/cap/purpose/expiry). Together they answer both "was this agent's
authority validly delegated from a human?" and "did a human authorize **this**
amount, **this** cap, **this** purpose, **this** expiry?"

## 1. The gap this closes — and what changed

The standing thesis has been "the signed human-authorization layer is
unclaimed in x402." That was true for the earlier threads (#2922 AIR, #2734
draft-morrison, #2332 Mycelium Trails, #2666 settlement binding — all
machine-side). **#3086 changes it**: a serious author (IETF OAuth SPT-Txn draft,
a working Groth16 implementation, a formal security paper) has now proposed the
human-anchored axis directly, five days ago, and received zero response.

That does not kill this position; it sharpens it. The proposal anchors
the *person* with a "rotating one-way ZK commitment" and proves the *chain* of
delegation — but the human's **grant terms** (the specific amount, cap, purpose,
and expiry) are deliberately opaque, folded inside the proof and commitment. The
consent receipt is the complementary primitive: it carries those terms in
cleartext, signed by the human, so they are human-auditable without a proving
ceremony. The two are:

- **Delegation-chain provenance** (#3086): *was the agent's authority a valid
  strict-subset of a human-rooted delegation chain, with no intermediate scopes
  revealed?* (Groth16, ~1.5 ms verify, ~759 B, no PII on the wire.)
- **Grant provenance** (the consent receipt): *did the human sign a grant of
  exactly this amount / cap / purpose / expiry, and is the payment inside it?*
  (A plain hash-bound JSON envelope — no ZK, no ceremony, readable by the human
  who signed it.)

The consent receipt is the cleartext **root** of the chain that #3086's proof
establishes: the "rotating one-way commitment to the authorizing person" should
commit to the consent receipt's `content_sha256` (a commitment to the exact
grant terms), not just to a person identifier — otherwise the chain proves a
valid delegation from *someone* without proving *what* they authorized.

## 2. The binding direction (`human_anchor` → consent, no new field)

A consent grant is issued **before** the interaction it authorizes, so the
consent carries **no** forward `references[]` to the attestation — the
attestation does not exist yet at grant time. The direction is one-way,
downstream → consent: the attestation's `human_anchor` commits to the consent's
`content_sha256`, making the chain's root the exact grant terms.

| Attestation field | Consent source | Meaning |
|---|---|---|
| `human_anchor` | `consent.content_sha256` | a one-way commitment to the signed grant digest — the chain proves a valid delegation from a human who signed **these** terms |
| `scope_binding` | — | the hash binding the attestation to this exact transaction context (replay protection) |
| `zk_proof` / `delegation_depth` | — | the delegation-chain proof (the proposal's own verification) |

No new field is required on the consent side: the consent is the commitment's
**pre-image** (`human_anchor = sha256(consent.content_sha256)`). A verifier
checks `sha256(JCS(attestation))` resolves, then that `human_anchor` opens to
the grant whose terms it must honor.

## 3. Worked example — the proposal's own shape

The fixture `examples/agent-payment-consent-receipt/receipt-with-authz-attestation-reference.json`
is a **standalone** consent grant: 50.00 USDC on Base, with no forward
reference. The attestation that anchors it commits back to the grant:

```json
{
  "format": "spt-txn/1",
  "human_anchor": "sha256:<sha256(consent.content_sha256)>",
  "scope_binding": "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9",
  "delegation_depth": 2,
  "zk_proof": "groth16:bn254:opaque-proof-bytes-0123456789abcdef"
}
```

Recomputed independently here (RFC 8785 JCS over the attestation bytes; see
`tools/test_consent_receipt_authz_attestation.py`):

| Field | Value |
|---|---|
| consent `content_sha256` | `c639f6ad440dcfded308342a9ca6f4efc18cc79430e5b07e07d9d8d27a550ca9` |
| `human_anchor` | `sha256:95449505510d87fae9401e810f65c10ca79366496e1ba3406bc9deacc4af9632` |

The `human_anchor` is a function of the grant terms: two different grants yield
two different anchors, so the chain is bound to *what* was authorized, not just
*who*.

## 4. The containment check (two independent gates)

Given a consent receipt and the attestation, a verifier answers "was this agent
validly delegated from a human **and** was the payment inside the human's
signed grant" in two independent passes:

**Gate A — delegation-chain validity (#3086's own verification):**

1. `sha256(JCS(attestation))` resolves (the attestation, proof included, is
   exactly what was presented).
2. `human_anchor == sha256(consent.content_sha256)` — the chain's root is the
   grant whose terms the verifier will enforce.
3. `zk_proof` verifies — the delegation chain is valid and the agent's scope is
   a strict subset of the root scope, with `delegation_depth` bounded.
4. `scope_binding` matches this exact transaction context (no replay across
   transactions).

**Gate B — human-consent containment (the receipt's job):**

5. Asset match — `receipt.asset` within the payment's authorized asset.
6. Amount within cap — `amount ≤ amount_cap`.
7. Within the validity window — the payment timestamp ∈ `[issued_at, expires_at]`.
8. Scope covered — the payment's action is within `receipt.scope`.

Steps 1–4 are the proposal's own verification; steps 5–8 are the consent-side
containment the proposal keeps opaque. The two gates are *separable*: a payment
can pass Gate A (valid delegation chain) and fail Gate B (the human capped this
purpose at a lower amount), or vice versa. That is exactly why the human's grant
terms must not be folded into the ZK proof and lost — they are the only thing
that distinguishes "a valid chain existed" from "the human authorized *this
spend*."

## 5. Alignment notes (for the proposal author)

1. **Make `human_anchor` commit to the grant, not just the person.** "A rotating
   one-way ZK commitment to the authorizing person" proves *who*, silently. If
   `human_anchor` is computed over `consent_receipt.content_sha256` (the exact
   amount/cap/purpose/expiry), the chain proves a valid delegation **from a
   human who signed these terms** — and the consent receipt is the cleartext
   witness anyone can read and check. This is the single highest-value change to
   the proposal, and it requires no new field: the consent receipt is the
   commitment's pre-image.
2. **Canonicalization.** `content_sha256` uses sorted-key compact JSON (RFC 8785
   JCS). The proposal pins no canonicalizer for `scope_binding` or the
   attestation; binding is by reference hash so they never collide, but the
   extension should pin one — JCS is the shared convention already used in the
   settlement-receipt-binding and trust-provider extensions.
3. **Scope answer.** The proposal asks the TSC whether authorization provenance
   belongs in the core spec or as a registered scheme. The consent receipt is
   evidence for "registered scheme": it is a plain, self-contained,
   human-signed object that any x402 payload can reference without touching the
   core 402 flow — the same opt-in posture the proposal already assumes.

## 6. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures
(ZK or otherwise), move money, issue tokens, or give trading/investment advice.
It makes no claim that any agent-payment product is safe or compliant.

[x402-foundation/x402#3086]: https://github.com/x402-foundation/x402/issues/3086
