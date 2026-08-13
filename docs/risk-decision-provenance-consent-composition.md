# Binding a consent receipt to a risk-decision provenance record

A field table for how a consent receipt and a risk-decision provenance record
compose, written against the `risk-decision-provenance` extension proposed in
[x402-foundation/x402#3142] ("Risk Decision Provenance for Trustworthy
Autonomous Payments", `sauravsingla`, 2026-08-13). The proposal standardizes a
compact, machine-readable record describing **how a risk/trust provider produced
a payment decision** (`decision`, `riskScore`, `confidence`, `model`,
`policy`, `evidence`, `fallbackUsed`, `reasonCodes`) so a resource server can
enforce its own policy on top of the decision's freshness and health.

This doc is the deliverable promised in the A10 convergence note on #3142: the
consent receipt composes with the proposal as a *sibling* — the provenance
record answers **"is this ALLOW decision trustworthy?"**, the consent receipt
answers **"did a human authorize this exact payment?"** — and the two join by
**containment** with no new field on either side.

## 1. The gap this closes

The proposal's own policy examples gate on the *decision process*, not on the
*human authorization*:

```text
if driftStatus == "DEGRADED":  require step-up authorization
if modelVersion not in approvedVersions: reject
if confidence < 0.70: require additional evidence
if freshnessSeconds > 300: require re-evaluation
```

Every one of those conditions asks "is the machine's ALLOW healthy and fresh?"
None of them asks "did a human sign off on **this** amount, **this** cap,
**this** purpose, **this** expiry?" A fully fresh, active, high-confidence ALLOW
is still a **machine** decision — it proves the model was healthy when it said
yes, not that a human said yes.

These are two orthogonal provenance axes that the proposal, correctly, does not
conflate — but it also does not name the missing one. They are:

- **Decision-process provenance** (the proposal): *was the ALLOW produced by a
  current, non-degraded model under an approved policy, on fresh evidence?*
- **Authorization provenance** (the consent receipt): *did a human authorize
  this specific payment, up to this cap, for this purpose, until this time?*

A resource server enforcing "autonomous payment policy" needs both, as
*separable, independently recomputable* conditions. The consent receipt
(`docs/agent-payment-consent-receipt.md`) is the authorization record; a
verifier holding both answers:

- **"Is the decision trustworthy?"** — the proposal's model/policy/evidence
  health checks.
- **"Was this payment inside a human's signed authorization?"** — the consent
  containment check below.

## 2. The binding direction (containment, no new field)

A consent grant is issued **before** the decision that gates the payment, so the
consent carries **no** forward `references[]` to the risk-decision record — the
decision does not exist yet at grant time. The direction is one-way, downstream
→ consent: a verifier holds the (standalone) consent and the decision record
together and checks the decision (and the payment it gates) sit **inside** the
grant's authorization.

| Decision record field | Consent authorization | Containment check |
|---|---|---|
| `evidence.evaluatedAt` | `issued_at` / `expires_at` | `evaluatedAt ∈ [issued_at, expires_at]` |
| the payment the decision gates | `amount` / `amount_cap` | `amount ≤ amount_cap` |
| the payer principal | `agent` | must be the same principal |
| `policy` | `references[].policy` (optional) | the same governing policy, if the consent declares one |

No record-level identifier is required to make the join: the containment check
runs by value (time within window, amount within cap, same principal). If a
provider assigns no decision id, the content digest itself is the join key.

## 3. Worked example — the proposal's own shape

The fixture `examples/agent-payment-consent-receipt/receipt-with-risk-decision-reference.json`
is a **standalone** consent grant: 50.00 USDC on Base, `issued_at
2026-08-13T09:00Z`, `expires_at 2026-08-14T09:00Z`, no forward reference. The
decision record that gates the payment is the proposal's example shape:

```json
{
  "decision": "ALLOW",
  "riskScore": 18,
  "confidence": 0.94,
  "model":    { "id": "agent-payment-risk", "version": "3.4.1", "status": "ACTIVE", "driftStatus": "NORMAL" },
  "policy":   { "id": "enterprise-payment-policy", "version": "2.1" },
  "evidence": { "evaluatedAt": "2026-08-13T09:30:00Z", "freshnessSeconds": 12, "digest": "sha256:9f7b3c2e…" },
  "fallbackUsed": false,
  "reasonCodes": ["ESTABLISHED_COUNTERPARTY", "LOW_TRANSACTION_VELOCITY"]
}
```

Recomputed independently here (RFC 8785 JCS over the record bytes; see
`tools/test_consent_receipt_risk_decision.py`):

| Field | Value |
|---|---|
| decision record digest | `5531f9b812e85c9989b079bbb091a24e046ed405f0bf844f666bd771eca8af84` |
| `evidence.evaluatedAt` | `2026-08-13T09:30:00Z` — inside the consent's `[09:00, next-day 09:00]` window |

## 4. The containment check (two independent gates)

Given a consent receipt and the risk-decision record, a verifier answers "was
this payment allowed by a healthy decision **and** authorized by a human" in two
independent passes:

**Gate A — decision-process health (the proposal's own conditions):**

1. `sha256(JCS(record))` resolves — the record is exactly what was presented
   (recomputable binding).
2. `model.status == "ACTIVE"` and `driftStatus != "DEGRADED"`.
3. `model.version ∈ approvedVersions` (local policy).
4. `evidence.freshnessSeconds ≤ threshold` (e.g. 300) and `evidence.evaluatedAt`
   is within the consent's validity window.
5. `confidence ≥ threshold` (e.g. 0.70); if `fallbackUsed`, apply the stricter
   policy branch.

**Gate B — human authorization (the consent-side containment):**

6. Asset match — `receipt.asset` within the payment's authorized asset.
7. Amount within cap — `amount ≤ amount_cap`.
8. Within the validity window — the payment timestamp ∈ `[issued_at, expires_at]`.
9. Scope covered — the payment's action is within `receipt.scope`.

Steps 1–5 are the proposal's own health gate; steps 6–9 are the consent-side
containment the proposal deliberately does not state. The two gates are
*separable*: a payment can pass Gate A (healthy ALLOW) and fail Gate B (no human
signed off), or vice versa — which is exactly why they must not share one record.

## 5. Alignment notes (for the proposal author)

1. **Attested vs recomputable.** The trust-provider thread (#2299) already
   landed the lesson that "a score is only worth the evidence a relying party
   can independently recompute." The proposal gestures at this ("content-
   addressed digests or provider signatures") but does not separate the two
   classes. Recommend marking explicitly: `decision`/`riskScore`/`confidence`/
   `fallbackUsed`/`reasonCodes` are **signed-asserted** (only as trustworthy as
   the issuer), while `model`/`policy`/`evidence` are **recomputable**
   (content-addressed + timestamped). A verifier should be able to re-derive
   freshness/drift/version without trusting the provider's word for them.
2. **Canonicalization.** The consent receipt's `content_sha256` uses sorted-key
   compact JSON; the proposal's `evidence.digest` does not yet pin a
   canonicalizer. Binding is by reference hash, so they never collide, but the
   extension should pin one (JCS / RFC 8785 is the natural choice and is
   already the shared convention in the settlement-receipt-binding and
   trust-provider extensions).
3. **`id` pointer form.** The proposal defines no record-level identifier. If
   the extension adopts one, a downstream record can carry it verbatim;
   otherwise the content digest itself keeps the record resolvable with no new
   field.

## 6. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures,
move money, issue tokens, or give trading/investment advice. It makes no claim
that any agent-payment product is safe or compliant.

[x402-foundation/x402#3142]: https://github.com/x402-foundation/x402/issues/3142
