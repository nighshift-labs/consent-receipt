# Agent Payment Consent Receipt — example fixtures

Synthetic receipts exercise the checker and the sign/verify tool:

- `valid-receipt.json` — a really-signed, well-formed grant. `content_sha256`
  is computed over the canonical body; `signatures.authorizer` is a real
  Ed25519 signature over that body (synthetic test key). The checker reports
  `ready-for-human-review` with zero flags.
- `unsigned-receipt.json` — the same authorization facts but with no
  `signatures` object. The checker flags `authorizer_signature_missing`, which
  is the exact unsigned-consent-receipt gap the spec exists to close.
- `receipt-with-air-reference.json` — a really-signed consent **grant** (no
  forward reference). The AIR entry that binds it lives in
  `examples/air-consent-receipt-composition/`; the direction is one-way
  (AIR → consent), because a grant is issued before the interaction it
  authorizes.
- `receipt-with-settlement-binding.json` — the standalone consent grant that
  authorizes the *real* §3.5 Polygon fee-split settlement of the
  Settlement-Receipt Binding Extension (PR #2666). The direction is one-way:
  the settlement record binds **back** to this grant by *containment* (its
  `agentId` equals the grant's `agent`; the summed per-leg amount ≤
  `amount_cap`; `timestampMs` within `[issued_at, expires_at]`). The
  `actionRef` and both per-leg digests are recomputed (not invented) from the
  extension's pinned bytes — see
  `tools/test_consent_receipt_settlement_binding.py` and
  `docs/consent-receipt-settlement-binding.md`.
- `receipt-with-authz-attestation-reference.json` — the standalone consent
  grant that is the **root** of the #3086 delegation chain. The attestation
  binds back: its `human_anchor` commits to this grant's `content_sha256`
  (`sha256:<sha256(content_sha256)>`), so the chain proves a valid delegation
  from a human who signed *these* terms. See
  `tools/test_consent_receipt_authz_attestation.py` and
  `docs/authz-provenance-consent-composition.md`.
- `receipt-with-risk-decision-reference.json` — the standalone consent grant
  that a #3142 risk-decision record gates. The decision binds back by
  *containment*: its `evidence.evaluatedAt` must fall within the grant's
  `[issued_at, expires_at]` window and the payment within its cap. See
  `tools/test_consent_receipt_risk_decision.py` and
  `docs/risk-decision-provenance-consent-composition.md`.
- `receipt-with-offer-reference.json` — the consent grant that binds an
  **accepted offer** as a *prior* artifact (correct direction — the offer
  exists before the grant). The `offer` reference carries the offer's
  `content_sha256` (the #3006 `offerDigest`), and the grant's `amount`/`asset`/
  `chain_id` match the offer's terms — the payer-side complement to #3006's
  receipt-side `offerDigest` fix. See
  `tools/test_consent_receipt_offer_reference.py` and
  `docs/receipt-offer-binding-composition.md`.
- `receipt-with-offer-receipt-v2.json` — the consent grant that binds a
  **batch-settlement offer** as a prior artifact. It is the authorization half
  of the #3140 offer-receipt v2 composition: the v2 receipt's `contentHash`
  (delivered bytes) and `commitmentId` (batch settlement) are the delivery/
  settlement half, produced *after* payment and bound back to this grant on
  their own side. See `tools/test_consent_receipt_offer_receipt_v2.py` and
  `docs/offer-receipt-v2-consent-composition.md`.
- `receipt-with-auth-hints-binding.json` — the consent grant that closes the
  #3009 entitlement-binding gap: it binds the authenticated subject
  (`authorizer`) to a payer wallet that differs from it, via two committed
  prior-artifact references — an `entitlement_policy` (naming the entitlement
  owner under third-party payment) and a `delegation` (justifying the distinct
  payer wallet). Both digests are recomputed, not invented. See
  `tools/test_consent_receipt_auth_hints_binding.py` and
  `docs/auth-hints-entitlement-binding-composition.md`.

In every composition the direction is **downstream → consent**: a grant is
issued before the interaction it authorizes, so it never carries a forward
`references[]` to the receipts, settlements, attestations, or decisions that
result from it — those bind back to the grant on their own side.

All money values are **decimal strings** (float-free). All signed fixtures
carry a real Ed25519 authorizer signature over a disclosed synthetic test key
(`tools/sign_consent_receipt.py`); no fixture corresponds to a real wallet,
agent, or payment.

To check them:

```sh
python3 tools/consent_receipt_check.py examples/agent-payment-consent-receipt/valid-receipt.json
python3 tools/consent_receipt_check.py examples/agent-payment-consent-receipt/unsigned-receipt.json --fail-on review
python3 tools/sign_consent_receipt.py verify examples/agent-payment-consent-receipt/valid-receipt.json
```
