# Binding authentication, payer, and entitlement — the auth-hints gap

A field table for how a consent receipt closes the gap named in
[x402-foundation/x402#3009] ("auth-hints does not define how authentication
identity, payer identity, and entitlement are bound", `johnakeke`, 2026-07-31).

The finding: #3009 is the *entitlement-binding* gap. `auth-hints` treats
authentication and payment as parallel concerns and permits the authenticated
subject to differ from the payer "subject to server policy" — but the spec never
says what that policy must express, nor provides a binding record among the
authenticated subject, payer wallet, payment requirements, and final
entitlement. The consent receipt is exactly that binding record, on the payer
side, before the payment.

## 1. The gap this closes

The spec states the split at `extension-auth-hints.md:28`:

> Authentication and payment are parallel concerns — authentication identifies
> the client, payment authorizes the transfer of value.

and at `:241–253` requires the server to validate both **independently**, while
"the authenticated client MAY use one or more payer wallets, subject to server
policy" — with no definition of what that policy must express at minimum.

#3009 states the impact precisely: if an implementation combines two
independent Boolean results as `authenticated && paid` without checking the
identity mapping, one subject's credentials can ride a valid payment from
another wallet, and the server assigns the entitlement to the wrong account,
tenant, or agent. A receipt signature proves the server signed the fields
*present*; it does not prove that *this* payment should grant *this*
authenticated subject the entitlement to *this* resource.

The comment thread converged on the right shape (`0xbrainkid`, 07-31): an
**entitlement receipt** that "proves why those two facts are allowed to resolve
to this resource for this subject," binding authenticated subject, payer,
resource/request fingerprint, the selected entitlement policy, the
delegation/tenant reference, `issued_at`/`expires_at`, and the verifier/server
decision. That is the consent receipt's discipline: **content-addressed,
digest is the binding, recompute by arithmetic, signed by a human.**

## 2. What the consent receipt adds

#3009's proposed solution requires an implementation to "explicitly select and
record at least one entitlement policy" and to bind "the authenticated subject,
payer, resource/request fingerprint, and the policy/delegation identifier used."
The consent receipt carries those bindings already:

| #3009 binding element | Consent field | Meaning |
|---|---|---|
| authenticated subject | `authorizer` | the human subject who authenticated and signed the grant |
| payer identity / wallet | `agent` + `asset` + `chain_id` + `references[].delegation` | the payer the grant authorizes; the delegation reference names the wallet when it differs from the authorizer |
| resource / request fingerprint | `scope` + `purpose` (+ `references[].content_sha256`) | the capability and the human-readable purpose the entitlement covers |
| selected entitlement policy | `references[].entitlement_policy` | the policy identifier + digest, chosen and committed |
| delegation / tenant mapping | `references[].delegation` / `references[].tenant` | the record that justifies an authenticated-subject ≠ payer mapping |
| issued_at / expires_at | `issued_at` / `expires_at` | the grant's validity window |
| verifier / server decision | `signatures.authorizer` + binding-coherence predicates | the human's signed authorization, checked offline against the payment |

The one element the consent receipt adds that a server-side entitlement receipt
cannot: it is signed by the **human**, so the entitlement is bounded by the
authorizer's actual intent (`amount`/`amount_cap`, `purpose`, `expires_at`),
not merely by the server's policy decision.

## 3. The four entitlement policies, restated as references

#3009's four allowed policies map onto the receipt's prior-artifact
`references[]` (the checker is type-generic — no new code):

| #3009 policy | Consent representation |
|---|---|
| 1. authenticated subject controls the payer wallet | **no** `delegation` reference — the authorizer signature over `asset`/`chain_id` is the proof of control |
| 2. payer wallet explicitly delegated to the subject | `references[].delegation` — `{type:"delegation", id:"<delegation id>", content_sha256:"<digest>"}` |
| 3. both map to the same verified account/tenant | `references[].tenant` — the account/tenant binding record, by digest |
| 4. resource allows third-party payment and defines entitlement ownership | `references[].entitlement_policy` — the policy that names the entitlement owner |

The policy and delegation records are **prior** artifacts — they exist before
the grant — so the consent references them (correct direction), unlike the
receipts the interaction produces, which bind back to the consent.

## 4. Worked example

The fixture `examples/agent-payment-consent-receipt/receipt-with-auth-hints-binding.json`
is the delegation case (policy 2 + 4): the authenticated subject
`human-pubkey-xyz789` authorizes `agent:openpay/x402-mcp-authhints` to spend
`25.00` USDC on Base (`8453`) for `premium-data`, while the payer wallet
`0x9a1B2c3D4e5F60718293A4b5C6d7E8f90a1B2c3D4` differs — justified by the two
committed references:

| Reference | Digest (`content_sha256`) |
|---|---|
| `entitlement_policy` (`policy:authhints/delegated-payer-v1`) | `d8df59e3230c3796d5c33dac8c12fc4f7b42355907b0eef7e139ec2076242553` |
| `delegation` (`delegation:authhints/wallet-delegation-2026-08-13`) | `d9fba67a90a148b68e7dc791623a1743dd7e026a0f23cc0bcbe9bc0c3656c119` |

Both digests recomputed independently in
`tools/test_consent_receipt_auth_hints_binding.py`. The fixture is really
Ed25519-signed (synthetic authorizer key), `flags=0`,
`content_sha256 872473f8…`.

## 5. What "policy must express at minimum" means, made concrete

#3009 asks the spec to say what the server policy must express at minimum. The
consent receipt's field set is that minimum, and it composes with the AIR
author's accepted amendments — **binding-coherence predicates**
(payment-within-cap, asset-match, within-validity) and the
`{expires_at_field}` computable freshness input — so the entitlement can be
checked offline: was this payment inside the signed cap, in the right asset, on
the right chain, before expiry, and justified by a committed policy/delegation
digest?

## 6. Alignment notes (for the extension authors)

1. **A binding record, not a Boolean.** Replace `authenticated && paid` with
   `authenticated && paid && entitlement_bound`, where the third term is a
   digest-bound grant (the consent receipt) or an equivalent signed record.
2. **Prior-artifacts-only direction.** The policy/delegation records predate the
   grant; the receipt binds forward to them. The settlement/receipt that results
   binds back to the consent. Do not flatten the two directions.
3. **Canonicalization.** The policy/delegation digests must use the same JCS
   (RFC 8785) canonicalizer as `content_sha256`, or the sides never agree.
4. **SATP/AgentFolio note.** `0xbrainkid`'s framing — settlement, identity, and
   authorization as separately verifiable facts, joined into a portable receipt
   — is the same three-axis split this composition documents; the consent
   receipt is the authorization fact in cleartext-signed form.

## 7. Boundary

This is free, non-financial documentation plus a read-only checker. It does not
custody funds, sign or verify transactions, verify cryptographic signatures,
move money, issue tokens, or give trading/investment advice. It makes no claim
that any agent-payment product is safe or compliant.

[x402-foundation/x402#3009]: https://github.com/x402-foundation/x402/issues/3009
