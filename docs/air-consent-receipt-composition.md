# Composing AIR receipts with payment-consent receipts

A field-shape drop-in for binding a human-signed payment-consent receipt into
an [Agent Interaction Receipt (AIR)](https://github.com/crisnovillo1991/agent-receipt-spec) entry. Written against AIR **v0.2**
(`crisnovillo1991/agent-receipt-spec`, `SPEC.md`) and its **v0.3 Draft 2**
(`SPEC-v0.3-draft.md`), the direct output of
[x402-foundation/x402#2922](https://github.com/x402-foundation/x402/issues/2922) and the issue-14 design record.

The normative binding table is `docs/air-consent-receipt-field-table.md`.
This document is the *why and how*; that document is the *what*.

## 1. The problem this closes

AIR proves the **agent ↔ merchant** interaction: a signed entry binding a
request digest, a response digest, the payment that authorized the exchange,
and a position in a per-session hash chain (AIR v0.2 §1). It is deliberately
silent on the **human ↔ agent** question (AIR v0.2 §9: "What it does not prove:
… that the response is true, that the issuer is honest, or the real-world
identity behind a key"). Nothing in an AIR entry records *who authorized the
spend, up to what cap, for what purpose, until when*.

A **payment-consent receipt** is exactly that record: a human-signed,
content-addressed envelope carrying `scope` (a least-privilege capability
list), `amount` / `amount_cap` (decimal strings), `purpose`, `expires_at`,
`nonce`, and a real Ed25519 `authorizer` signature
(`docs/agent-payment-consent-receipt.md`). The two compose rather than rival:
AIR is the proof-of-delivery layer, the consent receipt is the authorization
layer.

## 2. The convergence point (no new field needed)

AIR already defines the binding surface, and this drop-in uses it rather than
proposing a parallel mechanism:

- **AIR v0.2 §9** recommends binding external authorization artifacts via the
  `meta.authorization` extension point.
- **AIR v0.3 draft §2** graduates that to a first-class `authorizations[]`
  array of binding objects with a common core (`scheme`, `decision_ref`,
  `trust_model`, `authority_ref`, `axes`) plus a per-trust-model conditional
  set. Draft 2 keyed that conditional set on `trust_model`, never transport.

A consent receipt binds as **one element of `authorizations[]`** under
`trust_model: issuer_signed`, `authority_ref` = the human authorizer's key.
Full field table: `docs/air-consent-receipt-field-table.md` §2.

## 3. The drop-in field shape

The consent-receipt binding (see the field-table doc for the normative table):

| Field | Value for a consent receipt |
|---|---|
| `scheme` | `nightshift.consent_receipt.v1` |
| `decision_ref` | the consent receipt's `content_sha256` |
| `trust_model` | `issuer_signed` |
| `authority_ref` | `ed25519:<authorizer public key>` — the human authorizer's key |
| `authorization_sha256` | SHA-256 of the **exact consent bytes** the binding party verified at bind time |
| `authorization_uri` | checksum-stable retrieval pointer to the exact consent bytes |
| `transport_hint` | `raw_url` (or `relay_event` / `bundle`) |
| `axes` | §4 |

`decision_ref` and `authorization_sha256` are two different addresses of the
same artifact, and that is the point: `decision_ref` is the scheme-defined
*content* address (stable under re-serialization), while
`authorization_sha256` is the *byte-integrity* transport hash (AIR v0.3 §2.3 —
"these are the bytes I verified before binding," which a content-addressed URI
alone cannot guarantee).

## 4. What the consent receipt actually contributes

The AIR author's draft-2 ruling resolved three claims precisely. Two of the
earlier framings were wrong, and one was right in a stronger form
than originally aimed:

1. **No fourth axis.** Precedence/freshness/correctness are *epistemic* axes —
   properties any evidence artifact has over time. "Was this authorized" is
   what the artifact *is*; `scheme` names it. The consent receipt declares the
   three axes and no fourth (§2.4): `precedence` → `issued_at`, `freshness` →
   `expires_at`, `correctness` → `null`.
2. **No fourth authority surface.** The authority surface for a consent
   receipt is a signing key — `issuer_signed`, identical in kind to every
   other signed authorization (§2.6). The grant's content (cap/purpose/expiry)
   is artifact *content*, named by the scheme, not a lookup surface.
3. **Binding-coherence predicates — the real contribution.** "The payment sits
   inside the grant's cap/scope/expiry" is a cross-check between the bound
   artifact's content and the carrying entry's content — machinery §2.7 does
   not currently define. It is a pure function of bytes already in hand, and by
   AIR's own meta-rule everything computable from the bytes belongs to the
   format. The consent scheme therefore defines deterministic predicates over
   `(artifact, carrying entry)` — `payment-within-cap`, `asset-match`,
   `within-validity` — running in §2.7 **step 3**, offline. See the field-table
   doc §4. This fixture is the first binding-coherence fixture.

A second amendment rides the same shape: `expires_at` cannot be expressed by
the `computable` freshness encoding as drafted (it takes a relative cadence; a
consent ages by absolute deadline). Proposal: `computable` admits either
`{observed_at_field, max_age_field}` or `{expires_at_field}` — field-table doc
§3.

## 5. Direction: one-way binding

A consent grant is issued **before** the interaction it authorizes, so it
carries **no forward reference** to the receipts that result (an AIR receipt, a
settlement record, a trail record). Those artifacts bind **back** to the
consent on their own side — the AIR receipt names it via `authorizations[]`,
a settlement record via `actionRef`. The consent side stays a clean, immutable
grant (its optional `references` list binds only *prior* artifacts — a
governing policy, a parent grant). A dispute resolves as a pure containment
check on the receipt side: *"was this specific payment inside the human's
signed consent envelope?"*

## 6. Verification procedure

Given an AIR entry and a consent receipt (bytes), the composition is verified
by `tools/air_consent_compose.py`:

1. Validate the consent receipt (structure, `amount ≤ amount_cap` as exact
   decimals, expiry, nonce, content integrity, authorizer-signature presence).
2. Locate the consent-receipt binding in `authorizations[]` (v0.3) or
   `meta.authorization` (v0.2).
3. `SHA-256(exact consent bytes) == authorization_sha256` — a mismatch is a
   **transport failure, not a signing failure** (v0.3 §2.3).
4. `decision_ref == consent.content_sha256`.
5. **Binding-coherence predicates** — payment within cap, asset match, entry
   timestamp inside the grant's validity window (§4 / field-table §4).
6. Authority classification remains consumer-side (v0.3 §2.6):
   `structurally_invalid` / `structurally_valid_zero_authority` /
   `valid_and_authorized`.

AIR's own signature and JCS entry-hash verification are out of scope for the
reference checker — that is the AIR verifier's job, and the binding is
deliberately decoupled from it. Consent-signature *verification* (not just
presence) is `tools/sign_consent_receipt.py`.

## 7. Reference checker

`tools/air_consent_compose.py` is a dependency-free, offline, deterministic
validator for steps 1–5. Run:

```sh
python3 tools/air_consent_compose.py \
  --air examples/air-consent-receipt-composition/air-entry-with-authorization.json \
  --consent examples/air-consent-receipt-composition/consent-receipt.json \
  --fail-on review
```

Exit `1` means at least one review flag is present. It never contacts a chain,
signs, settles, or moves funds.

## 8. Alignment status

1. **Canonical form — ALIGNED (2026-08-13).** The consent receipt's
   `content_sha256` is now the SHA-256 of the receipt's **JCS (RFC 8785)**
   canonical form with `content_sha256`/`signatures` excluded (UTF-8, sorted
   keys, no insignificant whitespace, minimal string escaping, non-ASCII
   emitted verbatim). One canonicalizer now serves both specs. Pinned by
   `tools/test_jcs_canonicalization.py`.
2. **`expires_at` freshness encoding.** Whether `computable` should admit the
   `{expires_at_field}` input set — proposed here, to be settled in the
   draft-2 → draft-3 cycle (field-table doc §3).

## 9. Boundary

This is free, non-financial documentation plus a read-only checker and a
sign/verify tool for synthetic fixtures. It does not custody funds, sign
transactions on a real authorizer's behalf, move money, issue tokens, or give
trading/investment advice. It makes no claim that any agent-payment product is
safe or compliant.
