# AIR v0.3 draft-2 field table — `nightshift.consent_receipt.v1`

A PR-ready binding field table for a **signed payment-consent receipt** as an
AIR `authorizations[]` element. Written against
[crisnovillo1991/agent-receipt-spec](https://github.com/crisnovillo1991/agent-receipt-spec) **SPEC-v0.3-draft.md, DRAFT 2** (§2.2
binding object, §2.4 axis declaration, §2.6 authority surfaces, §2.7
verification procedure). This is the shape the AIR author invited in
[x402-foundation/x402#2922](https://github.com/x402-foundation/x402/issues/2922): a signed consent record is a legitimate
authorization-class artifact under `trust_model: issuer_signed`, with
`authority_ref` = the human authorizer's key.

## 1. Relationship to AP2 mandate objects

The consent receipt is a **mandate object** in the same territory as AP2's
mandates: a scoped, capped, purpose-bound, expiring payment authorization. It
is not an AP2 mandate; it is a float-free, sign-and-verify shape that AIR
binds as an authorization artifact under `scheme: nightshift.consent_receipt.v1`.
AP2 mandates, card-rail references and invoice IDs bind alongside it in the
same `authorizations[]` array, under their own schemes — same structure, no
overlap.

## 2. Binding field table (`issuer_signed`)

Per §2.2, the binding carries the common core plus the `issuer_signed`
conditional set (artifact-byte model). A consent-receipt binding fills it as:

| Field | Value | Req (§2.2) | Note |
|---|---|---|---|
| `scheme` | `nightshift.consent_receipt.v1` | common core | scheme name of the consent grant |
| `decision_ref` | the receipt's `content_sha256` | common core | scheme-defined content address |
| `trust_model` | `issuer_signed` | common core | verification obligation + authority surface |
| `authority_ref` | `ed25519:<authorizer public key>` | common core | the **human authorizer's** signing key — §2.6's `issuer_signed` surface |
| `authorization_sha256` | SHA-256 of the **exact consent bytes** | MUST | lowercase hex; attests the bytes verified at bind time (§2.3) |
| `authorization_uri` | checksum-stable retrieval pointer (Blossom blob / raw URL) | MUST unless bundled | byte-integrity transport (§2.3) |
| `transport_hint` | `raw_url` | retrieval detail | `relay_event` / `bundle` also legal |
| `axes` | see §3 | common core | all three keys MUST be present (§2.4) |

`authorization_uri` / `authorization_sha256` / `transport_hint` are the
`issuer_signed` artifact-byte set. They are never present for `chain_anchored`
(that would be non-conforming self-attestation) — the consent receipt does not
use that model.

## 3. Axis declaration (`axes`)

The consent grant declares the three §2.4 axes — and **no fourth**. AIR's
precedence/freshness/correctness are epistemic axes (properties an evidence
artifact has over time); "was this authorized" is not a fourth axis, it is
what the artifact *is*, and `scheme` already names it. The binding:

```json
"axes": {
  "precedence":  {"field": "issued_at"},
  "freshness":   {"expires_at_field": "expires_at", "flavor": "computable"},
  "correctness": null
}
```

- `precedence` — the grant's `issued_at` (§2.4 `{field}` form).
- `freshness` — **`expires_at_field` form**. A consent ages by absolute
  deadline, which the draft-2 `computable` shape `{observed_at_field,
  max_age_field}` cannot express (it takes a relative cadence). This table
  proposes `computable` admits either input set: `{observed_at_field,
  max_age_field}` (relative) **or** `{expires_at_field}` (absolute). Expiry
  vs. the consumer's clock stays in step 6 where it belongs; the field
  declaration stays a pure function of the bytes.
- `correctness` — `null`, visibly: a grant claims no outcome.

## 4. Binding-coherence predicates (the scheme's real content)

A consent scheme defines deterministic predicates over `(artifact, carrying
entry)` — both already in hand — that run in §2.7 **step 3** (verify the
artifact per `scheme`), offline, as part of structural verification:

| Predicate | Definition | Failure |
|---|---|---|
| payment-within-cap | `payment.amount <= amount_cap`, compared as exact decimals | `payment_exceeds_consent_cap` |
| asset-match | `payment.asset == asset` (case-insensitive) | `payment_asset_mismatch` |
| within-validity | `entry.issued_at ∈ [issued_at, expires_at]` | `payment_after_consent_expiry` / `payment_before_consent_issuance` |

Expiry-against-NOW is **not** a predicate here — it is step 6 (consumer clock).
These predicates are what the reference checker (`tools/air_consent_compose.py`)
implements; they are the concrete machinery the AIR author asked to fold in as
"binding-coherence predicates."

## 5. Authority surface (§2.6) — one surface, not a fourth

For a consent receipt the authority surface a consumer looks up is a **signing
key** — `issuer_signed`, identical in kind to every other signed authorization.
Trusting a key to issue verdicts never implied trusting it to grant spending;
the §2.6 lookup already carries `(key, scheme)`, so the policy question stays
`(key, scheme)`-relative. The grant's content (cap/purpose/expiry) is artifact
*content*, named by the scheme — not a lookup surface. **Three surfaces stand.**
The consent receipt contributes an `issuer_signed` fixture to the §6
"one fixture per authority surface" ledger item, not a fourth surface.

## 6. Reference fixture

The shipped, really-signed fixture:

- Consent grant (Ed25519 authorizer signature over the canonical body):
  `examples/agent-payment-consent-receipt/valid-receipt.json`
- AIR entry binding that grant via `authorizations[]`:
  `examples/air-consent-receipt-composition/air-entry-with-authorization.json`
- Offline compose checker (steps 1–5 incl. the §4 predicates):
  `tools/air_consent_compose.py`

Canonical-form note: the consent receipt's `content_sha256` is the SHA-256 of
the receipt's **JCS (RFC 8785) canonical form** with `content_sha256` and
`signatures` excluded — UTF-8, sorted keys, no insignificant whitespace,
minimal string escaping (non-ASCII emitted verbatim). The schema is float-free
(decimal-string money; integer `schema_version`/`chain_id`), so number
canonicalization is plain decimal integers. The authorizer signature signs
these same bytes. Full preimage definition: `docs/agent-payment-consent-receipt.md`
("Canonical body and integrity"); conformance pinned by
`tools/test_jcs_canonicalization.py`.
