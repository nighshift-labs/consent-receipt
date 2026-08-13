# AIR entry × consent receipt — composition fixtures

Two synthetic files exercise the composition checker
(`tools/air_consent_compose.py`), the binding layer between the
machine-to-machine proof-of-delivery (AIR) and the human authorization
(consent receipt):

- `consent-receipt.json` — a really-signed consent grant (Ed25519 authorizer
  signature over the canonical body): `agent` authorized to `pay_invoice`,
  asset USDC, cap `"50.00"` (decimal string), purpose, issued
  `2026-08-01T00:00:00Z`, expires `2026-09-01T00:00:00Z`. It carries **no
  forward reference** — a grant predates the interaction it authorizes.
- `air-entry-with-authorization.json` — an AIR-shaped entry (`spec_version
  "0.3-draft-2"`) whose first-class `authorizations[]` element binds to the
  consent via the AIR v0.3 draft-2 shape: `scheme:
  nightshift.consent_receipt.v1`, `trust_model: issuer_signed`, `authority_ref`
  = the human authorizer's key, `decision_ref` = the consent receipt's
  `content_sha256`, `authorization_sha256` = SHA-256 of the exact consent
  bytes, and a three-key `axes` declaration (`precedence` → `issued_at`,
  `freshness` → `{expires_at_field, flavor: computable}`, `correctness` →
  null). No `authorization` axis — authorization is what the grant *is*,
  named by the scheme, not a fourth axis.

These fixtures are synthetic: identities, amounts, nonces, and hashes
correspond to no real wallet, agent, or payment. The authorizer signature is a
**real** Ed25519 signature, but over a disclosed synthetic test key
(`tools/sign_consent_receipt.py`), not a real human's key.

To check the composition:

```sh
python3 tools/air_consent_compose.py \
  --air examples/air-consent-receipt-composition/air-entry-with-authorization.json \
  --consent examples/air-consent-receipt-composition/consent-receipt.json \
  --fail-on review
```

The expected result is `ready-for-human-review` with `flag_count 0`: the
binding hashes match, the consent receipt validates, and the binding-coherence
predicates hold (payment 5 USDC within cap 50.00, asset match, inside the
grant's validity window).

To verify the authorizer signature:

```sh
python3 tools/sign_consent_receipt.py verify examples/air-consent-receipt-composition/consent-receipt.json
```
