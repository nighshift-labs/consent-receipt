# NOMOS × consent-receipt composition — the human-authorization origin NOMOS scopes out

## The gap is stated, normatively, by NOMOS itself

AgentNOMOS's `nomos-trust-chain-verifier` (`AgentNOMOS/nomos-trust-chain-verifier`)
proves, publicly and offline, that a paid agent transaction was bound from
**represented intent → capability → offer → security evidence → authorization →
execution → signed receipt → outcome**. Its claim ceiling is explicit
(`docs/claim-boundary.md`):

> NOMOS proves continuity from the represented intent onward. It does not
> prove that the represented intent was the correct interpretation of the
> human's underlying meaning.

That excluded origin — *was this what the human actually authorized?* — is
exactly what a consent receipt is: a **signed human-authorization record**
(who authorized what, for what purpose, up to what cap, until when).

Neither layer is sufficient alone. NOMOS proves the execution side; the consent
receipt proves the authorization origin. Composed, the chain is continuous from
the human to the settled outcome:

```
human ──consent receipt──▶ represented intent ──NOMOS──▶ execution ──▶ signed receipt ──▶ outcome
   (signed grant)          (intent + authorization_ref)   (21 deterministic checks)
```

## The join is one field NOMOS already endorses

NOMOS's `docs/protocol-mapping.md` already names the seam in its AP2 mapping:

> an AP2 mandate identifier can travel inside the NOMOS intent (and thus inside
> the digest), giving a mandate an execution-bound counterpart.

The consent receipt is the signed, self-verifying form of that mandate. The
composition adds a single optional field to the NOMOS intent core:

```json
"authorization_ref": {
  "schema": "nightshift.consent_receipt.v1",
  "content_sha256": "<sha256 of the canonical consent-receipt body>"
}
```

Because NOMOS derives `intent_digest` over the intent core fields, adding
`authorization_ref` to that canonical field list binds the human-authorization
origin into the digest — the decision and the signed execution receipt then
bind it transitively, with no new field on the receipt side.

This is a proposal, not a claim of compatibility: the current NOMOS schema
(`nomos.intent.v1`) has no `authorization_ref` field, so a conformant
verifier would treat it as an unknown/extension field until NOMOS adopts it.
The composition mirrors NOMOS's own "unsupported-schema → proposed v1.1" note.

## What the checker verifies

`tools/nomos_consent_compose.py` (offline, dependency-free, stdlib-only):

1. The consent receipt is structurally valid, unexpired at the pinned instant,
   and carries a real authorizer signature (`tools/sign_consent_receipt.py`
   verifies the Ed25519 cryptographically).
2. `authorization_ref.content_sha256` equals the exact consent bytes
   (transport-integrity), matching the consent's own `content_sha256`.
3. The intent's purpose overlaps the grant's purpose.
4. The consent's `amount` sits inside its own `amount_cap`.
5. The intent's `created_at`/`expires_at` fall inside the consent's
   `issued_at`/`expires_at` window.
6. Direction is one-way: consent → intent, never a forward NOMOS reference
   (the consent predates the interaction it authorizes).

Run it:

```sh
python3 tools/nomos_consent_compose.py \
  --intent examples/nomos-consent-receipt/nomos-intent-with-consent-ref.json \
  --consent examples/nomos-consent-receipt/consent-grant.json
# verify the authorizer signature:
python3 tools/sign_consent_receipt.py verify examples/nomos-consent-receipt/consent-grant.json
```

## Honest boundaries

- **The consent grant is a synthetic fixture** reusing the mission's synthetic
  test authorizer key, mirroring NOMOS's own published canary scenario (the
  $0.001 USDC `RWA_REGISTRY_STATS_READ` ALLOW). It is machinery evidence, not
  adoption evidence — the same honesty NOMOS applies to its own canary.
- **The intent's `authorization_ref` is a proposal**, not a change NOMOS has
  accepted. Nothing here implies endorsement by AgentNOMOS/FeedOracle.
- **No independent cryptographic verification of NOMOS's own receipt** is done
  here — the mission ran NOMOS's verifier separately (21/21 checks pass, offline,
  no wallet) and this composition layers on top of that, not instead of it.
- The purpose-containment check is textual overlap, a weak-but-honest proxy; a
  production policy would match structured action identifiers.
