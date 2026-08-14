# BoundaryAttest Interop Profile v0.1 × consent receipt

Status: interop bridge, validated end-to-end against BoundaryAttest's published
schema. Not a fork, not a change to either project's spec — a composition.

## The two axes

**BoundaryAttest** ([cullenmeyers/BoundaryAttest](https://github.com/cullenmeyers/BoundaryAttest),
Interop Profile v0.1) proves **action provenance**: a signer attested "action X
happened with result R, and it has not changed." Its envelope is
`{claim, signature, public_key_id}`, Ed25519 over the canonical `claim`, and it
says so explicitly in
[`docs/interop-profile-v0.1.md`](https://github.com/cullenmeyers/BoundaryAttest/blob/main/docs/interop-profile-v0.1.md):

> These are policy-layer checks, not mandatory v0.1 cryptographic checks: …
> **authorization, grant, or policy validity** …

BoundaryAttest deliberately does not answer "who authorized this, under what
bounds." That is not a gap — it is the profile's stated boundary.

**The consent receipt** (this repo) proves **authorization**: a human signed a
grant of `amount` / `amount_cap` / `purpose` / `expires_at` before the payment
fired. Ed25519 + RFC 8785 JCS, `content_sha256` preimage, offline checker.

The two answer different questions about the same event, and neither needs to
know the other's internals to be composed — only a digest pointer.

## The binding: `authorization_ref`

Add one optional field inside `claim`:

```json
"authorization_ref": "bc486e73ff4220c86f83c4c35a8ecb4e984a6262b7b61af722364cf6f332f231"
```

where the value is the `content_sha256` of the signed consent grant. Because
the profile sets `claim.additionalProperties = true` (and only `claim` is
signed), this is a **zero-breaking drop-in**: existing verifiers ignore the
unknown signed field by default, and the reference inherits the receipt's
signature for free.

One combined check then answers both halves at once:

1. **Provenance** — the BoundaryAttest signature is valid over the canonical
   `claim` (the action really happened as recorded).
2. **Authorization** — the referenced grant's `content_sha256` and authorizer
   signature verify, and it is unexpired.
3. **Containment** — `claim.action_type` is in the grant's `scope`, and the
   amount is within `amount_cap`.

## Canonicalization note (honest, load-bearing)

The two formats use **different canonicalizations**:

| Side | Canonicalization |
|---|---|
| BoundaryAttest v0.1 | `stableJson` — compact JSON, keys sorted with the JS comparator `localeCompare` |
| Consent receipt | RFC 8785 JCS — compact JSON, keys sorted by Unicode code point |

`authorization_ref` carries only the *digest* of the grant, never the grant
bytes, so the two never have to agree on canonicalization. Each side verifies
its own bytes; the digest is the seam. (For the ASCII `snake_case` keys the
profile defines, `localeCompare` and code-point order coincide — the bridge
uses this in its `stable_json` implementation and documents it rather than
claiming a language-neutral canonical form, matching the profile's own caveat.)

## Files

- `tools/boundaryattest_interop.py` — `stable_json`, `spki_public_key_id`,
  `compose_receipt` / `verify_receipt`, and `check_authorization_binding`.
- `tools/test_boundaryattest_interop.py` — 13 tests covering canonicalization,
  key-id, signature round-trip, tamper rejection, wrong-key rejection, and the
  three-part binding/containment check.
- `examples/boundaryattest-consent-receipt/consent-grant.json` — a
  really-signed consent grant (synthetic authorizer key).
- `examples/boundaryattest-consent-receipt/interop-receipt-with-authorization-ref.json` —
  a really-signed BoundaryAttest v0.1 receipt whose `claim.authorization_ref`
  binds that grant.

Run:

```sh
python3 -m unittest tools/test_boundaryattest_interop.py -v
```

## Where the boundary is drawn

`authorization_ref` names the grant, not the judgment. Verifying that the grant
is *valid policy* (is this human authorized to approve 50 USDC at all?) stays a
relying party's business decision — exactly where BoundaryAttest's profile
already draws its line. The bridge makes that decision *computable* by putting
the signed grant one digest-hop from the signed action, with no change to
either format.
