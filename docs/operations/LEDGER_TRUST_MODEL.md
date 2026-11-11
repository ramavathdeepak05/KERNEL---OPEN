# Ledger proof-bundle trust model (K·02 / D3-1)

How an auditor or regulator independently trusts a QUAICU ledger export. (The byte-exact
serialization spec, threat model, and frozen review surface live in `K02_REVIEW_PACKAGE.md`.) A proof bundle
(`GET /v1/ledger/{tenant}/export`) asserts that a set of governed actions were sealed into an
append-only RFC 6962 transparency log. Verifying it has **two separable properties**.

## 1. Integrity — self-contained

`verify_ledger_proof_bundle` recomputes the Merkle root from each entry's inclusion proof and checks
it equals the **signed root** in the STH. This detects any tampering *within* the bundle (a changed
leaf, a doctored proof, an altered root) using **nothing but the bundle** — no key, no network.

## 2. Authenticity — requires a pinned key (the D3-1 change)

Integrity alone is not enough: an attacker can fabricate a fully self-consistent bundle signed with
**their own** keypair and embed that key. To stop this, the STH signature is verified against an
**out-of-band, pinned** key — never the key embedded in the bundle:

```python
from quaicu.core.regmap.export import verify_ledger_proof_bundle

ok, errors = verify_ledger_proof_bundle(
    bundle,
    trusted_keys={key_id: public_key_pem},   # the key you pinned at onboarding
)
```

Rules (all fail-closed):

- **No `trusted_keys`** → authenticity cannot be attested → `ok = False`.
- Bundle's `key_id` **not in** `trusted_keys` (a forged/unknown key) → `ok = False`.
- Signature does not verify against `trusted_keys[key_id]` → `ok = False`.
- If the bundle also embeds a public key and it differs from the pinned key → `ok = False`
  (tamper signal). The embedded key is advisory only.

## Obtaining and pinning the key

Once, at onboarding, over an authenticated channel:

```
GET /v1/ledger/signing-key   →   { "key_id": "...", "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
                                    "algorithm": "ed25519" | "ecdsa-p256" }
```

Record `key_id → public_key_pem` in **your own** records (a key registry / trust-center entry) and
pin it. Thereafter you verify every export against your pinned copy, so a later kernel-side key swap
cannot pass — the swapped `key_id`/key won't match what you pinned.

The signing scheme is transparent to the verifier: an Ed25519 (software / OpenBao) key and an
ECDSA-P256 (GCP/AWS Cloud KMS) key pin and verify through the same code path.

## The hosted verify endpoint

`POST /v1/ledger/export/verify` runs the verifier server-side and pins against **that tenant kernel's
own** signing key — so it answers *"did we sign this?"*. For a fully independent check, run
`verify_ledger_proof_bundle` yourself, offline, against the key you pinned.

## 3. Anchoring — an independent witness (D3-2)

Integrity + authenticity still trust a *single* party's key. A compromised kernel could present two
different histories (a **split view**) or silently **rewind** its log, each internally consistent and
correctly signed. An independent **witness** defeats this: it cosigns an STH only after checking the
STH is a consistent, append-only extension of the last STH it cosigned (RFC 6962 §2.1.4, proof-only —
the witness never sees the leaves). A fork or rewind is **refused** (`LedgerTamperError`).

The witness cosignature is embedded in the export bundle's `anchor` block and verified by pinning the
**witness** key — exactly like the signing key:

```
GET /v1/ledger/witness-key   →   { "witness_id": "...", "public_key_pem": "...", "algorithm": "ed25519" }

ok, errors = verify_ledger_proof_bundle(
    bundle,
    trusted_keys={key_id: signing_pem},          # authenticity (§2)
    trusted_witnesses={witness_id: witness_pem},  # anchoring (§3) — omit to skip
)
```

`trusted_witnesses` is optional: omit it and the bundle still verifies for integrity + authenticity,
just without the split-view guarantee. When supplied, the cosignature must verify against the pinned
witness key **and** attest the same `(tree_size, root)` as the STH.

For real independence, run the witness as a **separate service with its own key** —
`quaicu-kernel-witness` (`quaicu/delivery/entrypoint_witness.py`) is that service:

- Its **stable** Ed25519 key comes from `QUAICU_WITNESS_KEY_PEM` (pin its public half; the key must
  outlive restarts, or every restart changes what auditors pin). `QUAICU_WITNESS_TOKEN` is the shared
  bearer the kernel presents; `QUAICU_WITNESS_DSN` gives it **durable, monotonic** last-seen state
  (`quaicu_witness_state`, migration 016) so a rewind *after a restart* is still caught.
- The kernel reaches it via `adapters.ledger.http_witness.HttpWitness`, wired from config —
  `kernel.shared.toml` `[adapters] witness = "http_witness"` + `[witness] base_url, token`. A fork /
  rewind the witness refuses comes back as `409` → `LedgerTamperError` (fail-closed, no bundle).
- **Continuous** observation: set `[anchor] interval_seconds` (kernel.toml) so the kernel
  cosigns every tenant's STH on a cadence, not only at export — a split-view/rewind is caught promptly.

An auditor who collects cosignatures over time detects a split view because a divergent history cannot
produce witness cosignatures consistent with the ones already seen. Deploy the witness in a different
trust domain (ideally different key custody) from the kernel.

## Key rotation

Rotating the STH signing key mints a new `key_id`; new exports sign under it. **Retired keys are
never deleted** while any entry references them, and old bundles stay verifiable — so your pinned
registry keeps both the old and new `key_id → key` entries. The same applies to a rotated witness key.
