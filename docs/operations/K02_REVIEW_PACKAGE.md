# K·02 TrustLedger — Cryptographic Review Package (D3-3)

*The reviewer-facing design spec for the third-party crypto review (tracked as T-1). Companion to
the operator-facing `LEDGER_TRUST_MODEL.md`. This document plus the pinned tag IS the frozen review
surface.*

> **FREEZE NOTICE.** As of tag **`k02-review-v2`** (supersedes `k02-review-v1`; delta in §8),
> changes to any file listed in §6
> (everything under `quaicu/core/ledger/`, `quaicu/core/ports/anchor.py`, `quaicu/core/regmap/export.py`,
> `quaicu/adapters/ledger/`, `quaicu/delivery/witness_app.py`) require explicit owner sign-off until the
> T-1 review report + remediation re-review land. Bug fixes found *by* the review go through
> the normal fix flow and are re-reviewed.

---

## 1. System in one paragraph

Every governed action a tenant's kernel seals is appended as a leaf to that tenant's own
RFC 6962 Merkle transparency log (per-tenant tables — Frozen Decision F-07, never shared).
The current tree head is signed (STH) by a key held in an HSM/KMS boundary. A regulator
export (`GET /v1/ledger/{tenant}/export`) carries the STH, per-entry inclusion proofs, and
optionally an **independent witness cosignature** over the STH. The offline verifier
`verify_ledger_proof_bundle` checks three separable properties, each fail-closed:
**integrity** (proofs recompute the signed root — self-contained), **authenticity** (STH
signature verifies against a key the verifier pinned out-of-band — never the key embedded in
the bundle), and **anchoring** (the witness cosignature verifies against a pinned witness key
and attests the same `(tree_size, root)` — split-view/rewind defense).

## 2. Byte-exact serialization + hashing spec

### 2.1 Leaf bytes (what gets hashed)

A seal request is serialized by `quaicu/core/ledger/engine.py::_canonical_bytes`:

```python
json.dumps(d, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
```

where `d` contains the action identity/type/payload, the evaluation result, the recorded
(non-deterministic) execution result, the approver reference, the K·04 consent state at
evaluation time, and the governance profile. `sort_keys=True` + `ensure_ascii=True` give
byte-identical output across Python versions and locales; `default=str` totalizes
serialization (no unserializable-value exception path).

### 2.2 Merkle tree (RFC 6962, SHA-256 only)

`quaicu/core/ledger/merkle.py`:

- **Leaf hash:** `SHA-256(0x00 || entry_bytes)`
- **Node hash:** `SHA-256(0x01 || left || right)`
- Tree shape, inclusion proofs (§2.1.1/2.1.3), and consistency proofs (§2.1.2/2.1.4) follow
  RFC 6962 exactly — no custom proof structures.
- `verify_consistency_proof(old_size, old_root, new_size, new_root, proof)` is the
  **proof-only** §2.1.4 verifier (canonical CT/Trillian algorithm): it reconstructs both the
  old and new roots from the proof alone, so a party holding only STHs (the witness, an
  auditor) can verify append-only extension without any leaves.

### 2.3 STH signing message

`quaicu/core/ledger/signer.py::_signing_message`:

```
msg = tree_size.to_bytes(8, "big") || root_hash        # 8-byte BE size || 32-byte root
```

Signed by the active `TreeSigner`. Two schemes are in production scope:

| Scheme | Signers | Notes |
|---|---|---|
| Ed25519 | `InMemoryEd25519Signer` (tests), `quaicu/adapters/ledger/openbao.py` | key never leaves OpenBao |
| ECDSA P-256 / SHA-256 | `quaicu/adapters/ledger/gcp_kms.py`, `quaicu/adapters/ledger/aws_kms.py` | Cloud KMS has no Ed25519; key never leaves the HSM |

**No algorithm tag on the wire** — the offline verifier dispatches on the *type of the pinned
public key* (Ed25519 vs EC-P256). Review question: confirm this cannot be downgraded or
confused (the pinned key is chosen by the verifier, not the bundle, which is the intended
defense).

The STH carries `key_id` (which key signed) and `timestamp`. **The timestamp is not covered
by the signature** (only `tree_size || root_hash` is) — it is advisory; freshness/ordering
guarantees come from the witness cosignature timeline, not the STH timestamp.

### 2.4 Witness cosignature signing message

`quaicu/core/ports/anchor.py::WitnessCosignature.signing_message` (Ed25519 only):

```
b"quaicu.witness.v1\x00" + "\x00".join([
    witness_id, tenant, str(tree_size), root_hash.hex(), cosigned_at.isoformat()
]).encode("utf-8")
```

Domain-separated by the `quaicu.witness.v1` prefix; fields NUL-delimited (none of the field
encodings can contain NUL: `witness_id`/`tenant` are identifiers, size is decimal,
root is hex, timestamp is ISO-8601). Unlike the STH, the witness signature **does** cover
its timestamp, so a cosignature is a dated attestation "root R existed at size S at time T".

### 2.5 Multi-worker seal linearization (D4-1)

Multiple workers/instances each hold an in-memory copy of a tenant's tree (the fast read path,
ADR-0005) over ONE durable log. The **durable insert is the linearization point**:

- A seal succeeds iff its `INSERT` at `(tenant_id, ledger_seq)` actually inserted a row.
- A conflicting insert (same slot, **different** leaf hash) raises a typed
  `LedgerSequenceConflictError`; the losing worker rolls back its speculative in-memory append,
  **rehydrates that tenant's tree from the durable log**, recomputes position + root, re-signs,
  and retries (bounded at 3, then fail-closed HALT — F-03). An identical-leaf replay is an
  idempotent success.
- The durable STH upsert is **advance-only** (`WHERE stored.tree_size <= EXCLUDED.tree_size`), so
  a stale worker's late save can never regress the head.

Invariant: every worker's in-memory tree is always a *consistent prefix* of the durable log —
proofs served by a lagging worker are RFC 6962-consistent with the head; a fork is structurally
unreachable through this path. (Pre-D4-1 the insert was `ON CONFLICT DO NOTHING` with no status
check — a racing worker's seal was silently dropped while it reported success; threat row 12.)

### 2.6 Bundle wire format

`quaicu/core/regmap/export.py::LedgerProofBundle.to_dict()` — `format_version =
"quaicu.ledger-proof/1.0"`. JSON; all hashes/signatures hex-encoded (`*_hex`); the STH block
carries an **advisory** `public_key_pem` (see §3.2 — never used as the trust anchor); the
optional `anchor` block is `WitnessCosignature.to_dict()`.

## 3. Verifier specification (`verify_ledger_proof_bundle`)

Signature: `verify_ledger_proof_bundle(bundle, *, trusted_keys=None, trusted_witnesses=None)
-> (ok, errors)`. Three properties, checked independently; **any error → `ok = False`**.

### 3.1 Integrity — self-contained

For every inclusion proof: recompute the root from `(leaf_hash, ledger_seq, audit_path,
tree_size)` and require it to equal the STH's `root_hash`. Detects any tamper *within* the
bundle (changed leaf, doctored path, altered root) with no key and no network.

### 3.2 Authenticity — pinned signing key (D3-1)

Fail-closed rules, in order:

1. `trusted_keys is None` → **fail** ("no pinned trust anchor").
2. Bundle `key_id ∉ trusted_keys` (forged/unknown key) → **fail**.
3. STH signature does not verify against `trusted_keys[key_id]` (scheme by key type) → **fail**.
4. Bundle embeds a `public_key_pem` that differs from the pinned key → **fail** (tamper
   signal; the embedded key is advisory only and is *never* verified against).

The pinned key is obtained once, out-of-band, at onboarding via the authenticated
`GET /v1/ledger/signing-key` → `{key_id, public_key_pem, algorithm}`.

### 3.3 Anchoring — pinned witness key (D3-2)

Optional: `trusted_witnesses=None` skips this property (integrity + authenticity still
verify). When supplied (`{witness_id → PEM}`), fail-closed rules:

1. No `anchor` block in the bundle → **fail** (anchoring demanded but absent).
2. Malformed anchor → **fail**.
3. `witness_id ∉ trusted_witnesses` → **fail**.
4. Anchor attests a different `(tree_size, root_hash)` than the STH → **fail**
   (possible split-view).
5. Ed25519 signature does not verify against the pinned witness key → **fail**.

Witness key pinned once via `GET /v1/ledger/witness-key`.

## 4. Witness protocol (split-view / rewind defense)

- **State:** per tenant, the witness durably stores the last `(tree_size, root_hash)` it
  cosigned (`WitnessStateStore`; production = `PostgresWitnessStateStore`, migration 016,
  with an **advance-only** upsert — `ON CONFLICT … WHERE EXCLUDED.tree_size >= stored` — so a
  rewound size can never overwrite the high-water mark, even via the store API).
- **Cosign rule** (`quaicu/adapters/ledger/witness.py::SoftwareWitness.cosign`): if the witness has
  a last-seen `(old_size, old_root)`, it cosigns the presented STH **iff**
  `verify_consistency_proof(old_size, old_root, sth.tree_size, sth.root_hash, proof)` — a
  fork, same-size fork, or rewind fails the proof and raises `LedgerTamperError`
  (fail-closed; over HTTP this is a `409` mapped back to `LedgerTamperError`, so **no export
  bundle is produced for a compromised log**).
- **Orchestration** (`quaicu/core/ledger/anchor.py::anchor_current_sth`): the kernel fetches the
  consistency proof from `last_seen` to the current STH and presents both. If
  `last_seen.size >= sth.tree_size` an **empty proof** is sent — the witness's own
  `verify_consistency_proof` then fails unless the STH is bit-identical to its stored head
  (same size + same root passes trivially as a re-sign; a same-size different root or a
  smaller size fails). **Explicit review question:** confirm the empty-proof path cannot be
  abused to obtain a cosignature over a forked/rewound history.
- **Cadence:** at export (bundle anchoring) and continuously via `anchor_all_tenants` on a
  scheduler (`[anchor] interval_seconds`), so divergence is caught promptly, not only when a
  regulator asks.
- **Independence:** production runs `quaicu-kernel-witness` (`quaicu/delivery/witness_app.py`) as a
  separate service in a separate trust domain: own stable Ed25519 key
  (`QUAICU_WITNESS_KEY_PEM`), own DB (`QUAICU_WITNESS_DSN`), bearer-token auth. The
  in-process `SoftwareWitness` exists for tests/sovereign single-node runs.

## 5. Threat model → defense → test

| # | Attack | Defense | Proving test(s) |
|---|---|---|---|
| 1 | Tampered leaf / proof / root inside a bundle | Integrity: inclusion proofs recompute the signed root | `test_export.py::test_tampered_{leaf,root,signature}_fails_verification` |
| 2 | Fully self-consistent forged bundle signed with the attacker's own embedded key | Authenticity: verify only against the caller-pinned key; embedded key advisory | `test_export.py::test_forged_key_is_rejected`, `test_no_trust_anchor_fails_closed`, `test_swapped_embedded_key_is_rejected` |
| 3 | Kernel-side signing-key swap after onboarding | Pinned `key_id → PEM` registry at the verifier; swapped key/key_id won't match | `test_export.py::test_wrong_pinned_pem_fails_signature`, `test_missing_embedded_key_still_verifies_against_pin` |
| 4 | Split view — two histories to two audiences | Witness cosigns one history line; divergent STH fails the consistency proof | `test_witness.py::test_refuses_same_size_fork`, `test_export.py::test_anchor_attesting_wrong_head_rejected` |
| 5 | Silent rewind (drop sealed entries, re-grow) | Witness last-seen high-water mark + consistency proof | `test_witness.py::test_refuses_rewind` |
| 6 | Rewind timed across a witness restart | Durable, advance-only `PostgresWitnessStateStore` | `test_witness_state.py::test_rewind_caught_after_restart_with_durable_state` (+ the contrast test showing an in-memory store misses it) |
| 7 | Forged witness cosignature / unknown witness | Anchoring pinned like authenticity; wrong-head equality check | `test_export.py::test_unpinned_witness_rejected`, `test_anchored_bundle_verifies_with_pinned_witness` |
| 8 | Strip the anchor from a bundle | Verifier demands an anchor when `trusted_witnesses` is supplied | `test_export.py::test_missing_anchor_fails_when_witness_pinned` |
| 9 | Second-preimage on the tree | RFC 6962 0x00/0x01 domain separation | `test_merkle.py::test_leaf_hash_uses_0x00_domain_separator`, `test_internal_hash_uses_0x01_domain_separator` |
| 10 | Cross-protocol signature reuse (STH vs cosignature) | Disjoint signing messages: STH = raw `size‖root` under the *ledger* key; cosignature = `quaicu.witness.v1`-prefixed under the *witness* key (different keys, different formats) | reviewer to confirm |
| 11 | Cross-tenant proof replay | Per-tenant trees/tables (F-07); tenant in the cosignature signing message | `test_engine.py` isolation cases |
| 12 | Concurrent multi-worker sealing → lost entries / STH-vs-entries fork | Optimistic seal linearization (§2.5): PK insert arbitrates; loser rehydrates + retries; advance-only STH | `test_concurrent_seal.py` (no-loss interleave, STH == recomputed root, stale-STH rejection, exhaustion → HALT, benign replay) |

Out of scope for the mechanism (documented honestly): a kernel + witness that **collude**
from genesis; compromise of the verifier's own pinned-key records; availability of the
witness (an outage blocks anchored exports — fail-closed by design, tracked as an ops
concern, not a soundness one).

## 6. Review surface — file inventory (at tag `k02-review-v2`)

| Area | Files |
|---|---|
| Merkle + proofs | `quaicu/core/ledger/merkle.py` |
| Sealing / canonical bytes / engine | `quaicu/core/ledger/engine.py`, `quaicu/core/ledger/repository.py` |
| STH signing | `quaicu/core/ledger/signer.py`; adapters `openbao.py` (Ed25519), `gcp_kms.py`, `aws_kms.py` (ECDSA P-256), `memory_signed.py` |
| Anchor port + orchestration | `quaicu/core/ports/anchor.py`, `quaicu/core/ledger/anchor.py` |
| Witness | `quaicu/adapters/ledger/witness.py`, `quaicu/adapters/ledger/witness_store_postgres.py` (+ migration `016_create_witness_state.py`), `quaicu/adapters/ledger/http_witness.py`, `quaicu/delivery/witness_app.py`, `quaicu/delivery/entrypoint_witness.py` |
| Offline verifier + bundle | `quaicu/core/regmap/export.py` |
| Persistence | `quaicu/adapters/ledger/postgres.py` (append-only, per-tenant), `quaicu/adapters/ledger/memory*.py` (tests) |
| Tests | `tests/unit/ledger/` (merkle, engine, consistency_proof, witness, witness_state, witness_service, persistence, nonblocking_seal, **concurrent_seal**), `tests/unit/regmap/test_export.py` |

Key-custody surfaces (`openbao.py`, `gcp_kms.py`, `aws_kms.py`) are in scope.

## 7. How a reviewer runs it

```bash
pip install -e ".[dev]"          # from the repository root at the pinned tag
python -m pytest tests/unit/ledger tests/unit/regmap -q     # the K·02 suites
python -m pytest tests/unit -q                              # full unit suite (~1.2k tests)
```

All crypto uses `cryptography` (pyca) + `hashlib.sha256`; there is no hand-rolled primitive —
the review target is the *protocol composition and its fail-closed verifier*, not cipher code.

## 8. Changes since `k02-review-v1` (why the freeze was re-tagged)

The D4-1 shared-plane hardening surfaced a **multi-worker sealing defect** in the v1 surface: the
durable entry insert was `ON CONFLICT DO NOTHING` with no status check, so with `--workers > 1`
two workers racing the same `(tenant, ledger_seq)` slot silently dropped one seal while both
reported success, and the last-writer-wins STH upsert could persist an STH inconsistent with the
persisted entries (an accidental same-size fork — exactly what the D3-2 witness flags). Since the
T-1 review had not started, the owner elected to fix and re-freeze rather than hand reviewers a known-bad
concurrency story.

Delta (everything else in §6 is byte-identical to v1):

| File | Change |
|---|---|
| `quaicu/core/errors.py` | new `LedgerSequenceConflictError(LedgerPersistenceError)` |
| `quaicu/core/ledger/engine.py` | `seal` = bounded optimistic retry: conflict → `pop_last` → `_rehydrate_tenant` (new) → retry; exhaustion → HALT |
| `quaicu/core/ledger/repository.py` | conflict + advance-only contracts documented; new `load_tenant_entries(tenant)` |
| `quaicu/adapters/ledger/postgres.py` | insert status-tag conflict detection + benign-replay check; advance-only STH upsert; `load_tenant_entries` |
| `quaicu/adapters/ledger/memory_repo.py` | mirrors the same contract (drives the unit suite) |
| `tests/unit/ledger/test_concurrent_seal.py` | new — two ledgers over one repository simulate two workers |

No change to hashing, proofs, signing messages, the witness protocol, or the offline verifier —
§2.1–2.4 and §3 are exactly the v1 semantics. §2.5 (the linearization invariant) and threat row 12
are the new review material.
