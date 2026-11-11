# ADR-0008: Durable ledger persistence (`LedgerRepository` write-through)

- **Status:** Accepted
- **Date:** 2026-06-12
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/ledger/` (`repository.py`, `engine.py`, `merkle.py`), `quaicu/core/errors.py`, `quaicu/adapters/ledger/` (`memory_repo.py`, `postgres.py`, `openbao.py`), `quaicu/adapters/storage/migrations/versions/003_*`, `quaicu/delivery/sdk/kernel.py`

## Context

`OpenBaoLedgerAdapter` gave the K·02 transparency log a durable *signing key* (OpenBao Transit) but
wrapped an in-memory `TrustLedger`: the per-tenant Merkle trees, sealed `LedgerEntry` rows, and
Signed Tree Heads lived in process dicts and were **lost on restart**. A bank deployment needs the
log itself to survive restarts and be reconstructable — this was the heaviest remaining pre-sale
blocker.

The constraint shaping the design (same as ADR-0005's policy store): the read/proof path
(`get_entries`, inclusion/consistency proofs) is hot and synchronous, and the Merkle tree is cheap to
rebuild from its leaf hashes. So durability should be a write-through cache, not a DB round-trip on
every proof. `LedgerEntry` already carries every field, so no frozen `quaicu/core/types.py` change is
needed — but adding the port + write-through is recorded here under ADR-0001's incremental-freeze
rule (as `PolicyRepository` was under ADR-0005).

## Decision

Persist the ledger with a **write-through cache**; the in-memory per-tenant trees stay the read path.

- New port **`LedgerRepository`** (`quaicu/core/ledger/repository.py`, async): `append_entry`,
  `load_entries`, `save_sth`, `load_sths`, `close`. Layer-owned (frozen `quaicu/core/ports` untouched).
  Adapters: `InMemoryLedgerRepository` (default/tests) and `PostgresLedgerRepository` (asyncpg,
  mock-tested), faults wrapped in the new `LedgerPersistenceError`. Alembic migration `003`
  (`quaicu_ledger_entries` keyed `(tenant_id, ledger_seq)`, `quaicu_ledger_sth` keyed `tenant_id`).
- `TrustLedger` gains an optional `repository`. `seal()` is **write-through**: it appends the leaf,
  signs the new head, then persists the entry + STH **before** committing the in-memory mutation. On
  any signing or persistence failure it rolls back the in-memory append (`MerkleTree.pop_last`) and
  raises → `LedgerSealError` → the action HALTs (F-03). The durable log and the in-memory tree never
  diverge. No repository wired → unchanged in-memory behavior.
- `TrustLedger.hydrate()` rebuilds every tenant's tree from the stored leaf hashes
  (`MerkleTree.append_leaf_hash`), restores `_entries`/`_sequences`, and loads the latest STH
  (recompute + re-sign if a tenant has entries but no stored head). Idempotent.
- **Config wiring:** `[adapters].ledger_store` selects the durable backend (`postgres_ledger` /
  `memory_ledger_repo`); `_build_ledger` injects it into the TrustLedger-based `openbao_ledger`
  adapter. `kernel.startup()` calls `ledger.hydrate()` (after the policy hydrate); `shutdown()`
  closes the pool. The dev `memory_ledger` adapter does not persist.

**Tenant isolation (F-07):** the durable tables are keyed by `tenant_id` and every read is
tenant-scoped — the same logical-isolation posture the shipped `quaicu_actions` table uses. Physical
schema-per-tenant tables remain a hardening follow-up (see Consequences), not blocked by this ADR.

## Consequences

- The transparency log survives restarts: a kernel rebuilds entries, sequence, STH, and working
  proofs purely from the repository on boot. Proofs stay fast and synchronous (in-memory trees).
- A seal that cannot be persisted HALTs the action (fail-closed) rather than completing an unrecorded
  governed action — and leaves no orphan in-memory leaf.
- Forbidden: putting a DB round-trip on the proof/read hot path, or letting the in-memory tree get
  ahead of the durable log on a failed write.
- **Remaining hardening (not this ADR):** physical per-tenant ledger tables/schemas (stronger than
  the current `tenant_id`-keyed shared table) and the standing K·02 third-party cryptographic review.
- CI: `tests/unit/ledger/test_persistence.py` (write-through, hydrate round-trip, tenant isolation,
  fail-closed rollback), `test_merkle.py` (`append_leaf_hash`/`pop_last`),
  `tests/unit/adapters/test_postgres_ledger.py` (mock adapter), `tests/unit/sdk/test_ledger_wiring.py`
  (startup hydrate), and a `DATABASE_URL`-gated `tests/conformance/ledger/test_postgres_spec.py`.

## Alternatives considered

- **Replace the in-memory tree with a Postgres-backed Merkle store.** Rejected — puts DB I/O on the
  proof hot path; the tree rebuilds cheaply from stored leaf hashes, so a write-through cache is
  simpler and faster (mirrors ADR-0005).
- **Persist only entries and re-sign the STH on hydrate.** Rejected as the default — persisting the
  signed head preserves the exact historical signature; re-signing is kept only as the fallback when
  a tenant has entries but no stored head.
- **Physical schema-per-tenant tables now.** Deferred — the shipped `quaicu_actions` table already
  uses a shared `tenant_id`-keyed design; matching it keeps the adapters consistent, and physical
  isolation is recorded as a follow-up rather than expanding this change.
