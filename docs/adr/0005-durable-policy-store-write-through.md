# ADR-0005: Durable policy store as a write-through cache (`PolicyRepository`)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/policy/` (`repository.py`, `store.py`), `quaicu/adapters/policy/` (`memory.py`, `postgres.py`), `quaicu/adapters/storage/migrations/versions/002_*`, `quaicu/delivery/sdk/kernel.py`, `quaicu/delivery/api/app.py`

## Context

The real K·01 CEL `PolicyEngine` was built and tested but (a) **unreachable through
`Kernel.from_config`** — only the dev `always_allow` adapter was registered — and (b) backed by an
**in-memory `PolicyStore`** that loses every policy on restart. A policy management API and dashboards
cannot be built on a store that is both inaccessible from config and non-durable.

The hard constraint shaping the design: `PolicyEngine.evaluate` → `PolicyStore.lookup` is **sync and
on the hot path**, and each policy holds a **compiled CEL program** (`compiled_condition`) that is
**not serialisable**. A naive "swap the store for a Postgres-backed one" would either put a DB round
trip on every evaluation or require serialising compiled programs — both unacceptable.

## Decision

Persist policies with a **write-through cache** model; the in-memory store stays the read path.

- New port **`PolicyRepository`** (`quaicu/core/policy/repository.py`, async): `load_all`,
  `load_impact_reports`, `save_envelope`, `save_impact_report`, `set_lifecycle`, `close`. It is a
  layer-owned port added under ADR-0001's incremental-freeze rule (sub-decision 3) — the frozen
  `quaicu/core/ports` is untouched. Adapters: `InMemoryPolicyRepository` (default) and
  `PostgresPolicyRepository` (asyncpg, upsert, faults wrapped in the new `PolicyPersistenceError`),
  with Alembic migration `002` (`quaicu_policies`, `quaicu_policy_impact_reports`).
- `PolicyStore` gains an **optional `repository`** and stays the fast in-memory read cache. The
  **sync `register`/`activate`/`lookup` API is preserved unchanged** (existing K·01 tests untouched).
  New async write-through methods — `hydrate`, `register_persisted`, `activate_persisted`,
  `deprecate_persisted` — coordinate cache + repository. The hot-path `lookup` **never touches the DB**.
- **Compiled CEL is never persisted.** `load_all` returns envelopes with `compiled_condition=None`;
  `hydrate()` re-`register`s each, which **recompiles the CEL on load**. This is the load-bearing
  reason for write-through rather than a DB-backed store.
- **Config wiring:** `policy = "cel_policy"` builds `PolicyEngine` over a `PolicyStore` (helper
  `_build_policy`); `[adapters].policy_store` selects the durable backend. The kernel exposes
  `policy_store`/`policy_repository` and `register_policy`/`activate_policy`/`deprecate_policy`
  primitives (the surface the future management API wraps). `kernel.startup()` calls `hydrate()`
  (wired into the FastAPI lifespan); `shutdown()` closes pools.
- **No file seeding (deliberate).** Policies enter only through the durable write path. A
  freshly-configured kernel with an empty store **fail-closed DENYs every governed action** until
  policies are written and ACTIVATED — the intended secure default, consistent with F-03.

## Consequences

- The real CEL engine is now selectable from config and survives restarts (hydrate-on-boot).
- Evaluation stays fast and synchronous; durability cost is paid only on writes and at startup.
- A management API (next iteration) is a thin HTTP layer over the existing write-through primitives.
- Forbidden: adding a DB round-trip to the evaluation hot path, or persisting the compiled CEL program.
- CI: in-memory round-trip + hydrate-recompiles-CEL + full durability loop
  (`tests/unit/policy/test_store_persistence.py`); Postgres adapter mock-tested (no live DB,
  `tests/unit/adapters/test_postgres_policy.py`); end-to-end config wiring
  (`tests/unit/sdk/test_policy_wiring.py`).

## Alternatives considered

- **Replace `PolicyStore` with a Postgres-backed store implementing the same interface.** Rejected —
  puts an async DB call on the sync evaluation hot path and/or forces serialising the non-serialisable
  compiled CEL program.
- **Cache compiled programs by serialising them.** Rejected — celpy programs are not portable
  artifacts; recompiling from the stored `condition` string on hydrate is simple and correct.
- **Seed policies from a config/pack file at boot.** Rejected for this iteration (per the user) — the
  secure default is an empty store that DENYs until policies are explicitly written; file seeding can
  be added later without changing this port.
