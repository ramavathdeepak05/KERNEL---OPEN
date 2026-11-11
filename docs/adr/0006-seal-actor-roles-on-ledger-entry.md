# ADR-0006: Seal `actor_roles` on `LedgerEntry` for role-based replay

- **Status:** Accepted
- **Date:** 2026-06-12
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/types.py` (`LedgerEntry`), `quaicu/core/ledger/engine.py`, `quaicu/core/sandbox/engine.py` (`CandidateEvaluator`), `quaicu/delivery/api/routes/policies.py`

## Context

The K·13 counterfactual backtest (`POST /v1/policies/{id}/versions/{v}/simulate`) re-evaluates a
candidate policy against the tenant's sealed ledger entries, with no model re-call (F-09). The
candidate evaluator can only see what the sealed `LedgerEntry` carries.

`LedgerEntry.actor_id` was already sealed (and committed to the Merkle leaf via `_canonical_bytes`),
so a follow-up threaded it into the backtest activation — `actor_id`-based conditions replay
faithfully. But `actor_roles` were **not** on the entry. A candidate condition referencing
`actor_roles` (the common authorization shape, e.g. `"role:risk_head" in actor_roles`) hit an
undefined CEL variable, raised, and was scored fail-closed (`deny`) — inflating the simulated flip
count and making the backtest unreliable for exactly the policies banks care about.

`quaicu/core/types.py` is the frozen contract surface (ADR-0001). Adding a field to `LedgerEntry` therefore
requires an ADR. `actor_roles` is already available on the in-flight `Action` (`action.actor.roles`)
at seal time, so no upstream plumbing is needed — only the decision to seal it.

## Decision

Add **`actor_roles: tuple[str, ...] = ()`** to `LedgerEntry` (defaulted, appended after
`recorded_outputs`; all construction sites use keyword args, so existing code is unaffected).

- **Seal path** (`quaicu/core/ledger/engine.py`): `seal()` populates `actor_roles=tuple(action.actor.roles)`,
  and `_canonical_bytes` adds `"actor_roles": list(action.actor.roles)` to the hashed dict — so the
  roles are committed to the Merkle leaf alongside `actor_id`, making them tamper-evident and
  point-in-time replayable (F-09). Existing ledger tests recompute expected bytes from the same
  action, so they remain valid; no hash constants are hard-coded.
- **K·13 contract** (`quaicu/core/sandbox/engine.py`): the `CandidateEvaluator` protocol grows a 5th
  argument `actor_roles: tuple[str, ...]`; `run_counterfactual_backtest` passes `entry.actor_roles`.
- **Simulate activation** (`quaicu/delivery/api/routes/policies.py`): `_cel_activation` sets the CEL
  `actor_roles` list variable (mirroring `quaicu/core/policy/evaluator._build_activation`), so a backtest
  re-evaluates role-gated conditions exactly as the live evaluator would.

## Consequences

- Role-based policies now replay faithfully in the simulate backtest; the documented limitation is
  closed (no remaining actor field is missing — `actor_id` + `actor_roles` are both sealed).
- The Merkle leaf now commits the actor's roles. This is additive: leaf hashes for newly sealed
  entries differ from what they would have been before, but no stored vectors or cross-tree
  consistency proofs are invalidated (each tenant's tree is independent and append-only).
- Forbidden going forward: re-introducing an actor field into a policy condition that the ledger
  does not seal — the backtest must be able to reconstruct every input the live evaluator used.
- CI: `tests/unit/ledger/test_engine.py::test_seal_records_actor_roles` (roles sealed);
  `tests/unit/api/test_simulate.py::test_simulate_actor_roles_condition_evaluates` (faithful
  role-based replay). Sandbox evaluator signatures updated to the 5-arg contract.

## Alternatives considered

- **Leave roles unsealed; accept fail-closed role replay.** Rejected — it silently overstates flip
  counts for the most common policy shape (role gates), which defeats the purpose of the F-10
  backtest the simulate route feeds.
- **Reconstruct roles by re-resolving the actor via the IdentityPort at backtest time.** Rejected —
  violates F-09 (replay must reuse recorded inputs, never recompute them); roles can drift, so a
  re-resolution would not reflect the actor's roles *at the original decision*.
- **Carry roles only on the entry, not in the Merkle leaf.** Rejected — `actor_id` is already
  sealed into the leaf; sealing roles too keeps the committed record complete and tamper-evident.
