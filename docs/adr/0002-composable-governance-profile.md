# ADR-0002: Composable governance via `GovernanceProfile`

- **Status:** Accepted
- **Date:** 2026-06-10
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/lifecycle/` (`profile.py`, `engine.py`), `quaicu/core/gateway/engine.py`, `quaicu/core/ledger/engine.py`, `quaicu/delivery/sdk/kernel.py`

## Context

The original lifecycle ran a fixed, maximal pipeline: identity → consent → policy → HITL gate →
execute → seal → emit, every layer, every action. Two real requirements broke that assumption:

1. **Different actions need different governance.** A high-stakes wire transfer wants the full stack;
   a low-risk internal model call may only need the gateway protections (allowlist / PII mask /
   budget) without policy-gating or HITL. Forking the engine per posture (a separate "gateway-only"
   path was emerging) would have created exactly the multi-codebase divergence ADR-0001 exists to
   prevent.
2. **A customer must be able to adopt one layer at a time.** "Monitor mode" (record, don't block) and
   "consent only" are legitimate first steps that the all-or-nothing pipeline could not express.

The user's directive: each layer must be enforceable **independently, as a pack, or all at once** —
"full lifecycle" and "gateway-only" should be two *presets of one model*, not a fork.

## Decision

Introduce `GovernanceProfile` (`quaicu/core/lifecycle/profile.py`) — a frozen dataclass of per-call boolean
toggles for the ten inline layers: `verify_identity`, `enforce_consent`, `enforce_policy`,
`enforce_hitl_gate`, `seal_to_ledger`, `emit_events` (engine-owned) and `enforce_model_allowlist`,
`mask_pii`, `log_prompts`, `enforce_budget` (gateway sub-layers). Rules an agent applies mechanically:

- `LifecycleEngine.run(action, fn, *, profile=None)` and `AIGateway.generate(..., profile=None)` take
  a profile; `None` resolves to the engine default, which is `GovernanceProfile.all()` — so **every
  pre-existing call path keeps maximal governance unchanged** (zero regression).
- A **disabled layer is skipped, but every *enabled* layer stays fail-closed** (F-03). Disabling is an
  explicit configuration act, never a fallback. Two guards make that safe: a disabled `enforce_policy`
  synthesizes an explicit `ALLOW` with `policy_versions=("<policy-unenforced>",)` (never a silent
  pass), and `REQUIRE_APPROVAL` under a disabled `enforce_hitl_gate` **fail-closed DENYs** (you asked
  for approval but turned off the gate).
- The set of **enabled layers is sealed into the Merkle leaf** (`governance_profile` in
  `quaicu/core/ledger/engine.py`), so an auditor can verify exactly which controls ran for any action.
- Presets: `all()`, `standard()` (consent off), `gateway_only()` (gateway protections only),
  `audit_only()` (seal+emit, no gating), `monitor()` (evaluate+seal, no HITL gate). Resolved by name
  from config (`[governance]`) and overridable per action type and per call.
- Offline assurance sweeps (drift K·10, fairness K·09, sandbox K·13) are **not** per-call layers and
  are deliberately absent from the profile.

This does **not** change the frozen surface (`quaicu/core/ports`, `quaicu/core/types`, `quaicu/core/errors`):
`GovernanceProfile` is a new leaf type in `quaicu/core/lifecycle/`, and `EvaluationResult.metadata` already
existed to carry the sealed layer list.

## Consequences

- A single codebase expresses every governance posture by config — no per-customer engine fork
  (upholds ADR-0001's "one core, no forks").
- The ledger leaf now records the enforced-layer set; replay/audit can see which controls were active.
- Any new inline layer must add a profile flag **and** be honored fail-closed when enabled; CI
  lifecycle tests assert each toggle independently (`tests/unit/lifecycle/test_profile.py`).
- Forbidden: adding a layer that runs unconditionally regardless of profile, or a disabled layer that
  "passes" without an explicit recorded decision.

## Alternatives considered

- **Separate engines per posture (full vs gateway-only).** Rejected — duplicate lifecycles diverge and
  violate the one-core rule; the bug surface doubles.
- **A single coarse "mode" enum (strict/lenient/off).** Rejected — too coarse; customers need
  individual layers (e.g. consent-only, or gateway-without-policy), which an enum cannot express.
