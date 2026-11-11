# ADR-0003: Decision-only authorization surface (PDP / PEP split)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/lifecycle/` (`decision.py`, `engine.py`), `quaicu/delivery/sdk/kernel.py`, `quaicu/delivery/api/routes/authorize.py`, `quaicu/delivery/api/middleware.py`

## Context

Every entry path bundled **decision with execution**: `@governed`, `governed_tool`, `generate`, and
`POST /v1/actions/propose` all run `LifecycleEngine.run`, which inserts the action, transitions the
state machine, executes the body, seals, and emits. There was no way to ask *"is this allowed?"*
without also performing the action.

That blocks the kernel from being a **monitoring layer for every AI/user action** (the stated goal):
an enforcement point in front of an action the kernel does not itself execute (an LLM call inside a
customer's app, a user clicking "approve") needs a pure verdict it can act on. In policy-architecture
terms the kernel was a strong **PDP** (Policy Decision Point) with no decision API and no **PEP**
(Policy Enforcement Point) story.

## Decision

Add a **side-effect-free decision path** alongside `run`, and make the verdict the caller's to enforce.

- `LifecycleEngine.decide(action, *, context=None, profile=None, record=None) -> AuthorizationResult`
  runs identity → consent → policy and returns a verdict. It performs **no** repository insert, **no**
  state-machine transition, **no** event emit, and never mutates the action. Each enabled layer keeps
  the same fail-closed semantics as `run` (identity fault / consent missing / policy error → DENY).
- `AuthorizationResult` is a new frozen type in **`quaicu/core/lifecycle/decision.py`** — deliberately *not*
  in the frozen `quaicu/core/types.py`, so the frozen surface is untouched. It carries
  `decision / allowed / actor_id / reason / policy_versions / approvers / enforced_layers /
  consent_state / sealed / ledger_seq`.
- **Monitoring is sealing a decision-only leaf.** When `record` is `None` the seal follows the active
  profile's `seal_to_ledger`; under the default `all()`/`monitor()` profile every decision is sealed
  (`recorded_result={"decision_only": True}`) — a tamper-evident log of *decisions*, not just executed
  actions. A seal failure here is **best-effort** (logged, `sealed=False`): a failed monitoring record
  must never turn a pure query into a HALT. (Contrast `run`, where a seal failure HALTs.)
- `kernel.check(...)` / `BoundAgent.check(...)` expose this in the SDK and **never raise on DENY** —
  the caller is the enforcement point.
- `POST /v1/authorize` is a **pure PDP**: it **always returns 200** with the verdict in the body
  (`allowed: false` on deny), never a 403. HTTP status encodes infra faults only.
- `GovernanceMiddleware` (`quaicu/delivery/api/middleware.py`) is the reference **PEP**: opt-in via
  `create_app(enforce_paths=...)`, it calls `check()` and short-circuits denied requests with 403
  before the route runs.

The consent decision logic is refactored into a non-mutating `_consent_verdict` helper shared by both
`run` (which wraps failures in `_deny`) and `decide` (which maps them straight to a DENY verdict), so
the two paths cannot drift.

## Consequences

- The kernel can now sit in front of actions it does not execute, and can run in pure monitor mode
  (record every decision, block nothing) — the foundation of "govern every action."
- `decide`/`check` is safe to call on hot paths and from PEPs because it is guaranteed side-effect-free
  (asserted in `tests/unit/lifecycle/test_decide.py`: no repo insert, no state change).
- Forbidden: making `/v1/authorize` return non-200 for a deny verdict (it is a decision, not an error),
  or letting a monitoring-seal failure change the verdict.
- Any future enforcement point (proxy, sidecar, framework hook) builds on `check()`, not on `run`.

## Alternatives considered

- **Reuse `run` with a no-op execute_fn for "check".** Rejected — it still inserts the action,
  transitions state, and seals an execution leaf; not side-effect-free and wrong leaf semantics.
- **Return 403 on deny from `/v1/authorize` (mirror `/propose`).** Rejected — a PDP answers a question;
  the enforcement decision belongs to the caller. 200-with-verdict matches OPA/standard policy APIs.
