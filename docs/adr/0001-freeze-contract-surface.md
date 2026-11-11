# ADR-0001: Freeze the contract surface (Wave 0)

- **Status:** Accepted
- **Date:** 2026-06-06
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/ports/`, `quaicu/core/types.py`, `quaicu/core/errors.py` — and therefore every layer and adapter

## Context

The kernel is built by multiple AI agents working in parallel (see `AGENTS.md`). Agents do not share
memory and cannot coordinate live. The only way parallel work is safe is if every agent builds against
a **stable, shared interface surface** that does not change underneath it. Build spec §5 defines the
ports; the `quaicu-kernel-arch` skill defines the error hierarchy; the `clean-code` skill mandates
immutable domain models. Wave 0 commits these as the first artifact so Waves 1+ can proceed in parallel.

## Decision

The following files are the **frozen contract surface**. They are committed before any layer is built
and may not change except through the orchestrator + a new ADR:

- `quaicu/core/ports/` — `InferencePort`, `HITLPort`, `IdentityPort`, `StoragePort`, `WorkflowPort`
  (`typing.Protocol`, `runtime_checkable`), faithful to build spec §5.
- `quaicu/core/types.py` — shared value types: identifiers (`TenantId`, `ActionId`, …), enums (`ActionState`,
  `Decision`, `ApprovalDecision`), and the cross-layer shapes `Action`, `Actor`, `RequestContext`,
  `EvaluationResult`, `LedgerEntry`, plus the port-referenced types.
- `quaicu/core/errors.py` — the `QUAICUError` hierarchy. Every error in `core/` is a typed subclass.

Resolved sub-decisions:

1. **Immutable domain models.** `Action`, `EvaluationResult`, `LedgerEntry`, and the value types are
   `@dataclass(frozen=True)`. Lifecycle progress is expressed by constructing a new value
   (`Action.with_state(...)` / `dataclasses.replace`), never in-place mutation. This supersedes the
   illustrative in-place `action.state = ...` shown in some skill anti-pattern snippets (those snippets
   illustrate fail-closed exception handling, not the state model).
2. **One error tree.** All errors — including Gateway (K·05) and Consent (K·04) — are rooted at
   `QUAICUError`. No parallel error base. (The `ai-gateway` skill's standalone `GatewayError(Exception)`
   is folded under `QUAICUError` here; the architecture skill is authoritative on the tree.)
3. **Minimal where a layer owns the detail.** `Transaction` is a thin Protocol marker; `ProcessDef`
   is a minimal frozen shape. Per-layer repository methods and the full K·06 step DSL are added by the
   owning layer **under this same freeze rule** — they are not pre-frozen here, to avoid guessing.
4. **Ports raise, never return permissive defaults.** Every port method fail-closes by raising a typed
   error; returning `None`/empty is a `PortContractError` caught by the conformance suite.

## Consequences

- Waves 1+ (K·01 Policy, K·02 Ledger, …) may begin in parallel against these interfaces (`AGENTS.md` §9).
- Any need to change a port signature, a shared field, or an error `code` is an escalation → new ADR →
  orchestrator edit → notify dependents. Silent edits are forbidden.
- CI enforces the surface stays clean: no domain terms / no SDK·DB imports in `core/`, `mypy --strict`,
  and the adapter conformance suites verify each adapter satisfies its port Protocol.
- The surface compiles and imports cleanly (verified at creation: `py_compile` + import smoke test).

## Alternatives considered

- **Build layers first, extract interfaces later.** Rejected — parallel agents would diverge before any
  interface stabilized; integration would be a merge nightmare.
- **Fully specify every repository method up front.** Rejected — over-freezes layer-internal detail we
  can't yet know; better to freeze incrementally per layer under the same rule (sub-decision 3).
