# ADR-0004: Zero-friction integration — ambient actor context + guard / wrap / proxy

- **Status:** Accepted
- **Date:** 2026-06-10
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/lifecycle/context.py` (new), `quaicu/delivery/sdk/kernel.py`, `quaicu/delivery/sdk/proxy.py` (new)

## Context

Requirement from the user: a customer must be able to adopt the kernel **without changing their
existing codebase except for adding a few kernel calls** — no function-signature changes, no
call-site rewrites, no fork. The existing decorators (`@kernel.governed`, `governed_tool`) forced the
wrapped function to accept `actor: Actor` and forced every call-site to thread the actor through. For
an existing app that is invasive: it touches every governed function and every place that calls one.

## Decision

Introduce an **ambient, task-local actor** and three additive wrappers that read it. None of these
change the frozen surface; they live in `quaicu/core/lifecycle/context.py` and `quaicu/delivery/sdk/`.

- **Actor `ContextVar`** (`quaicu/core/lifecycle/context.py`): the governed actor is bound once at the
  request/session boundary and read implicitly by the wrappers. `ContextVar` is chosen specifically
  because it is **task-local under asyncio** — each `asyncio` task inherits the context at creation and
  runs in its own copy, so concurrent requests cannot see each other's actor. Exposed as
  `kernel.actor_context(actor)` (works as both `with` and `async with`, accepts an `Actor` or a bare
  id string) plus imperative `set_actor`/`get_actor` escape hatches.
- **`@kernel.guard(policy=...)`** — decorate any existing function; **signature and call-sites
  unchanged**. The actor comes from the ContextVar (with an `actor=` kwarg escape hatch). Returns the
  function's own value; raises `LifecycleDeniedError`/`LifecycleHaltedError` on DENY/HALT.
- **`kernel.wrap(fn, policy=...)`** — the programmatic (non-decorator) form, for callables the
  developer does not own (third-party libraries).
- **`kernel.proxy(obj, policies={...})`** (`quaicu/delivery/sdk/proxy.py`) — a transparent object proxy that
  governs only the listed dotted method paths (e.g. `"chat.completions.create"`) and passes every other
  attribute access straight through, so wrapping a client (OpenAI, a DB client) is invisible to the
  rest of the code.

The integration contract becomes: `Kernel.from_config(...)` once, one decorator/`wrap`/`proxy` line
per governed surface, and one `actor_context(...)` at each request boundary — nothing else in the
host codebase changes.

## Consequences

- Adoption is additive: existing functions keep their exact signatures and call-sites.
- A clear, fail-closed error is raised when a `guard`/`wrap`/`proxy` call runs with no actor in scope
  (no silent "anonymous" execution).
- Trade-off accepted: governance now depends on **ambient context**, which is implicit. The mitigations
  are (a) ContextVar's task-local isolation prevents cross-request bleed, (b) the explicit `actor=`
  override remains for call sites that prefer it, and (c) a missing actor fails closed rather than
  proceeding. The original explicit-`actor` decorators (`governed`, `governed_tool`, `for_agent`)
  remain for callers who want no ambient state.
- CI covers binding/restore, nesting, sync+async, deny, no-actor error, and proxy pass-through
  (`tests/unit/sdk/test_zero_friction.py`).

## Alternatives considered

- **Keep requiring an explicit `actor=` parameter everywhere.** Rejected — it forces signature and
  call-site edits across the host codebase, the exact friction this ADR removes.
- **Thread-local instead of ContextVar.** Rejected — thread-locals are wrong under asyncio (one thread
  runs many tasks); a `ContextVar` is the correct async-aware primitive.
- **A global mutable "current actor".** Rejected — not concurrency-safe; one request would overwrite
  another's actor.
