#!/usr/bin/env python3
"""QUAICU Python SDK — async approval + error semantics, end-to-end in one process.

This is the D2-3 worked example: it shows the *SDK ergonomics* around governance outcomes — the
typed exceptions you catch and the ``kernel.approve`` / ``kernel.reject`` helpers — with zero
external services. Four beats:

  1. ALLOW              → the guarded function runs and returns normally.
  2. DENY               → the call raises ``LifecycleDeniedError`` (terminal — do not retry).
  3. REQUIRE_APPROVAL   → the call raises ``LifecyclePendingApprovalError`` (NOT a failure): the
                          action suspended durably. A different compliance officer then
                          ``kernel.approve(handle_id, actor=checker)`` → the action resumes,
                          executes its recorded payload, and seals to the K·02 ledger.
  4. Separation of duties → the *maker* trying to approve their own action is blocked (fail-closed).

Everything is public SDK surface: the governance API and every exception come from
``delivery.sdk``. Only the one-time wiring (a real policy engine + in-memory HITL/ledger/event
adapters) reaches into the kernel internals, exactly as a host app's bootstrap would.

    python examples/sdk-approval-demo/demo.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Emojis/arrows in the narrative need a UTF-8 stream (Windows consoles default to cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

# Make the kernel importable when run directly (repo root = two levels up from this file).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# ── Public SDK surface: the governance API + the exceptions you catch ──────────────
from quaicu.delivery.sdk import (  # noqa: E402
    Kernel,
    LifecycleDeniedError,
    LifecyclePendingApprovalError,
    QUAICUError,
)

# ── One-time wiring (a host app does this once at boot) ────────────────────────────
from quaicu.adapters.events.memory import InMemoryEventBusAdapter  # noqa: E402
from quaicu.adapters.ledger.memory_signed import MemorySignedLedgerAdapter  # noqa: E402
from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.policy import PolicyEngine, PolicyEnvelope, PolicyStore  # noqa: E402
from quaicu.core.policy.model import PolicyLifecycle  # noqa: E402
from quaicu.core.types import Actor, ActorId, ApproverRef, Decision, TenantId  # noqa: E402

TENANT = TenantId("demo-co")

# Two distinct compliance officers — the kernel forbids self-approval (separation of duties).
MAKER = Actor(id=ActorId("compliance:alice"), tenant=TENANT, roles=("role:compliance",))
CHECKER = Actor(id=ActorId("compliance:bob"), tenant=TENANT, roles=("role:compliance",))


def _policy(governs: str, decision: Decision, *, approvers: tuple[str, ...] = ()) -> PolicyEnvelope:
    """An ACTIVATED, always-matching policy for one action type (condition = ``true``)."""
    return PolicyEnvelope(
        id=f"demo.{governs}",
        version=1,
        governs=governs,
        scope={"tenant": "*"},
        condition="true",
        decision=decision,
        approvers=tuple(ApproverRef(a) for a in approvers),
        regulatory_refs=(),
        lifecycle=PolicyLifecycle.ACTIVATED,
    )


def _build_kernel(hitl: InProcessHITLPort, ledger: MemorySignedLedgerAdapter) -> Kernel:
    store = PolicyStore()
    store.register(_policy("demo.allow", Decision.ALLOW))
    store.register(_policy("demo.deny", Decision.DENY))
    store.register(_policy("demo.approve", Decision.REQUIRE_APPROVAL, approvers=("role:compliance",)))
    return Kernel.from_parts(
        tenant=TENANT,
        policy=PolicyEngine(store),
        hitl=hitl,
        ledger=ledger,
        events=InMemoryEventBusAdapter(),
        policy_store=store,
    )


async def main() -> int:
    print("=" * 78)
    print("QUAICU Python SDK — async approval + error semantics")
    print("=" * 78)

    hitl = InProcessHITLPort()
    ledger = MemorySignedLedgerAdapter()
    kernel = _build_kernel(hitl, ledger)

    # The "agent": three guarded functions, one per policy decision. Signatures are unchanged —
    # governance is the decorator line + an actor_context at the call boundary.
    @kernel.guard(policy="demo.allow")
    async def do_allowed(*, note: str) -> dict:
        return {"ran": True, "note": note}

    @kernel.guard(policy="demo.deny")
    async def do_denied(*, note: str) -> dict:  # pragma: no cover - body never runs (denied)
        return {"ran": True, "note": note}

    @kernel.guard(policy="demo.approve")
    async def do_needs_approval(*, note: str) -> dict:
        return {"ran": True, "note": note}

    # 1) ALLOW ─────────────────────────────────────────────────────────────────────
    async with kernel.actor_context(MAKER):
        result = await do_allowed(note="routine")
    print(f"\n1) ALLOW    → ran, returned {result}")

    # 2) DENY ──────────────────────────────────────────────────────────────────────
    try:
        async with kernel.actor_context(MAKER):
            await do_denied(note="forbidden")
        raise SystemExit("BUG: denied action did not raise")
    except LifecycleDeniedError as exc:
        print(f"2) DENY     → raised {type(exc).__name__} (code={exc.code}) — terminal, not retried")

    # 3) REQUIRE_APPROVAL → pending → a *different* officer approves ─────────────────
    handle_id: str | None = None
    try:
        async with kernel.actor_context(MAKER):
            await do_needs_approval(note="high-value")
        raise SystemExit("BUG: require_approval action did not suspend")
    except LifecyclePendingApprovalError as exc:
        handle_id = exc.detail["handle_id"]
        print(
            f"3) APPROVAL → raised {type(exc).__name__} (code={exc.code}); "
            f"action {exc.detail['action_id']} is PENDING, handle={handle_id}"
        )

    assert handle_id is not None
    record = await kernel.approve(handle_id, actor=CHECKER)
    print(f"            → kernel.approve(actor={CHECKER.id}) → decision={record.decision.value}; "
          "action resumed → executed → sealed to the K·02 ledger")

    # 4) Separation of duties — the maker cannot approve their own action ────────────
    hitl2 = InProcessHITLPort()
    kernel2 = _build_kernel(hitl2, MemorySignedLedgerAdapter())

    @kernel2.guard(policy="demo.approve")
    async def another_approval(*, note: str) -> dict:
        return {"ran": True, "note": note}

    own_handle: str | None = None
    try:
        async with kernel2.actor_context(MAKER):
            await another_approval(note="self-approve attempt")
    except LifecyclePendingApprovalError as exc:
        own_handle = exc.detail["handle_id"]

    assert own_handle is not None
    try:
        await kernel2.approve(own_handle, actor=MAKER)  # maker == proposer → blocked
        raise SystemExit("BUG: self-approval was allowed")
    except QUAICUError as exc:
        print(f"4) SoD      → maker approving own action blocked: {type(exc).__name__} (code={exc.code})")

    print("\n✅ done — allow / deny / approve / self-approval-block all behaved as governed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
