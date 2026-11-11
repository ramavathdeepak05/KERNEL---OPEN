"""kernel.check() and BoundAgent.check() — decision-only SDK surface."""

from __future__ import annotations


from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.types import ActorId, Decision, TenantId
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger, FakePolicy

TENANT = TenantId("acme")


def _kernel(decision=Decision.ALLOW):
    ledger = FakeLedger()
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=ledger,
        events=FakeEvents(),
    )
    return kernel, ledger


# ── kernel.check basics ────────────────────────────────────────────────────────


async def test_check_allow_returns_allowed_true() -> None:
    from quaicu.core.types import Actor
    kernel, _ = _kernel()
    actor = Actor(id=ActorId("alice"), tenant=TENANT)
    result = await kernel.check(action_type="payments.wire", actor=actor, record=False)
    assert isinstance(result, AuthorizationResult)
    assert result.allowed is True


async def test_check_deny_returns_allowed_false_without_raising() -> None:
    from quaicu.core.types import Actor
    kernel, _ = _kernel(decision=Decision.DENY)
    actor = Actor(id=ActorId("alice"), tenant=TENANT)
    # Must NOT raise — the caller is the PEP.
    result = await kernel.check(action_type="payments.wire", actor=actor, record=False)
    assert result.allowed is False
    assert result.decision is Decision.DENY


async def test_check_seals_to_ledger_under_all_profile() -> None:
    from quaicu.core.types import Actor
    kernel, ledger = _kernel()
    actor = Actor(id=ActorId("alice"), tenant=TENANT)
    result = await kernel.check(action_type="payments.wire", actor=actor)
    # Default all() profile → seal_to_ledger=True
    assert result.sealed is True
    assert len(ledger.sealed) == 1
    rr = ledger.sealed[0].recorded_result
    # FakeLedger wraps recorded_result in {"result": ...}; what matters is the content.
    assert rr.get("result") == {"decision_only": True} or rr == {"decision_only": True}


async def test_check_no_seal_with_record_false() -> None:
    from quaicu.core.types import Actor
    kernel, ledger = _kernel()
    actor = Actor(id=ActorId("alice"), tenant=TENANT)
    await kernel.check(action_type="payments.wire", actor=actor, record=False)
    assert len(ledger.sealed) == 0


async def test_check_no_insert_to_repo() -> None:
    from quaicu.core.types import Actor
    kernel, _ = _kernel()
    actor = Actor(id=ActorId("alice"), tenant=TENANT)
    await kernel.check(action_type="payments.wire", actor=actor, record=False)
    # InMemoryActionRepository inside Kernel — check it stays empty.
    repo = kernel.engine._repo  # type: ignore[attr-defined]
    assert len(repo.by_key) == 0


# ── BoundAgent.check ──────────────────────────────────────────────────────────


async def test_bound_agent_check_stamps_agent_actor_id() -> None:
    kernel, ledger = _kernel()
    agent = kernel.for_agent("agent:risk-bot")
    result = await agent.check(action_type="loans.approve")
    assert str(result.actor_id) == "agent:risk-bot"
    # Sealed under default all() → ledger entry carries agent actor.
    assert ledger.sealed[0].actor_id == ActorId("agent:risk-bot")


async def test_two_agents_check_attributed_separately() -> None:
    kernel, ledger = _kernel()
    researcher = kernel.for_agent("agent:researcher")
    writer = kernel.for_agent("agent:writer")

    await researcher.check(action_type="tools.search")
    await writer.check(action_type="tools.publish")

    actor_ids = {e.actor_id for e in ledger.sealed}
    assert actor_ids == {ActorId("agent:researcher"), ActorId("agent:writer")}


async def test_bound_agent_check_deny_not_raised() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)
    agent = kernel.for_agent("agent:restricted")
    result = await agent.check(action_type="payments.wire", record=False)
    assert result.allowed is False  # no raise
