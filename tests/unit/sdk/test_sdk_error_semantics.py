"""D2-3: SDK error semantics — re-exports importable, governance outcomes typed, misuse → SdkUsageError.

Governance *outcomes* (deny/halt/pending) are the typed LifecycleError subclasses; SDK *misuse*
(no actor, no adapter) is the new SdkUsageError. All are catchable from `delivery.sdk`.
"""

from __future__ import annotations

import pytest

# The whole error surface must be importable straight from the SDK (no reaching into core.errors).
from quaicu.delivery.sdk import (
    Kernel,
    LifecycleDeniedError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
    QUAICUError,
    SdkUsageError,
)
from quaicu.core.types import Actor, ActorId, Decision, ModelRef, TenantId
from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger, FakePolicy

TENANT = TenantId("acme")
ACTOR = Actor(id=ActorId("alice"), tenant=TENANT)


def _kernel(*, decision=Decision.ALLOW, ledger=None, gateway=None) -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=ledger or FakeLedger(),
        events=FakeEvents(),
        gateway=gateway,
    )


def test_error_types_are_reexported_and_subclass_quaicu_error():
    assert issubclass(SdkUsageError, QUAICUError)
    for cls in (LifecycleDeniedError, LifecycleHaltedError, LifecyclePendingApprovalError):
        assert issubclass(cls, QUAICUError)
    assert SdkUsageError("x").code == "SDK_USAGE_ERROR"


async def test_deny_raises_lifecycle_denied():
    kernel = _kernel(decision=Decision.DENY)

    @kernel.guard(policy="payments.transfer")
    async def transfer(amount: int) -> dict:
        return {"moved": amount}

    with pytest.raises(LifecycleDeniedError):
        async with kernel.actor_context(ACTOR):
            await transfer(amount=100)


async def test_seal_fault_raises_lifecycle_halted():
    # An injected ledger seal failure must HALT (fail-closed), surfaced as LifecycleHaltedError.
    kernel = _kernel(ledger=FakeLedger(raise_exc=True))

    @kernel.guard(policy="records.write")
    async def write_record(data: str) -> None:
        return None

    with pytest.raises(LifecycleHaltedError):
        async with kernel.actor_context(ACTOR):
            await write_record("x")


async def test_guard_missing_actor_raises_sdk_usage_error():
    kernel = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve(loan_id: str) -> dict:
        return {"ok": loan_id}

    with pytest.raises(SdkUsageError, match="no actor in scope"):
        await approve("L1")


async def test_wrap_missing_actor_raises_sdk_usage_error():
    kernel = _kernel()

    async def do_work() -> str:
        return "done"

    governed = kernel.wrap(do_work, policy="work.do")
    with pytest.raises(SdkUsageError, match="no actor in scope"):
        await governed()


async def test_governed_missing_actor_raises_sdk_usage_error():
    kernel = _kernel()

    @kernel.governed(policy="test.action")
    async def do_thing(value: int, *, actor: Actor):
        return value

    with pytest.raises(SdkUsageError, match="actor"):
        await do_thing(42)


async def test_governed_tool_missing_actor_raises_sdk_usage_error():
    kernel = _kernel()

    @kernel.governed_tool(policy="tools.search")
    async def search(q: str) -> str:
        return "ok"

    with pytest.raises(SdkUsageError, match="actor"):
        await search(q="x")


async def test_generate_without_gateway_raises_sdk_usage_error():
    kernel = _kernel(gateway=None)
    with pytest.raises(SdkUsageError, match="inference adapter"):
        await kernel.generate(
            prompt_text="hi", model_ref=ModelRef(id="m", version="1"), actor=ACTOR
        )
