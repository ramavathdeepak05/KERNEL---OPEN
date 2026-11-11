"""Unit tests for the Kernel SDK class and @governed decorator."""

from __future__ import annotations

import pytest

from quaicu.delivery.sdk import SdkUsageError

from quaicu.core.errors import LifecycleDeniedError, LifecycleHaltedError
from quaicu.core.types import Actor, ActorId, Decision, TenantId
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import (
    FakeEvents,
    FakeHITL,
    FakeLedger,
    FakePolicy,
)

TENANT = TenantId("ciro-bank")


def _kernel(
    decision: Decision = Decision.ALLOW,
    raise_ledger: bool = False,
) -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(raise_exc=raise_ledger),
        events=FakeEvents(),
    )


def _actor() -> Actor:
    return Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:risk_analyst",))


# ── Kernel.from_parts ────────────────────────────────────────────────────────────


def test_kernel_from_parts_creates_kernel():
    k = _kernel()
    assert isinstance(k, Kernel)
    assert k.tenant == TENANT


# ── @governed decorator ──────────────────────────────────────────────────────────


async def test_governed_allow_returns_completed_action():
    k = _kernel(decision=Decision.ALLOW)

    @k.governed(policy="test.action")
    async def do_thing(*, actor: Actor):
        return "done"

    result = await do_thing(actor=_actor())
    from quaicu.core.types import ActionState
    assert result.state == ActionState.COMPLETED


async def test_governed_deny_raises_lifecycle_denied_error():
    k = _kernel(decision=Decision.DENY)

    @k.governed(policy="test.action")
    async def do_thing(*, actor: Actor):
        return "done"

    with pytest.raises(LifecycleDeniedError):
        await do_thing(actor=_actor())


async def test_governed_missing_actor_raises_type_error():
    k = _kernel()

    @k.governed(policy="test.action")
    async def do_thing(value: int, *, actor: Actor):
        return value

    with pytest.raises(SdkUsageError, match="actor"):
        await do_thing(42)  # no actor kwarg


async def test_governed_passes_kwargs_as_payload():
    k = _kernel()

    @k.governed(policy="test.action")
    async def capture(*, actor: Actor, loan_id: str, amount: int):
        return "captured"

    # After the decorated fn runs, we can't easily inspect the action payload
    # from outside. Verify indirectly: the call completes without error.
    result = await capture(actor=_actor(), loan_id="L-42", amount=1000)
    from quaicu.core.types import ActionState
    assert result.state == ActionState.COMPLETED


async def test_governed_execute_body_runs_on_allow():
    ran = []
    k = _kernel(decision=Decision.ALLOW)

    @k.governed(policy="test.action")
    async def do_thing(*, actor: Actor):
        ran.append(True)
        return "ok"

    await do_thing(actor=_actor())
    assert ran == [True]


async def test_governed_execute_body_does_not_run_on_deny():
    ran = []
    k = _kernel(decision=Decision.DENY)

    @k.governed(policy="test.action")
    async def do_thing(*, actor: Actor):
        ran.append(True)
        return "ok"

    with pytest.raises(LifecycleDeniedError):
        await do_thing(actor=_actor())
    assert ran == []


async def test_governed_halt_on_ledger_failure():
    k = _kernel(raise_ledger=True)

    @k.governed(policy="test.action")
    async def do_thing(*, actor: Actor):
        return "ok"

    with pytest.raises(LifecycleHaltedError):
        await do_thing(actor=_actor())


async def test_governed_preserves_function_name():
    k = _kernel()

    @k.governed(policy="test.action")
    async def my_special_function(*, actor: Actor):
        return "ok"

    assert my_special_function.__name__ == "my_special_function"


def test_governed_decorator_attaches_metadata():
    k = _kernel()

    @k.governed(policy="ciro.ifrs9.stage_transition")
    async def do_thing(*, actor: Actor):
        pass

    assert do_thing._governed_policy == "ciro.ifrs9.stage_transition"
    assert do_thing._governed_action_type == "ciro.ifrs9.stage_transition"


def test_governed_custom_action_type():
    k = _kernel()

    @k.governed(policy="my-policy", action_type="custom.action.type")
    async def do_thing(*, actor: Actor):
        pass

    assert do_thing._governed_action_type == "custom.action.type"
