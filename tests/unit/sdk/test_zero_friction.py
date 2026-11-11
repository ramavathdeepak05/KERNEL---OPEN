"""Zero-friction integration tests — guard / wrap / actor_context / proxy.

These tests prove that existing function signatures and call-sites require zero changes. The only
additions are the decorator/wrap line and an actor_context at the request boundary.
"""

from __future__ import annotations

import pytest

from quaicu.core.errors import LifecycleDeniedError
from quaicu.delivery.sdk import SdkUsageError
from quaicu.core.lifecycle.context import get_current_actor
from quaicu.core.types import Actor, ActorId, Decision, TenantId
from quaicu.delivery.sdk import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger, FakePolicy

TENANT = TenantId("acme")
ACTOR = Actor(id=ActorId("alice"), tenant=TENANT)


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


# ── actor_context ─────────────────────────────────────────────────────────────


async def test_actor_context_binds_and_restores() -> None:
    kernel, _ = _kernel()
    assert get_current_actor() is None

    async with kernel.actor_context(ACTOR):
        assert get_current_actor() == ACTOR

    assert get_current_actor() is None  # restored after block


async def test_actor_context_string_shorthand() -> None:
    kernel, _ = _kernel()
    async with kernel.actor_context("agent:planner"):
        actor = get_current_actor()
        assert actor is not None
        assert str(actor.id) == "agent:planner"
        assert actor.tenant == TENANT


async def test_actor_context_nested_innermost_wins() -> None:
    kernel, _ = _kernel()
    outer = Actor(id=ActorId("outer"), tenant=TENANT)
    inner = Actor(id=ActorId("inner"), tenant=TENANT)

    async with kernel.actor_context(outer):
        assert get_current_actor() == outer
        async with kernel.actor_context(inner):
            assert get_current_actor() == inner
        assert get_current_actor() == outer  # restored


# ── @kernel.guard — zero signature change ─────────────────────────────────────


async def test_guard_async_function_unchanged_signature() -> None:
    kernel, _ = _kernel()

    # EXISTING FUNCTION — signature unchanged: no actor= required
    @kernel.guard(policy="documents.analyze")
    async def analyze_document(doc: str) -> str:
        return f"analyzed:{doc}"

    async with kernel.actor_context(ACTOR):
        result = await analyze_document("my_doc")  # call-site unchanged

    assert result == "analyzed:my_doc"


async def test_guard_sync_function_unchanged_signature() -> None:
    kernel, _ = _kernel()

    @kernel.guard(policy="math.add")
    def add(a: int, b: int) -> int:
        return a + b

    async with kernel.actor_context(ACTOR):
        result = await add(2, 3)

    assert result == 5


async def test_guard_deny_raises_lifecycle_denied() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)

    @kernel.guard(policy="payments.transfer")
    async def transfer(amount: float) -> bool:
        return True

    with pytest.raises(LifecycleDeniedError):
        async with kernel.actor_context(ACTOR):
            await transfer(100.0)


async def test_guard_no_actor_raises_runtime_error() -> None:
    kernel, _ = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve(loan_id: str) -> dict:
        return {"approved": True}

    with pytest.raises(SdkUsageError, match="no actor in scope"):
        await approve("L-1")  # no actor_context → clear error


async def test_guard_actor_kwarg_override_works() -> None:
    """Caller can pass actor= as an escape hatch without changing the decorated function."""
    kernel, ledger = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve(loan_id: str) -> dict:
        return {"approved": True}

    override_actor = Actor(id=ActorId("override"), tenant=TENANT)
    result = await approve("L-1", actor=override_actor)

    assert result == {"approved": True}
    assert ledger.sealed[0].actor_id == ActorId("override")


async def test_guard_seals_to_ledger_by_default() -> None:
    kernel, ledger = _kernel()

    @kernel.guard(policy="records.write")
    async def write_record(data: str) -> None:
        pass

    async with kernel.actor_context(ACTOR):
        await write_record("important data")

    assert len(ledger.sealed) == 1


async def test_guard_actor_id_in_ledger_from_context() -> None:
    kernel, ledger = _kernel()

    @kernel.guard(policy="data.export")
    async def export() -> list:
        return ["row1", "row2"]

    async with kernel.actor_context(ACTOR):
        result = await export()

    assert result == ["row1", "row2"]
    assert ledger.sealed[0].actor_id == ActorId("alice")


# ── kernel.wrap — programmatic wrapper ───────────────────────────────────────


async def test_wrap_governs_existing_callable() -> None:
    kernel, _ = _kernel()

    # Simulating an external function that the developer doesn't own
    async def external_api_call(endpoint: str, payload: dict) -> dict:
        return {"status": "ok", "endpoint": endpoint}

    governed = kernel.wrap(external_api_call, policy="external.api")

    async with kernel.actor_context(ACTOR):
        result = await governed("/v1/data", {"key": "value"})

    assert result["status"] == "ok"


async def test_wrap_bound_actor_priority() -> None:
    kernel, ledger = _kernel()
    bound_actor = Actor(id=ActorId("bound-agent"), tenant=TENANT)

    async def do_work() -> str:
        return "done"

    governed = kernel.wrap(do_work, policy="work.do", actor=bound_actor)

    # No actor_context needed when actor is bound at wrap-time
    result = await governed()
    assert result == "done"
    assert ledger.sealed[0].actor_id == ActorId("bound-agent")


async def test_wrap_deny_raises() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)

    def risky_operation() -> str:
        return "did it"

    governed = kernel.wrap(risky_operation, policy="risky.op")

    with pytest.raises(LifecycleDeniedError):
        async with kernel.actor_context(ACTOR):
            await governed()


async def test_wrap_sync_function() -> None:
    kernel, _ = _kernel()

    def calculate(x: int, y: int) -> int:
        return x * y

    governed = kernel.wrap(calculate, policy="math.multiply")

    async with kernel.actor_context(ACTOR):
        result = await governed(6, 7)

    assert result == 42


# ── kernel.proxy — transparent object proxy ──────────────────────────────────


class _FakeClient:
    """Simulates an external client (e.g. OpenAI, Anthropic, database)."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def generate(self, prompt: str, model: str = "gpt-4") -> dict:
        self.calls.append({"prompt": prompt, "model": model})
        return {"content": f"response:{prompt}", "model": model}

    async def embed(self, text: str) -> list:
        return [0.1, 0.2, 0.3]

    async def admin_action(self) -> str:
        return "admin"


async def test_proxy_governed_method_allowed_delegates() -> None:
    kernel, _ = _kernel()
    raw_client = _FakeClient()

    client = kernel.proxy(
        raw_client,
        policies={"generate": "ai.generate", "embed": "ai.embed"},
    )

    async with kernel.actor_context(ACTOR):
        result = await client.generate(prompt="hello world")

    assert result["content"] == "response:hello world"
    assert len(raw_client.calls) == 1


async def test_proxy_governed_method_denied_raises() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)
    raw_client = _FakeClient()

    client = kernel.proxy(raw_client, policies={"generate": "ai.generate"})

    with pytest.raises(LifecycleDeniedError):
        async with kernel.actor_context(ACTOR):
            await client.generate(prompt="disallowed")

    assert len(raw_client.calls) == 0  # never reached the real method


async def test_proxy_ungoverned_method_passes_through() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)  # would block governed calls
    raw_client = _FakeClient()

    client = kernel.proxy(raw_client, policies={"generate": "ai.generate"})

    # admin_action is NOT in policies → passes through even with DENY policy
    result = await client.admin_action()
    assert result == "admin"


async def test_proxy_no_actor_raises_on_governed_method() -> None:
    kernel, _ = _kernel()
    raw_client = _FakeClient()

    client = kernel.proxy(raw_client, policies={"generate": "ai.generate"})

    with pytest.raises(SdkUsageError, match="no actor in scope"):
        await client.generate(prompt="test")


async def test_proxy_transparent_to_unrelated_attributes() -> None:
    """Attribute access for non-governed paths is completely transparent."""
    kernel, _ = _kernel()
    raw_client = _FakeClient()

    client = kernel.proxy(raw_client, policies={"generate": "ai.generate"})

    # Accessing .calls (a data attribute) passes through unchanged
    assert client.calls == raw_client.calls


# ── set_actor / get_actor imperative API ─────────────────────────────────────


async def test_set_get_actor_imperative() -> None:
    kernel, _ = _kernel()
    kernel.set_actor(ACTOR)
    assert kernel.get_actor() == ACTOR
    kernel.set_actor(None)
    assert kernel.get_actor() is None
