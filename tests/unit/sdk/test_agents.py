"""Governed tools + per-agent identity (multi-agent attribution)."""

from __future__ import annotations

import pytest

from quaicu.delivery.sdk import SdkUsageError

from quaicu.core.errors import LifecycleDeniedError
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


async def test_governed_tool_returns_tool_result() -> None:
    kernel, _ = _kernel()
    agent = kernel.for_agent("agent:researcher")

    @agent.tool(policy="tools.web_search")
    async def web_search(query: str) -> str:
        return f"results-for:{query}"

    out = await web_search(query="merkle trees")
    assert out == "results-for:merkle trees"  # the tool's own value, not an Action


async def test_governed_tool_supports_sync_functions() -> None:
    kernel, _ = _kernel()
    agent = kernel.for_agent("agent:researcher")

    @agent.tool(policy="tools.add")
    def add(a: int, b: int) -> int:
        return a + b

    assert await add(a=2, b=3) == 5


async def test_governed_tool_denied_raises() -> None:
    kernel, _ = _kernel(decision=Decision.DENY)
    agent = kernel.for_agent("agent:researcher")

    @agent.tool(policy="tools.danger")
    async def danger() -> str:
        return "did it"

    with pytest.raises(LifecycleDeniedError):
        await danger()


async def test_each_agent_is_attributed_individually() -> None:
    kernel, ledger = _kernel()
    researcher = kernel.for_agent("agent:researcher")
    writer = kernel.for_agent("agent:writer")

    @researcher.tool(policy="tools.search")
    async def search(q: str) -> str:
        return "ok"

    @writer.tool(policy="tools.publish")
    async def publish(doc: str) -> str:
        return "ok"

    await search(q="x")
    await publish(doc="y")

    actor_ids = {e.actor_id for e in ledger.sealed}
    assert actor_ids == {ActorId("agent:researcher"), ActorId("agent:writer")}


async def test_governed_tool_requires_an_actor() -> None:
    kernel, _ = _kernel()

    @kernel.governed_tool(policy="tools.search")
    async def search(q: str) -> str:
        return "ok"

    with pytest.raises(SdkUsageError):
        await search(q="x")  # no bound actor and no actor= kwarg
