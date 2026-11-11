"""GovernedMCPServer + GovernedMCPProxy → CallToolResult mapping (D2-1). Needs the mcp SDK."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.types import Actor, ActorId, ApproverRef, Decision, TenantId  # noqa: E402
from quaicu.delivery.mcp.proxy import GovernedMCPProxy  # noqa: E402
from quaicu.delivery.mcp.server import GovernedMCPServer  # noqa: E402
from quaicu.delivery.sdk.kernel import Kernel  # noqa: E402
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy  # noqa: E402

AGENT = Actor(id=ActorId("agent:research"), tenant=TenantId("acme"), roles=())


def _kernel(policy) -> Kernel:
    return Kernel.from_parts(
        tenant="acme", policy=policy, hitl=InProcessHITLPort(),
        ledger=FakeLedger(), events=FakeEvents(),
    )


def _approval_policy() -> FakePolicy:
    return FakePolicy(
        decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
    )


async def test_server_allow_returns_structured_result() -> None:
    server = GovernedMCPServer(_kernel(FakePolicy(decision=Decision.ALLOW)), actor=AGENT)
    server.register_tool("echo", handler=lambda a: {"echo": a}, policy="p")
    res = await server.handle_call("echo", {"x": 1})
    assert res.isError is False
    assert res.structuredContent == {"echo": {"x": 1}}


async def test_server_deny_blocks_and_does_not_run_handler() -> None:
    ran: list = []

    def handler(a):
        ran.append(a)
        return {}

    server = GovernedMCPServer(_kernel(FakePolicy(decision=Decision.DENY)), actor=AGENT)
    server.register_tool("t", handler=handler, policy="p")
    res = await server.handle_call("t", {"a": 1})
    assert res.isError is True
    assert ran == []
    assert "governance" in res.content[0].text.lower()


async def test_server_require_approval_surfaces_handle() -> None:
    server = GovernedMCPServer(_kernel(_approval_policy()), actor=AGENT)
    server.register_tool("t", handler=lambda a: {}, policy="p")
    res = await server.handle_call("t", {})
    assert res.isError is True
    assert res.meta and res.meta["quaicu_status"] == "PENDING"
    assert res.meta["handle_id"]


async def test_server_unknown_tool_is_error() -> None:
    server = GovernedMCPServer(_kernel(FakePolicy(decision=Decision.ALLOW)), actor=AGENT)
    res = await server.handle_call("nope", {})
    assert res.isError is True


async def test_build_mcp_server_constructs() -> None:
    server = GovernedMCPServer(_kernel(FakePolicy(decision=Decision.ALLOW)), actor=AGENT)
    server.register_tool("echo", handler=lambda a: {}, policy="p", description="Echo")
    assert server.build_mcp_server() is not None  # low-level mcp Server wires without error


class _FakeDownstream:
    def __init__(self) -> None:
        self.calls: list = []

    async def list_tools(self):
        return []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"downstream": arguments}


async def test_proxy_forwards_allowed_calls() -> None:
    ds = _FakeDownstream()
    proxy = GovernedMCPProxy(
        _kernel(FakePolicy(decision=Decision.ALLOW)), actor=AGENT, downstream=ds, default_policy="p"
    )
    res = await proxy.handle_call("search", {"q": "x"})
    assert res.isError is False
    assert ds.calls == [("search", {"q": "x"})]  # forwarded to downstream


async def test_proxy_blocks_denied_without_forwarding() -> None:
    ds = _FakeDownstream()
    proxy = GovernedMCPProxy(
        _kernel(FakePolicy(decision=Decision.DENY)), actor=AGENT, downstream=ds, default_policy="p"
    )
    res = await proxy.handle_call("search", {"q": "x"})
    assert res.isError is True
    assert ds.calls == []  # never reached the downstream (fail-closed)
