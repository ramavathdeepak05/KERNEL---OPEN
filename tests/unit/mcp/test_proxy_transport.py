"""The proxy over a real MCP client/server pair (in memory): a downstream tool with an outputSchema
returns its structured result to the agent, and a downstream error stays an error."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

import mcp.types as types  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.types import Actor, ActorId, Decision, TenantId  # noqa: E402
from quaicu.delivery.mcp.proxy import GovernedMCPProxy  # noqa: E402
from quaicu.delivery.sdk.kernel import Kernel  # noqa: E402
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy  # noqa: E402

_SCHEMA = {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]}


class _Downstream:
    def __init__(self) -> None:
        self.calls: list = []

    async def list_tools(self):
        return [
            types.Tool(name="send", inputSchema={"type": "object"}, outputSchema=_SCHEMA),
            types.Tool(name="broken", inputSchema={"type": "object"}),
        ]

    async def call_tool(self, name, arguments):
        self.calls.append(name)
        if name == "broken":
            return types.CallToolResult(content=[types.TextContent(type="text", text="disk full")], isError=True)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="sent")], structuredContent={"result": "sent"}
        )


async def test_structured_output_and_errors_pass_through():
    kernel = Kernel.from_parts(
        tenant="acme", policy=FakePolicy(decision=Decision.ALLOW), hitl=InProcessHITLPort(),
        ledger=FakeLedger(), events=FakeEvents(),
    )
    downstream = _Downstream()
    agent = Actor(id=ActorId("agent:a"), tenant=TenantId("acme"))
    server = GovernedMCPProxy(kernel, actor=agent, downstream=downstream).build_mcp_server()

    async with create_connected_server_and_client_session(server) as client:
        await client.list_tools()
        ok = await client.call_tool("send", {})
        assert ok.isError is False
        assert ok.structuredContent == {"result": "sent"}

        bad = await client.call_tool("broken", {})
        assert bad.isError is True
        assert "disk full" in bad.content[0].text
    assert downstream.calls == ["send", "broken"]
