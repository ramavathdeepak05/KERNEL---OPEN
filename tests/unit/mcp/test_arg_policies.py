"""MCP tool calls are governable by their ARGUMENTS via CEL (payload_<field>), and the per-tool
`policy` knob selects the action type. Uses a real PolicyEngine (not FakePolicy)."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.policy import PolicyEngine, PolicyEnvelope, PolicyStore  # noqa: E402
from quaicu.core.policy.model import PolicyLifecycle  # noqa: E402
from quaicu.core.types import Actor, ActorId, Decision, TenantId  # noqa: E402
from quaicu.delivery.mcp.server import GovernedMCPServer  # noqa: E402
from quaicu.delivery.sdk.kernel import Kernel  # noqa: E402
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger  # noqa: E402

_TENANT = "acme"
AGENT = Actor(id=ActorId("agent:research"), tenant=TenantId(_TENANT), roles=())


def _policy(pid: str, governs: str, condition: str, decision: Decision) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=pid, version=1, governs=governs, scope={"tenant": "*"}, condition=condition,
        decision=decision, approvers=(), regulatory_refs=(), lifecycle=PolicyLifecycle.ACTIVATED,
    )


def _kernel(*envelopes: PolicyEnvelope) -> Kernel:
    store = PolicyStore()
    for env in envelopes:
        store.register(env)
    return Kernel.from_parts(
        tenant=_TENANT, policy=PolicyEngine(store), hitl=InProcessHITLPort(),
        ledger=FakeLedger(), events=FakeEvents(),
    )


async def test_policy_conditions_on_a_tool_argument():
    # A CEL policy conditioned on the tool's `amount` argument: allow by default, deny high value.
    kernel = _kernel(
        _policy("mcp.wire.allow", "mcp.wire_transfer", "true", Decision.ALLOW),
        _policy("mcp.wire.deny_high", "mcp.wire_transfer", "payload_amount > 10000", Decision.DENY),
    )
    server = GovernedMCPServer(kernel, actor=AGENT)
    server.register_tool("wire_transfer", handler=lambda a: {"ok": a})

    high = await server.handle_call("wire_transfer", {"amount": 15000})
    assert high.isError is True  # payload_amount > 10000 → deny-overrides

    low = await server.handle_call("wire_transfer", {"amount": 5000})
    assert low.isError is False and low.structuredContent == {"ok": {"amount": 5000}}


async def test_policy_knob_selects_the_action_type():
    # A tool registered with policy="mcp.tool" is governed as THAT action type — so a policy
    # governing "mcp.tool" applies even though none governs "mcp.search". (If the knob were still
    # dead, the action type would be "mcp.search" → no policy → fail-closed DENY, not ALLOW.)
    kernel = _kernel(_policy("mcp.catchall", "mcp.tool", "true", Decision.ALLOW))
    server = GovernedMCPServer(kernel, actor=AGENT)
    server.register_tool("search", handler=lambda a: {"hits": 1}, policy="mcp.tool")

    res = await server.handle_call("search", {"q": "x"})
    assert res.isError is False and res.structuredContent == {"hits": 1}
