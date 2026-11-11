"""Multi-tenant GovernedMCPProxy: each call is governed by the RESOLVED tenant's kernel, forwarded to
THAT tenant's downstream, and sealed to its ledger — transport-free, via a stub session_resolver."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.types import Actor, ActorId, Decision, TenantId  # noqa: E402
from quaicu.delivery.mcp.proxy import GovernedMCPProxy, ProxySession  # noqa: E402
from quaicu.delivery.sdk.kernel import Kernel  # noqa: E402
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy  # noqa: E402


class _FakeDownstream:
    def __init__(self) -> None:
        self.calls: list = []

    async def list_tools(self):
        return []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"downstream": arguments}


def _session(tenant: str, decision: Decision):
    ledger = FakeLedger()
    kernel = Kernel.from_parts(
        tenant=tenant, policy=FakePolicy(decision=decision), hitl=InProcessHITLPort(),
        ledger=ledger, events=FakeEvents(),
    )
    actor = Actor(id=ActorId(f"user:{tenant}"), tenant=TenantId(tenant))
    downstream = _FakeDownstream()
    return ProxySession(kernel, actor, downstream), ledger, downstream


async def test_allowed_call_forwards_to_resolved_downstream_and_seals():
    sess_a, ledger_a, ds_a = _session("acme", Decision.ALLOW)
    sess_b, ledger_b, ds_b = _session("globex", Decision.DENY)
    current = {"s": sess_a}

    proxy = GovernedMCPProxy(name="hosted", default_policy="mcp.tool")
    proxy.bind_session_resolver(lambda: current["s"])

    # Tenant A (ALLOW): forwarded to A's downstream + sealed to A's ledger.
    res_a = await proxy.handle_call("search", {"q": "x"})
    assert res_a.isError is False
    assert ds_a.calls == [("search", {"q": "x"})]
    assert len(ledger_a.sealed) == 1
    assert ds_b.calls == [] and len(ledger_b.sealed) == 0  # B untouched

    # Tenant B (DENY): blocked — never forwarded to B's downstream; A still untouched.
    current["s"] = sess_b
    res_b = await proxy.handle_call("search", {"q": "y"})
    assert res_b.isError is True
    assert ds_b.calls == []
    assert ds_a.calls == [("search", {"q": "x"})]  # isolation: A saw only its own call


async def test_unbound_proxy_raises():
    proxy = GovernedMCPProxy(name="hosted")
    with pytest.raises(RuntimeError):
        await proxy.handle_call("t", {})
