"""MCP tool-call governance core (D2-1) — no MCP SDK needed."""

from __future__ import annotations

from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import Actor, ActorId, ApproverRef, Decision, TenantId
from quaicu.delivery.mcp.governance import ToolStatus, govern_tool_call
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy

AGENT = Actor(id=ActorId("agent:researcher"), tenant=TenantId("acme"), roles=())


def _kernel(policy) -> Kernel:
    return Kernel.from_parts(
        tenant="acme",
        policy=policy,
        hitl=InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )


async def _govern(kernel: Kernel, ran: list, arguments=None):
    async def execute(args: dict):
        ran.append(args)
        return {"echo": args}

    return await govern_tool_call(
        kernel,
        actor=AGENT,
        tool_name="search",
        arguments=arguments if arguments is not None else {"q": "x"},
        policy="tools.search",
        execute=execute,
    )


async def test_allow_executes_and_returns_result() -> None:
    ran: list = []
    ledger = FakeLedger()
    kernel = Kernel.from_parts(
        tenant="acme", policy=FakePolicy(decision=Decision.ALLOW),
        hitl=InProcessHITLPort(), ledger=ledger, events=FakeEvents(),
    )
    out = await _govern(kernel, ran)
    assert out.status is ToolStatus.ALLOWED
    assert out.result == {"echo": {"q": "x"}}
    assert ran == [{"q": "x"}]  # the tool executed
    assert not out.blocked


async def test_deny_blocks_the_tool_call() -> None:
    ran: list = []
    out = await _govern(_kernel(FakePolicy(decision=Decision.DENY)), ran)
    assert out.status is ToolStatus.DENIED
    assert out.blocked
    assert ran == []  # the tool did NOT run (fail-closed)


async def test_require_approval_pends_without_running() -> None:
    ran: list = []
    out = await _govern(
        _kernel(
            FakePolicy(decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),))
        ),
        ran,
    )
    assert out.status is ToolStatus.PENDING
    assert out.handle_id  # a human can approve this handle via /v1/approvals
    assert out.blocked
    assert ran == []  # suspended durably before execution


async def test_tool_execution_failure_halts_fail_closed() -> None:
    kernel = _kernel(FakePolicy(decision=Decision.ALLOW))

    async def execute(args: dict):
        raise RuntimeError("tool boom")

    out = await govern_tool_call(
        kernel, actor=AGENT, tool_name="search", arguments={}, policy="p", execute=execute
    )
    assert out.status is ToolStatus.HALTED
    assert out.blocked
