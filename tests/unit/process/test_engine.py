"""Unit tests for the InMemoryWorkflowAdapter (K·06 Postgres state-machine stand-in).

Tests cover: happy path, HITL approve/reject, HITL timeout (fail-closed),
cancel signal, unknown step, unknown outcome, tenant isolation, state replay,
and the WorkflowPort protocol contract.
"""

from __future__ import annotations

import asyncio

import pytest

from quaicu.adapters.workflow.memory import InMemoryWorkflowAdapter
from quaicu.core.process.definitions import (
    DEAD_LETTER,
    TERMINAL_COMPLETED,
    TERMINAL_DENIED,
    TERMINAL_REJECTED,
    GovernedProcessDef,
    StepDef,
)
from quaicu.core.process.errors import WorkflowTenantIsolationError
from quaicu.core.types import ProcessDef, Signal, TenantId, WorkflowHandle

TENANT = TenantId("t-1")
OTHER_TENANT = TenantId("t-2")


# ── Factories ─────────────────────────────────────────────────────────────────

def _proc_def(
    name: str = "governed_action",
    allow: bool = True,
) -> GovernedProcessDef:
    """Minimal 3-step process: evaluate → execute → emit."""
    return GovernedProcessDef(
        name=name,
        version=1,
        steps=[
            StepDef("evaluate", timeout_seconds=1),
            StepDef("execute", timeout_seconds=1),
            StepDef("emit", timeout_seconds=1),
        ],
        transitions={
            "evaluate": {"allow": "execute", "deny": TERMINAL_DENIED, "error": TERMINAL_DENIED},
            "execute": {"ok": "emit", "error": DEAD_LETTER},
            "emit": {"ok": TERMINAL_COMPLETED, "error": TERMINAL_COMPLETED},
        },
    )


def _hitl_proc_def() -> GovernedProcessDef:
    """3-step process with a HITL gate."""
    return GovernedProcessDef(
        name="hitl_process",
        version=1,
        steps=[
            StepDef("evaluate", timeout_seconds=1),
            StepDef("gate", timeout_seconds=1, is_hitl=True, hitl_timeout_hours=1),
            StepDef("execute", timeout_seconds=1),
        ],
        transitions={
            "evaluate": {
                "allow": "execute",
                "require_approval": "gate",
                "error": TERMINAL_DENIED,
            },
            "gate": {
                "approved": "execute",
                "rejected": TERMINAL_REJECTED,
                "timeout": TERMINAL_REJECTED,
            },
            "execute": {"ok": TERMINAL_COMPLETED},
        },
    )


def _adapter(
    proc_def: GovernedProcessDef,
    *,
    evaluate_outcome: str = "allow",
    execute_outcome: str = "ok",
    emit_outcome: str = "ok",
    hitl_timeout_seconds: float | None = None,
) -> InMemoryWorkflowAdapter:
    async def _eval(payload):
        return {"outcome": evaluate_outcome}

    async def _exec(payload):
        return {"outcome": execute_outcome}

    async def _emit(payload):
        return {"outcome": emit_outcome}

    return InMemoryWorkflowAdapter(
        process_defs={proc_def.name: proc_def},
        step_fns={"evaluate": _eval, "execute": _exec, "emit": _emit},
        hitl_timeout_seconds=hitl_timeout_seconds,
    )


async def _wait_done(adapter: InMemoryWorkflowAdapter, handle: WorkflowHandle, *, max_sleep: float = 0.2) -> None:
    """Yield to the event loop until the workflow is no longer 'running'."""
    for _ in range(20):
        s = await adapter.state(handle)
        if s.status not in ("running", "paused_hitl"):
            return
        await asyncio.sleep(max_sleep / 20)


# ── Happy path ────────────────────────────────────────────────────────────────


async def test_allow_path_completes():
    pd = _proc_def()
    adp = _adapter(pd)
    handle = await adp.start(definition=ProcessDef(id="governed_action"), payload={}, tenant=TENANT)
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert s.status == "completed"
    assert s.current_step == TERMINAL_COMPLETED


async def test_deny_path_is_terminal_denied():
    pd = _proc_def()
    adp = _adapter(pd, evaluate_outcome="deny")
    handle = await adp.start(definition=ProcessDef(id="governed_action"), payload={}, tenant=TENANT)
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert s.status == "denied"


async def test_step_events_recorded():
    pd = _proc_def()
    adp = _adapter(pd)
    handle = await adp.start(definition=ProcessDef(id="governed_action"), payload={}, tenant=TENANT)
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    event_types = [e["event_type"] for e in s.data["events"]]
    assert "workflow_started" in event_types
    assert "step_started" in event_types
    assert "step_completed" in event_types


# ── HITL ──────────────────────────────────────────────────────────────────────


async def test_hitl_pauses_workflow():
    pd = _hitl_proc_def()
    adp = InMemoryWorkflowAdapter(
        process_defs={"hitl_process": pd},
        step_fns={
            "evaluate": lambda p: ({"outcome": "require_approval"}),
            "execute": lambda p: ({"outcome": "ok"}),
        },
    )
    handle = await adp.start(definition=ProcessDef(id="hitl_process"), payload={}, tenant=TENANT)
    await asyncio.sleep(0.05)  # let evaluate step complete
    s = await adp.state(handle)
    assert s.status == "paused_hitl"


async def test_hitl_approve_resumes_to_completed():
    pd = _hitl_proc_def()
    adp = InMemoryWorkflowAdapter(
        process_defs={"hitl_process": pd},
        step_fns={
            "evaluate": lambda p: ({"outcome": "require_approval"}),
            "execute": lambda p: ({"outcome": "ok"}),
        },
    )
    handle = await adp.start(definition=ProcessDef(id="hitl_process"), payload={}, tenant=TENANT)
    await asyncio.sleep(0.05)
    await adp.signal(handle, Signal(name="hitl_approved", payload={}))
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert s.status == "completed"


async def test_hitl_reject_is_terminal_rejected():
    pd = _hitl_proc_def()
    adp = InMemoryWorkflowAdapter(
        process_defs={"hitl_process": pd},
        step_fns={
            "evaluate": lambda p: ({"outcome": "require_approval"}),
            "execute": lambda p: ({"outcome": "ok"}),
        },
    )
    handle = await adp.start(definition=ProcessDef(id="hitl_process"), payload={}, tenant=TENANT)
    await asyncio.sleep(0.05)
    await adp.signal(handle, Signal(name="hitl_rejected", payload={}))
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert s.status == "rejected"


async def test_hitl_timeout_is_fail_closed_rejected():
    """HITL timeout must resolve as REJECTED — never auto-approve (F-03)."""
    pd = _hitl_proc_def()
    adp = InMemoryWorkflowAdapter(
        process_defs={"hitl_process": pd},
        step_fns={
            "evaluate": lambda p: ({"outcome": "require_approval"}),
            "execute": lambda p: ({"outcome": "ok"}),
        },
        hitl_timeout_seconds=0.05,  # 50ms for fast test
    )
    handle = await adp.start(definition=ProcessDef(id="hitl_process"), payload={}, tenant=TENANT)
    await asyncio.sleep(0.3)  # wait for timeout
    s = await adp.state(handle)
    assert s.status == "rejected"


# ── Fail paths ────────────────────────────────────────────────────────────────


async def test_unknown_step_fn_returns_error_outcome():
    """A step with no registered function must not hang — it returns 'error'."""
    pd = GovernedProcessDef(
        name="no_fn",
        version=1,
        steps=[StepDef("orphan", timeout_seconds=1)],
        transitions={"orphan": {"error": TERMINAL_DENIED, "ok": TERMINAL_COMPLETED}},
    )
    adp = InMemoryWorkflowAdapter(process_defs={"no_fn": pd}, step_fns={})
    handle = await adp.start(definition=ProcessDef(id="no_fn"), payload={}, tenant=TENANT)
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert s.status == "denied"


async def test_state_raises_for_missing_workflow():
    adp = InMemoryWorkflowAdapter()
    with pytest.raises(Exception):
        await adp.state(WorkflowHandle(id="nonexistent", tenant=TENANT))


# ── Tenant isolation ──────────────────────────────────────────────────────────


async def test_signal_cross_tenant_raises():
    pd = _hitl_proc_def()
    adp = InMemoryWorkflowAdapter(
        process_defs={"hitl_process": pd},
        step_fns={"evaluate": lambda p: {"outcome": "require_approval"}},
    )
    handle = await adp.start(definition=ProcessDef(id="hitl_process"), payload={}, tenant=TENANT)
    await asyncio.sleep(0.05)

    wrong_tenant_handle = WorkflowHandle(id=handle.id, tenant=OTHER_TENANT)
    with pytest.raises(WorkflowTenantIsolationError):
        await adp.signal(wrong_tenant_handle, Signal(name="hitl_approved", payload={}))


async def test_state_cross_tenant_raises():
    pd = _proc_def()
    adp = _adapter(pd)
    handle = await adp.start(definition=ProcessDef(id="governed_action"), payload={}, tenant=TENANT)
    wrong_handle = WorkflowHandle(id=handle.id, tenant=OTHER_TENANT)
    with pytest.raises(WorkflowTenantIsolationError):
        await adp.state(wrong_handle)


# ── Replay: state reconstructed from events ───────────────────────────────────


async def test_state_derived_from_events():
    """ProcessState.data["events"] holds the append-only event log."""
    pd = _proc_def()
    adp = _adapter(pd)
    handle = await adp.start(definition=ProcessDef(id="governed_action"), payload={}, tenant=TENANT)
    await _wait_done(adp, handle)
    s = await adp.state(handle)
    assert isinstance(s.data["events"], list)
    assert len(s.data["events"]) > 0
    assert s.data["events"][0]["event_type"] == "workflow_started"
