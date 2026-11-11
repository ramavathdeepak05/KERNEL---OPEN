"""AWS Step Functions WorkflowPort adapter (W6-7): ASL translation + start/signal/state (fake SFN client)."""

from __future__ import annotations

import json

from quaicu.adapters.workflow.aws_sfn import (
    StepFunctionsWorkflowAdapter,
    governed_def_to_asl,
)
from quaicu.core.process.definitions import (
    GOVERNED_ACTION_PROCESS,
    TERMINAL_COMPLETED,
    TERMINAL_DENIED,
    TERMINAL_REJECTED,
)
from quaicu.core.types import ProcessDef, Signal, TenantId

_PREFIX = "arn:aws:states:us-east-1:123456789012:activity:quaicu"


# ── ASL translation (pure) ─────────────────────────────────────────────────────


def test_asl_translation_structure():
    asl = governed_def_to_asl(GOVERNED_ACTION_PROCESS, activity_arn_prefix=_PREFIX)
    assert asl["StartAt"] == GOVERNED_ACTION_PROCESS.steps[0].name
    states = asl["States"]
    # Every step has a Task + a Choice route.
    for step in GOVERNED_ACTION_PROCESS.steps:
        assert states[step.name]["Type"] == "Task"
        assert states[f"{step.name}__route"]["Type"] == "Choice"
    # The HITL gate is a long-timeout Task with a States.Timeout catch routing to the timeout outcome.
    gate = states["gate"]
    assert gate["TimeoutSeconds"] == 48 * 3600
    assert any("States.Timeout" in c["ErrorEquals"] for c in gate["Catch"])
    # Terminal sentinels: success → Succeed, deny/reject → Fail with the sentinel as Error.
    assert states[TERMINAL_COMPLETED]["Type"] == "Succeed"
    assert states[TERMINAL_DENIED]["Type"] == "Fail" and states[TERMINAL_DENIED]["Error"] == TERMINAL_DENIED


def test_asl_choice_routes_match_transitions():
    asl = governed_def_to_asl(GOVERNED_ACTION_PROCESS, activity_arn_prefix=_PREFIX)
    # evaluate's Choice must mirror the def's transitions (allow/deny/require_approval).
    routes = {c["StringEquals"]: c["Next"] for c in asl["States"]["evaluate__route"]["Choices"]}
    for outcome, dest in GOVERNED_ACTION_PROCESS.transitions["evaluate"].items():
        if outcome != "error":
            assert routes[outcome] == dest


# ── Adapter with an injected fake SFN client (no boto3 / AWS) ───────────────────


class _FakeSfn:
    def __init__(self, status="RUNNING", error=""):
        self.status = status
        self.error = error
        self.calls: list[tuple] = []

    def create_state_machine(self, name, definition, roleArn):  # noqa: N803 - boto3 kwargs
        self.calls.append(("create", name))
        json.loads(definition)  # must be valid ASL JSON
        return {"stateMachineArn": f"arn:sm:{name}"}

    def start_execution(self, stateMachineArn, name, input):  # noqa: N803, A002
        self.calls.append(("start", stateMachineArn, input))
        return {"executionArn": "arn:exec:1"}

    def describe_execution(self, executionArn):  # noqa: N803
        return {"status": self.status, "error": self.error}

    def send_task_success(self, taskToken, output):  # noqa: N803
        self.calls.append(("success", taskToken, output))

    def send_task_failure(self, taskToken, error, cause):  # noqa: N803
        self.calls.append(("failure", taskToken, error))


def _adapter(client):
    return StepFunctionsWorkflowAdapter(role_arn="arn:role", activity_arn_prefix=_PREFIX, client=client)


_DEF = ProcessDef(id=GOVERNED_ACTION_PROCESS.name)


async def test_start_creates_and_starts_execution():
    fake = _FakeSfn()
    handle = await _adapter(fake).start(definition=_DEF, payload={"x": 1}, tenant=TenantId("acme"))
    assert handle.id == "arn:exec:1" and str(handle.tenant) == "acme"
    kinds = [c[0] for c in fake.calls]
    assert "create" in kinds and "start" in kinds
    start_input = json.loads(next(c[2] for c in fake.calls if c[0] == "start"))
    assert start_input["_tenant"] == "acme" and start_input["x"] == 1


async def test_state_maps_sfn_status():
    from quaicu.core.types import WorkflowHandle

    h = WorkflowHandle(id="arn:exec:1", tenant=TenantId("acme"))
    assert (await _adapter(_FakeSfn(status="RUNNING")).state(h)).status == "running"
    assert (await _adapter(_FakeSfn(status="SUCCEEDED")).state(h)).status == TERMINAL_COMPLETED
    assert (await _adapter(_FakeSfn(status="FAILED", error=TERMINAL_DENIED)).state(h)).status == TERMINAL_DENIED
    assert (await _adapter(_FakeSfn(status="TIMED_OUT")).state(h)).status == TERMINAL_REJECTED


async def test_signal_success_and_failure():
    from quaicu.core.types import WorkflowHandle

    h = WorkflowHandle(id="arn:exec:1", tenant=TenantId("acme"))
    fake = _FakeSfn()
    await _adapter(fake).signal(h, Signal(name="approved", payload={"task_token": "tok-1"}))
    assert ("success", "tok-1", '{"outcome": "approved"}') in fake.calls

    fake2 = _FakeSfn()
    await _adapter(fake2).signal(h, Signal(name="rejected", payload={"task_token": "tok-2"}))
    assert any(c[0] == "failure" and c[1] == "tok-2" for c in fake2.calls)


async def test_signal_without_token_raises():
    from quaicu.core.errors import WorkflowPortError
    from quaicu.core.types import WorkflowHandle

    h = WorkflowHandle(id="arn:exec:1", tenant=TenantId("acme"))
    try:
        await _adapter(_FakeSfn()).signal(h, Signal(name="approved", payload={}))
        raise AssertionError("expected WorkflowPortError")
    except WorkflowPortError:
        pass


async def test_missing_boto3_raises_workflow_error(monkeypatch):
    import builtins

    from quaicu.core.errors import WorkflowPortError

    real_import = builtins.__import__

    def _fake_import(name, *a, **k):
        if name == "boto3":
            raise ImportError("no boto3")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    adapter = StepFunctionsWorkflowAdapter(role_arn="r", activity_arn_prefix=_PREFIX)  # no client → lazy import
    try:
        await adapter.start(definition=_DEF, payload={}, tenant=TenantId("acme"))
        raise AssertionError("expected WorkflowPortError")
    except WorkflowPortError:
        pass
