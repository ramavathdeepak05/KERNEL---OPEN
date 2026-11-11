"""Policies see every argument of a governed call — positional ones included — and a proxied
client call exposes its keyword arguments."""

from __future__ import annotations

from quaicu.core.types import Action, Actor, ActorId, Decision, EvaluationResult, TenantId
from quaicu.delivery.sdk import Kernel
from quaicu.delivery.sdk.kernel import call_payload
from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger

TENANT = TenantId("acme")
ACTOR = Actor(id=ActorId("alice"), tenant=TENANT)


class _RecordingPolicy:
    def __init__(self) -> None:
        self.seen: list[Action] = []

    async def evaluate(self, action: Action) -> EvaluationResult:
        self.seen.append(action)
        return EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",))


def _kernel() -> tuple[Kernel, _RecordingPolicy]:
    policy = _RecordingPolicy()
    kernel = Kernel.from_parts(
        tenant=TENANT, policy=policy, hitl=FakeHITL(), ledger=FakeLedger(), events=FakeEvents()
    )
    return kernel, policy


def test_call_payload_binds_positional_arguments():
    def send_wire(amount: int, to: str, *, memo: str = "") -> None: ...

    assert call_payload(send_wire, (500, "ACME"), {}) == {"amount": 500, "to": "ACME"}
    assert call_payload(send_wire, (500,), {"to": "ACME"}) == {"amount": 500, "to": "ACME"}
    assert call_payload(send_wire, (), {"amount": 1, "to": "B"}) == {"amount": 1, "to": "B"}


def test_call_payload_handles_varargs_and_methods():
    def many(*items: str, **extra: int) -> None: ...

    assert call_payload(many, ("a", "b"), {"n": 1}) == {"items": ["a", "b"], "n": 1}

    class Svc:
        def run(self, job: str) -> None: ...

    svc = Svc()
    assert call_payload(Svc.run, (svc, "j1"), {}) == {"job": "j1"}


def test_call_payload_falls_back_when_unbindable():
    def one(x: int) -> None: ...

    assert call_payload(one, (1, 2, 3), {}) == {"args": [1, 2, 3]}


async def test_guard_payload_includes_positional_arguments():
    kernel, policy = _kernel()

    @kernel.guard(policy="payments.wire")
    async def send_wire(amount: int, to: str) -> str:
        return f"{amount}->{to}"

    async with kernel.actor_context(ACTOR):
        assert await send_wire(500, "ACME") == "500->ACME"
    assert dict(policy.seen[-1].payload) == {"amount": 500, "to": "ACME"}


async def test_wrap_and_governed_tool_payloads_include_positional_arguments():
    kernel, policy = _kernel()

    def transfer(amount: int, to: str) -> str:
        return "ok"

    governed = kernel.wrap(transfer, policy="payments.transfer", actor=ACTOR)
    await governed(10, "B")
    assert dict(policy.seen[-1].payload) == {"amount": 10, "to": "B"}

    @kernel.governed_tool(policy="tools.lookup", actor=ACTOR)
    async def lookup(query: str) -> str:
        return query

    await lookup("q1")
    assert dict(policy.seen[-1].payload) == {"query": "q1"}


async def test_proxy_payload_exposes_call_arguments():
    kernel, policy = _kernel()

    class _Client:
        async def create(self, *args, **kwargs):
            return "done"

    client = kernel.proxy(_Client(), policies={"create": "ai.chat"}, actor=ACTOR)
    await client.create("pos", model="m1", messages=[{"role": "user", "content": "hi"}])
    payload = dict(policy.seen[-1].payload)
    assert payload["model"] == "m1"
    assert payload["messages"] == [{"role": "user", "content": "hi"}]
    assert payload["args"] == ["pos"]
    assert payload["method"] == "create" and payload["args_count"] == 1
