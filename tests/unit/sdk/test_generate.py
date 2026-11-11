"""Governed inference via kernel.generate — composable enforcement around a model call."""

from __future__ import annotations

import pytest

from quaicu.delivery.sdk import SdkUsageError

from quaicu.core.errors import LifecycleDeniedError, LifecycleHaltedError
from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.engine import AIGateway
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.types import Actor, ActorId, Decision, ModelRef, ModelResponse, Prompt, TenantId
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger, FakePolicy

TENANT = TenantId("acme")
MODEL = ModelRef(id="gpt-4", version="0613")
ACTOR = Actor(id=ActorId("user-1"), tenant=TENANT)


class _FakeInference:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def generate(self, *, prompt: Prompt, model_ref: ModelRef, tenant: TenantId) -> ModelResponse:
        self.calls.append({"prompt": prompt, "model_ref": model_ref})
        return ModelResponse(content="ok", model_id=model_ref.id, recorded_output={})


def _kernel(*, decision=Decision.ALLOW, permit=True, with_gateway=True, default_profile=None):
    fake = _FakeInference()
    gateway = None
    if with_gateway:
        allowlist = InMemoryModelAllowlist()
        if permit:
            allowlist.permit(TENANT, MODEL.id)
        gateway = AIGateway(inference=fake, allowlist=allowlist)
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        gateway=gateway,
        default_profile=default_profile,
    )
    return kernel, fake


async def test_generate_returns_model_response() -> None:
    kernel, fake = _kernel()
    resp = await kernel.generate(prompt_text="hello", model_ref=MODEL, actor=ACTOR)
    assert isinstance(resp, ModelResponse)
    assert resp.content == "ok"
    assert len(fake.calls) == 1
    assert resp.recorded_output["action_id"]  # surfaced for correlation


async def test_generate_seals_to_ledger_under_all_profile() -> None:
    kernel, _ = _kernel()
    kernel.engine._ledger  # type: ignore[attr-defined]
    await kernel.generate(prompt_text="hi", model_ref=MODEL, actor=ACTOR)
    assert len(kernel.engine._ledger.sealed) == 1  # type: ignore[attr-defined]


async def test_generate_denied_by_policy_raises() -> None:
    kernel, fake = _kernel(decision=Decision.DENY)
    with pytest.raises(LifecycleDeniedError):
        await kernel.generate(prompt_text="hi", model_ref=MODEL, actor=ACTOR)
    assert len(fake.calls) == 0  # never reached the model


async def test_unlisted_model_halts_under_all_profile() -> None:
    kernel, fake = _kernel(permit=False)
    with pytest.raises(LifecycleHaltedError):
        await kernel.generate(prompt_text="hi", model_ref=MODEL, actor=ACTOR)
    assert len(fake.calls) == 0


async def test_gateway_only_profile_skips_policy_and_seal() -> None:
    # DENY policy would block under all(), but gateway_only skips policy + seal entirely.
    kernel, fake = _kernel(decision=Decision.DENY, default_profile=GovernanceProfile.gateway_only())
    resp = await kernel.generate(prompt_text="hi", model_ref=MODEL, actor=ACTOR)
    assert resp.content == "ok"
    assert len(fake.calls) == 1
    assert len(kernel.engine._ledger.sealed) == 0  # type: ignore[attr-defined]


async def test_generate_without_gateway_raises() -> None:
    kernel, _ = _kernel(with_gateway=False)
    with pytest.raises(SdkUsageError):
        await kernel.generate(prompt_text="hi", model_ref=MODEL, actor=ACTOR)
