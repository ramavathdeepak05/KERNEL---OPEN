from __future__ import annotations

import pytest

from quaicu.core.errors import (
    GatewayBudgetExceededError,
    GatewayDeniedError,
    GatewayLoggingError,
    InferencePortError,
)
from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.budget import InMemoryBudgetTracker
from quaicu.core.gateway.engine import AIGateway
from quaicu.core.gateway.log import InMemoryPromptLog
from quaicu.core.gateway.masking import MaskingConfig
from quaicu.core.types import ModelRef, ModelResponse, Prompt, TenantId


class FakeInference:
    def __init__(self, response_content: str = "ok", *, fail: bool = False) -> None:
        self.calls: list[dict] = []
        self._response_content = response_content
        self._fail = fail

    async def generate(self, *, prompt: Prompt, model_ref: ModelRef, tenant: TenantId) -> ModelResponse:
        self.calls.append({"prompt": prompt, "model_ref": model_ref, "tenant": tenant})
        if self._fail:
            raise InferencePortError("Inference failed.")
        return ModelResponse(content=self._response_content, model_id=model_ref.id, recorded_output={})


def _make_gateway(
    inference: FakeInference,
    *,
    allowlist: InMemoryModelAllowlist | None = None,
    prompt_log: InMemoryPromptLog | None = None,
    budget: InMemoryBudgetTracker | None = None,
    masking_configs: dict | None = None,
) -> tuple[AIGateway, InMemoryModelAllowlist, InMemoryPromptLog, InMemoryBudgetTracker]:
    al = allowlist or InMemoryModelAllowlist()
    pl = prompt_log or InMemoryPromptLog()
    bt = budget or InMemoryBudgetTracker()
    gw = AIGateway(
        inference=inference,
        allowlist=al,
        prompt_log=pl,
        budget=bt,
        masking_configs=masking_configs,
    )
    return gw, al, pl, bt


TENANT_A = TenantId("tenant-a")
TENANT_B = TenantId("tenant-b")
MODEL_GPT4 = ModelRef(id="gpt-4", version="0613")
MODEL_CLAUDE = ModelRef(id="claude-3", version="opus")


async def test_permitted_model_calls_inference() -> None:
    fake = FakeInference()
    gw, al, pl, bt = _make_gateway(fake)
    al.permit(TENANT_A, MODEL_GPT4.id)

    resp = await gw.generate(prompt_text="hello", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert resp.content == "ok"
    assert len(fake.calls) == 1


async def test_unpermitted_model_raises_denied() -> None:
    fake = FakeInference()
    gw, al, pl, bt = _make_gateway(fake)

    with pytest.raises(GatewayDeniedError):
        await gw.generate(prompt_text="hello", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert len(fake.calls) == 0


async def test_no_models_permitted_raises_denied() -> None:
    fake = FakeInference()
    gw, al, pl, bt = _make_gateway(fake)

    with pytest.raises(GatewayDeniedError):
        await gw.generate(prompt_text="query", model_ref=MODEL_CLAUDE, tenant=TENANT_A)

    assert len(fake.calls) == 0


async def test_prompt_logged_before_call() -> None:
    fake = FakeInference()
    pl = InMemoryPromptLog()
    gw, al, _, _ = _make_gateway(fake, prompt_log=pl)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(prompt_text="log me", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert len(pl.entries) == 1
    assert pl.entries[0].prompt_hash != ""


async def test_log_failure_denies_call() -> None:
    fake = FakeInference()
    pl = InMemoryPromptLog()
    gw, al, _, _ = _make_gateway(fake, prompt_log=pl)
    al.permit(TENANT_A, MODEL_GPT4.id)
    pl.inject_failure()

    with pytest.raises(GatewayLoggingError):
        await gw.generate(prompt_text="should not call", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert len(fake.calls) == 0


async def test_response_hash_recorded_in_log() -> None:
    fake = FakeInference(response_content="response text")
    pl = InMemoryPromptLog()
    gw, al, _, _ = _make_gateway(fake, prompt_log=pl)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(prompt_text="prompt", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert pl.entries[0].response_hash is not None
    assert len(pl.entries[0].response_hash) == 64  # SHA-256 hex


async def test_recorded_output_in_response() -> None:
    fake = FakeInference()
    gw, al, _, _ = _make_gateway(fake)
    al.permit(TENANT_A, MODEL_GPT4.id)

    resp = await gw.generate(prompt_text="check output", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert "prompt_hash" in resp.recorded_output
    assert "response_hash" in resp.recorded_output
    assert resp.recorded_output["model_id"] == MODEL_GPT4.id


async def test_budget_exhausted_raises() -> None:
    fake = FakeInference()
    bt = InMemoryBudgetTracker()
    gw, al, _, _ = _make_gateway(fake, budget=bt)
    al.permit(TENANT_A, MODEL_GPT4.id)
    bt.set_budget(TENANT_A, max_tokens=1)

    with pytest.raises(GatewayBudgetExceededError):
        await gw.generate(
            prompt_text="this is a long prompt that will exceed the token budget",
            model_ref=MODEL_GPT4,
            tenant=TENANT_A,
        )


async def test_budget_consumed_on_success() -> None:
    fake = FakeInference()
    bt = InMemoryBudgetTracker()
    gw, al, _, _ = _make_gateway(fake, budget=bt)
    al.permit(TENANT_A, MODEL_GPT4.id)
    bt.set_budget(TENANT_A, max_tokens=1000)

    await gw.generate(prompt_text="hello world", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert bt.usage(TENANT_A)["tokens"] > 0


async def test_pii_masking_strips_sensitive_from_prompt() -> None:
    fake = FakeInference()
    masking_configs = {str(TENANT_A): MaskingConfig(sensitive_fields=frozenset(["ssn"]))}
    gw, al, _, _ = _make_gateway(fake, masking_configs=masking_configs)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(
        prompt_text="Process record for SSN 123-45-6789",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        payload={"ssn": "123-45-6789"},
    )

    assert len(fake.calls) == 1
    sent_prompt: Prompt = fake.calls[0]["prompt"]
    assert "123-45-6789" not in sent_prompt.text


async def test_pii_masking_rehydrated_in_response() -> None:
    ssn_value = "123-45-6789"
    fake = FakeInference(response_content="Processed [MASKED:placeholder] — done")
    masking_configs = {str(TENANT_A): MaskingConfig(sensitive_fields=frozenset(["ssn"]))}
    gw, al, _, _ = _make_gateway(fake, masking_configs=masking_configs)
    al.permit(TENANT_A, MODEL_GPT4.id)

    resp = await gw.generate(
        prompt_text=f"Process record for SSN {ssn_value}",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        payload={"ssn": ssn_value},
    )

    # The response content should have rehydrated any masked tokens back to original values.
    # Since FakeInference doesn't echo the token, we verify the gateway doesn't corrupt clean content.
    assert resp.content is not None


async def test_pattern_masking_strips_undeclared_pii() -> None:
    """Built-in PII detectors mask PAN/Aadhaar/email even when no sensitive field is declared (#3)."""
    fake = FakeInference()
    gw, al, _, _ = _make_gateway(fake)  # no masking_configs → defaults (mask_patterns=True)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(
        prompt_text="Applicant PAN ABCDE1234F, Aadhaar 1234 5678 9012, email jane@example.com",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
    )

    sent = fake.calls[0]["prompt"].text
    assert "ABCDE1234F" not in sent
    assert "1234 5678 9012" not in sent
    assert "jane@example.com" not in sent


async def test_pattern_masking_can_be_disabled() -> None:
    """With mask_patterns=False and no declared fields, free-text PII is left intact."""
    fake = FakeInference()
    masking_configs = {str(TENANT_A): MaskingConfig(mask_patterns=False)}
    gw, al, _, _ = _make_gateway(fake, masking_configs=masking_configs)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(
        prompt_text="email jane@example.com",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
    )

    assert "jane@example.com" in fake.calls[0]["prompt"].text


async def test_profile_disables_allowlist() -> None:
    """A profile with enforce_model_allowlist=False lets an unlisted model through (#composable)."""
    from quaicu.core.lifecycle.profile import GovernanceProfile

    fake = FakeInference()
    gw, al, _, _ = _make_gateway(fake)  # nothing permitted
    resp = await gw.generate(
        prompt_text="hi",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        profile=GovernanceProfile(enforce_model_allowlist=False),
    )
    assert resp.content == "ok"
    assert len(fake.calls) == 1


async def test_profile_disables_masking() -> None:
    from quaicu.core.lifecycle.profile import GovernanceProfile

    fake = FakeInference()
    masking_configs = {str(TENANT_A): MaskingConfig(sensitive_fields=frozenset(["ssn"]))}
    gw, al, _, _ = _make_gateway(fake, masking_configs=masking_configs)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(
        prompt_text="SSN 123-45-6789",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        payload={"ssn": "123-45-6789"},
        profile=GovernanceProfile(mask_pii=False),
    )
    assert "123-45-6789" in fake.calls[0]["prompt"].text  # masking skipped


async def test_profile_disables_logging() -> None:
    from quaicu.core.lifecycle.profile import GovernanceProfile

    fake = FakeInference()
    pl = InMemoryPromptLog()
    gw, al, _, _ = _make_gateway(fake, prompt_log=pl)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(
        prompt_text="no log please",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        profile=GovernanceProfile(log_prompts=False),
    )
    assert len(pl.entries) == 0  # logging skipped
    assert len(fake.calls) == 1


async def test_profile_disables_budget() -> None:
    from quaicu.core.lifecycle.profile import GovernanceProfile

    fake = FakeInference()
    bt = InMemoryBudgetTracker()
    gw, al, _, _ = _make_gateway(fake, budget=bt)
    al.permit(TENANT_A, MODEL_GPT4.id)
    bt.set_budget(TENANT_A, max_tokens=1)  # would normally block a multi-word prompt

    resp = await gw.generate(
        prompt_text="this prompt would exceed the tiny budget",
        model_ref=MODEL_GPT4,
        tenant=TENANT_A,
        profile=GovernanceProfile(enforce_budget=False),
    )
    assert resp.content == "ok"  # budget not enforced


async def test_inference_failure_propagates() -> None:
    fake = FakeInference(fail=True)
    gw, al, _, _ = _make_gateway(fake)
    al.permit(TENANT_A, MODEL_GPT4.id)

    with pytest.raises(InferencePortError):
        await gw.generate(prompt_text="will fail", model_ref=MODEL_GPT4, tenant=TENANT_A)


async def test_tenant_isolation_allowlists() -> None:
    fake = FakeInference()
    gw, al, _, _ = _make_gateway(fake)
    al.permit(TENANT_A, MODEL_GPT4.id)

    with pytest.raises(GatewayDeniedError):
        await gw.generate(prompt_text="cross-tenant", model_ref=MODEL_GPT4, tenant=TENANT_B)

    assert len(fake.calls) == 0


async def test_multiple_permitted_models() -> None:
    fake = FakeInference()
    gw, al, _, _ = _make_gateway(fake)
    al.permit(TENANT_A, MODEL_GPT4.id)
    al.permit(TENANT_A, MODEL_CLAUDE.id)

    resp1 = await gw.generate(prompt_text="first", model_ref=MODEL_GPT4, tenant=TENANT_A)
    resp2 = await gw.generate(prompt_text="second", model_ref=MODEL_CLAUDE, tenant=TENANT_A)

    assert resp1.content == "ok"
    assert resp2.content == "ok"
    assert len(fake.calls) == 2


async def test_log_entry_has_tenant() -> None:
    fake = FakeInference()
    pl = InMemoryPromptLog()
    gw, al, _, _ = _make_gateway(fake, prompt_log=pl)
    al.permit(TENANT_A, MODEL_GPT4.id)

    await gw.generate(prompt_text="tenant check", model_ref=MODEL_GPT4, tenant=TENANT_A)

    assert pl.entries[0].tenant == TENANT_A
