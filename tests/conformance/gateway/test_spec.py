"""Conformance: spec §3.12 and §6 K·05 DoD requirements."""
from __future__ import annotations

import ast
import pathlib

import pytest

from quaicu.core.errors import GatewayDeniedError, GatewayLoggingError
from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.budget import InMemoryBudgetTracker
from quaicu.core.gateway.engine import AIGateway
from quaicu.core.gateway.log import InMemoryPromptLog
from quaicu.core.types import ModelRef, ModelResponse, Prompt, TenantId


class _FakeInference:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def generate(self, *, prompt: Prompt, model_ref: ModelRef, tenant: TenantId) -> ModelResponse:
        self.calls.append({"prompt": prompt, "model_ref": model_ref, "tenant": tenant})
        return ModelResponse(content="conformance-ok", model_id=model_ref.id, recorded_output={})


@pytest.mark.conformance
async def test_no_model_sdk_in_core() -> None:
    """K·05 core code must not import any model SDK directly — only InferencePort."""
    gateway_dir = pathlib.Path("quaicu/core/gateway")
    forbidden = {"openai", "anthropic", "boto3", "google.generativeai", "ollama"}
    for py_file in gateway_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in getattr(node, "names", [])] + (
                    [node.module] if hasattr(node, "module") and node.module else []
                )
                for name in names:
                    if name and any(name.startswith(f) for f in forbidden):
                        pytest.fail(f"Forbidden import {name!r} found in {py_file}")


@pytest.mark.conformance
async def test_log_before_call_invariant() -> None:
    """If prompt log write succeeds, call happens. If it fails, call does not happen."""
    tenant = TenantId("conformance-tenant")
    model = ModelRef(id="test-model", version="1")

    fake_success = _FakeInference()
    pl_success = InMemoryPromptLog()
    al_success = InMemoryModelAllowlist()
    al_success.permit(tenant, model.id)
    gw_success = AIGateway(
        inference=fake_success,
        allowlist=al_success,
        prompt_log=pl_success,
        budget=InMemoryBudgetTracker(),
    )
    await gw_success.generate(prompt_text="test", model_ref=model, tenant=tenant)
    assert len(pl_success.entries) == 1
    assert len(fake_success.calls) == 1

    fake_fail = _FakeInference()
    pl_fail = InMemoryPromptLog()
    al_fail = InMemoryModelAllowlist()
    al_fail.permit(tenant, model.id)
    gw_fail = AIGateway(
        inference=fake_fail,
        allowlist=al_fail,
        prompt_log=pl_fail,
        budget=InMemoryBudgetTracker(),
    )
    pl_fail.inject_failure()
    with pytest.raises(GatewayLoggingError):
        await gw_fail.generate(prompt_text="test", model_ref=model, tenant=tenant)
    assert len(fake_fail.calls) == 0


@pytest.mark.conformance
async def test_no_fallback_to_unapproved_model() -> None:
    """When the requested model is not approved, DENY — never fall back to another model."""
    tenant = TenantId("conformance-tenant-2")
    unapproved = ModelRef(id="unapproved-model", version="1")

    fake = _FakeInference()
    al = InMemoryModelAllowlist()
    gw = AIGateway(
        inference=fake,
        allowlist=al,
        prompt_log=InMemoryPromptLog(),
        budget=InMemoryBudgetTracker(),
    )

    with pytest.raises(GatewayDeniedError):
        await gw.generate(prompt_text="test", model_ref=unapproved, tenant=tenant)

    assert len(fake.calls) == 0
