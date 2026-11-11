"""Unit tests for POST /v1/inference — governed model call over the API."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.engine import AIGateway
from quaicu.core.types import Decision, ModelRef, ModelResponse, Prompt, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}


class _FakeInference:
    async def generate(self, *, prompt: Prompt, model_ref: ModelRef, tenant: TenantId) -> ModelResponse:
        return ModelResponse(content="generated text", model_id=model_ref.id, recorded_output={})


def _app(decision: Decision = Decision.ALLOW, with_gateway: bool = True):
    gateway = None
    if with_gateway:
        allowlist = InMemoryModelAllowlist()
        allowlist.permit(TENANT, "gpt-4")
        gateway = AIGateway(inference=_FakeInference(), allowlist=allowlist)
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(),
        gateway=gateway,
    )
    return create_app(kernel)


def _body(key: str = "ik-inf-1") -> dict:
    return {"model_id": "gpt-4", "prompt_text": "summarize this", "idempotency_key": key}


async def test_inference_without_token_returns_401():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/inference", json=_body())
    assert resp.status_code == 401


async def test_inference_returns_content_and_hashes():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/inference", json=_body(), headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["content"] == "generated text"
    assert data["model_id"] == "gpt-4"
    assert len(data["prompt_hash"]) == 64  # SHA-256 hex
    assert len(data["response_hash"]) == 64


async def test_inference_denied_returns_403():
    app = _app(decision=Decision.DENY)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/inference", json=_body(), headers=AUTH)
    assert resp.status_code == 403


async def test_inference_without_gateway_returns_503():
    app = _app(with_gateway=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/inference", json=_body(), headers=AUTH)
    assert resp.status_code == 503
