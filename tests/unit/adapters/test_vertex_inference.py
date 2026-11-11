"""Unit tests for VertexInferenceAdapter.

The google-genai client is faked (async ``aio.models.generate_content``), so no GCP project or
credentials are required.
"""

from __future__ import annotations

import asyncio

import pytest

from quaicu.adapters.inference.vertex import VertexInferenceAdapter
from quaicu.core.errors import InferencePortError, PortTimeoutError
from quaicu.core.types import ModelRef, Prompt, TenantId


class _FakeResp:
    def __init__(self, text: str) -> None:
        self.text = text

    def model_dump(self, mode: str = "json") -> dict:
        return {"text": self.text, "candidates": [{"content": self.text}]}


class _FakeModels:
    def __init__(self, resp: _FakeResp | None = None, error: Exception | None = None,
                 delay: float = 0.0) -> None:
        self._resp = resp
        self._error = error
        self._delay = delay
        self.last_call: dict | None = None

    async def generate_content(self, *, model: str, contents: str, config) -> _FakeResp:
        self.last_call = {"model": model, "contents": contents, "config": config}
        if self._error is not None:
            raise self._error
        if self._delay:
            await asyncio.sleep(self._delay)
        assert self._resp is not None
        return self._resp


class _FakeClient:
    def __init__(self, models: _FakeModels) -> None:
        self.aio = type("Aio", (), {"models": models})()


def _adapter(models: _FakeModels, *, timeout: float = 30.0) -> VertexInferenceAdapter:
    return VertexInferenceAdapter(
        project="proj", location="us-central1", timeout=timeout, client=_FakeClient(models)
    )


_PROMPT = Prompt(text="hello")
_TENANT = TenantId("acme")


async def test_generate_returns_model_response():
    models = _FakeModels(resp=_FakeResp("hi there"))
    adapter = _adapter(models)
    resp = await adapter.generate(prompt=_PROMPT, model_ref=ModelRef(id="gemini-2.5-pro", version="1"), tenant=_TENANT)
    assert resp.content == "hi there"
    assert resp.model_id == "gemini-2.5-pro"
    assert resp.recorded_output["text"] == "hi there"  # full response sealed for replay
    assert resp.metadata["provider"] == "vertex"
    assert models.last_call["model"] == "gemini-2.5-pro"


async def test_generate_uses_default_model_when_unset():
    models = _FakeModels(resp=_FakeResp("ok"))
    adapter = _adapter(models)
    await adapter.generate(prompt=_PROMPT, model_ref=ModelRef(id="", version="1"), tenant=_TENANT)
    assert models.last_call["model"] == "gemini-2.5-pro"  # the adapter default


async def test_generate_fail_closed_on_client_error():
    adapter = _adapter(_FakeModels(error=RuntimeError("vertex down")))
    with pytest.raises(InferencePortError, match="Vertex inference request failed"):
        await adapter.generate(prompt=_PROMPT, model_ref=ModelRef(id="m", version="1"), tenant=_TENANT)


async def test_generate_timeout_raises_port_timeout():
    adapter = _adapter(_FakeModels(resp=_FakeResp("slow"), delay=1.0), timeout=0.01)
    with pytest.raises(PortTimeoutError):
        await adapter.generate(prompt=_PROMPT, model_ref=ModelRef(id="m", version="1"), tenant=_TENANT)


async def test_generate_empty_text_is_fail_closed():
    adapter = _adapter(_FakeModels(resp=_FakeResp("")))
    with pytest.raises(InferencePortError, match="missing text"):
        await adapter.generate(prompt=_PROMPT, model_ref=ModelRef(id="m", version="1"), tenant=_TENANT)
