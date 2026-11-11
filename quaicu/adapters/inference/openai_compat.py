"""OpenAI-compatible InferencePort adapter.

Works with any OpenAI-compatible REST endpoint: OpenAI, Ollama, vLLM, TGI, Together AI,
Mistral, Perplexity. For Anthropic, an OpenAI-compatibility shim is required (e.g. LiteLLM).

Invariants:
- Fail-closed (F-03): any HTTP error or timeout → InferencePortError; never returns a partial result.
- Replay-safe (F-09): ModelResponse.recorded_output carries the full response for replay.
- No model SDK in core (F-08): this adapter lives in adapters/, not core/.
- Config-driven (F-11): base_url and api_key come from config, not code.
"""

from __future__ import annotations

from typing import Any

import httpx

from quaicu.core.errors import InferencePortError, PortTimeoutError
from quaicu.core.types import ModelRef, ModelResponse, Prompt, TenantId


class OpenAICompatInferenceAdapter:
    """InferencePort adapter for any OpenAI-compatible chat completions endpoint.

    Args:
        base_url: REST base URL (e.g. ``"https://api.openai.com/v1"`` or
            ``"http://localhost:11434/v1"`` for Ollama).
        api_key: Bearer token. Pass ``"ollama"`` for Ollama (which ignores it).
        timeout: Per-request timeout in seconds (fail-closed on breach).
        default_model: Fallback model id if ``model_ref.id`` is not set.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "sk-placeholder",
        timeout: float = 30.0,
        default_model: str = "llama3",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._default_model = default_model

    async def generate(
        self,
        *,
        prompt: Prompt,
        model_ref: ModelRef,
        tenant: TenantId,
    ) -> ModelResponse:
        """Call the chat completions endpoint and return a ModelResponse.

        Fail-closed: any error → InferencePortError. The recorded_output carries
        the full API response dict for replay (F-09).
        """
        model_id = model_ref.id or self._default_model
        request_body = {
            "model": model_id,
            "messages": [{"role": "user", "content": prompt.text}],
            **prompt.metadata,  # caller may pass temperature, max_tokens, etc.
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._base_url}/chat/completions",
                    json=request_body,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "X-Tenant-Id": str(tenant),
                    },
                )
        except httpx.TimeoutException as exc:
            raise PortTimeoutError(
                f"Inference timeout after {self._timeout}s for model {model_id!r}",
                detail={"model_id": model_id, "tenant": str(tenant)},
            ) from exc
        except Exception as exc:
            raise InferencePortError(
                f"Inference request failed: {exc}",
                detail={"model_id": model_id, "tenant": str(tenant)},
            ) from exc

        if resp.status_code != 200:
            raise InferencePortError(
                f"Inference endpoint returned HTTP {resp.status_code}",
                detail={"status_code": resp.status_code, "body": resp.text[:500]},
            )

        try:
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            raise InferencePortError(
                "Inference response is not valid JSON",
                detail={"body": resp.text[:500]},
            ) from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise InferencePortError(
                "Inference response missing expected fields",
                detail={"response": data},
            ) from exc

        return ModelResponse(
            content=content,
            model_id=model_id,
            recorded_output=data,  # full response sealed for replay (F-09)
            metadata={"tenant": str(tenant)},
        )
