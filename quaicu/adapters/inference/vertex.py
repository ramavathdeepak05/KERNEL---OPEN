"""Vertex AI (Gemini) InferencePort adapter.

Routes inference to Google Cloud Vertex AI via the ``google-genai`` SDK (Vertex backend). For
regulated deployments this is the "AI sovereignty" path: run the kernel inside the customer's VPC and
reach Vertex over Private Service Connect, so prompts never traverse the public internet and are
never used to train base models (see docs/adr/0012-cloud-native-adapters.md).

Invariants (same as every InferencePort adapter):
- Fail-closed (F-03): any error → InferencePortError; timeout → PortTimeoutError. Never a partial result.
- Replay-safe (F-09): ModelResponse.recorded_output carries the full response for replay.
- No model SDK in core (F-08): the SDK is imported lazily here, behind the ``[gcp]`` extra.
- Config-driven (F-11): project/location/model come from config, not code. Auth via ADC / Workload
  Identity (no static keys).
"""

from __future__ import annotations

import asyncio
from typing import Any

from quaicu.core.errors import InferencePortError, PortTimeoutError
from quaicu.core.types import ModelRef, ModelResponse, Prompt, TenantId


def _to_recorded_dict(resp: Any) -> dict[str, Any]:
    """Best-effort JSON-serializable dict of the SDK response for replay fidelity (F-09)."""
    for attr, kwargs in (("model_dump", {"mode": "json"}), ("to_json_dict", {}), ("dict", {})):
        fn = getattr(resp, attr, None)
        if callable(fn):
            try:
                return dict(fn(**kwargs))
            except Exception:  # noqa: BLE001 — fall through to the next strategy
                continue
    return {}


class VertexInferenceAdapter:
    """InferencePort adapter for Google Cloud Vertex AI (Gemini family).

    Args:
        project: GCP project id hosting Vertex AI.
        location: Vertex region (e.g. ``"us-central1"``).
        default_model: Fallback model id if ``model_ref.id`` is not set (e.g. ``"gemini-2.5-pro"``).
        timeout: Per-request timeout in seconds (fail-closed on breach).
        client: Optional pre-built ``google.genai`` client (injected in tests). When ``None``, a
            Vertex-backed client is constructed lazily using Application Default Credentials.
    """

    def __init__(
        self,
        project: str,
        location: str = "us-central1",
        default_model: str = "gemini-2.5-pro",
        timeout: float = 30.0,
        *,
        client: Any | None = None,
    ) -> None:
        if client is None:
            # Lazy import: keeps google-genai an optional ([gcp]) dependency, out of core.
            from google import genai

            client = genai.Client(vertexai=True, project=project, location=location)
        self._client = client
        self._project = project
        self._location = location
        self._default_model = default_model
        self._timeout = timeout

    async def generate(
        self,
        *,
        prompt: Prompt,
        model_ref: ModelRef,
        tenant: TenantId,
    ) -> ModelResponse:
        """Call Vertex AI and return a ModelResponse.

        The prompt is already masked by the Gateway (K·05). Fail-closed: any error →
        InferencePortError, timeout → PortTimeoutError. The full response is recorded for replay.
        """
        model_id = model_ref.id or self._default_model
        config = dict(prompt.metadata) or None  # caller may pass temperature, max_output_tokens, etc.

        try:
            resp = await asyncio.wait_for(
                self._client.aio.models.generate_content(
                    model=model_id,
                    contents=prompt.text,
                    config=config,
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError as exc:
            raise PortTimeoutError(
                f"Vertex inference timeout after {self._timeout}s for model {model_id!r}",
                detail={"model_id": model_id, "tenant": str(tenant)},
            ) from exc
        except Exception as exc:
            raise InferencePortError(
                f"Vertex inference request failed: {exc}",
                detail={"model_id": model_id, "tenant": str(tenant)},
            ) from exc

        content = getattr(resp, "text", None)
        if not content:
            raise InferencePortError(
                "Vertex response missing text content",
                detail={"model_id": model_id, "tenant": str(tenant)},
            )

        return ModelResponse(
            content=content,
            model_id=model_id,
            recorded_output=_to_recorded_dict(resp),  # full response sealed for replay (F-09)
            metadata={"tenant": str(tenant), "provider": "vertex", "location": self._location},
        )
