"""InferencePort (K·05) — FROZEN. Abstracts ALL inference backends. Core never imports a model SDK."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.types import ModelRef, ModelResponse, Prompt, TenantId


@runtime_checkable
class InferencePort(Protocol):
    """Abstracts every inference backend (ollama, vllm, tgi, openai, anthropic, bedrock,
    azure_openai, vertex). Core depends only on this Protocol.

    Fail-closed contract:
      - Model unavailable → raise `InferencePortError` (never return empty).
      - Model not in the tenant's approved registry → raise `InferencePortError`.
      - Call cannot be logged (the K·05 prompt-logging requirement) → raise `InferencePortError`.
        An unlogged model call is an ungoverned call and is categorically forbidden.
      - Timeout → raise `PortTimeoutError`; the caller must DENY.
    """

    async def generate(
        self,
        *,
        prompt: Prompt,
        model_ref: ModelRef,
        tenant: TenantId,
    ) -> ModelResponse:
        """Generate a model response.

        Args:
            prompt: The already-masked prompt. PII masking is done by the Gateway before this call.
            model_ref: Which model to invoke (id + version + runtime).
            tenant: Tenant boundary. The adapter must verify the model is approved for this tenant
                via the Model Registry (K·08) before executing.

        Returns:
            A `ModelResponse` whose `recorded_output` is sealed to the ledger for replay fidelity
            (non-determinism recorded here, never recomputed — F-09).

        Raises:
            InferencePortError: model unavailable, unapproved, or logging failed.
            PortTimeoutError: call exceeded the configured timeout.
        """
        ...
