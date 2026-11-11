from __future__ import annotations

import dataclasses
import hashlib
import logging

from quaicu.core.errors import GatewayDeniedError, GatewayLoggingError
from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.budget import InMemoryBudgetTracker
from quaicu.core.gateway.log import InMemoryPromptLog
from quaicu.core.gateway.masking import MaskingConfig, MaskingContext, mask_payload, mask_text
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.ports.inference import InferencePort
from quaicu.core.types import ActionId, ModelRef, ModelResponse, Prompt, TenantId

log = logging.getLogger("quaicu.gateway")


class AIGateway:
    """
    K·05 AI Gateway. All model calls in the kernel go through here.

    Governance enforcement order (each step is fail-closed):
    1. Check model allowlist → GatewayDeniedError if not permitted
    2. Mask PII in prompt → GatewayMaskingError on failure
    3. Log prompt BEFORE call → GatewayLoggingError on failure (call cancelled)
    4. Check / consume budget → GatewayBudgetExceededError if exhausted
    5. Call InferencePort.generate()
    6. Record response hash in log
    7. Return ModelResponse with recorded_output populated
    """

    def __init__(
        self,
        *,
        inference: InferencePort,
        allowlist: InMemoryModelAllowlist | None = None,
        prompt_log: InMemoryPromptLog | None = None,
        budget: InMemoryBudgetTracker | None = None,
        masking_configs: dict[str, MaskingConfig] | None = None,
    ) -> None:
        self._inference = inference
        self._allowlist = allowlist or InMemoryModelAllowlist()
        self._prompt_log = prompt_log or InMemoryPromptLog()
        self._budget = budget or InMemoryBudgetTracker()
        self._masking_configs: dict[str, MaskingConfig] = masking_configs or {}

    async def generate(
        self,
        *,
        prompt_text: str,
        model_ref: ModelRef,
        tenant: TenantId,
        action_id: ActionId | None = None,
        payload: dict | None = None,
        profile: GovernanceProfile | None = None,
    ) -> ModelResponse:
        """
        Execute a governed model call.

        `prompt_text` is the raw (unmasked) prompt. Masking happens here before transmission.
        Returns a `ModelResponse` with `recorded_output` populated for ledger sealing.

        `profile` toggles the four gateway sub-layers independently (allowlist, PII masking,
        prompt logging, budget). When None, all four are enforced (maximal posture).
        """
        prof = profile or GovernanceProfile.all()

        if prof.enforce_model_allowlist:
            if not self._allowlist.is_permitted(tenant, model_ref):
                raise GatewayDeniedError(
                    f"Model {model_ref.id!r} is not in the allowlist for tenant {tenant!r}. Denied (no fallback).",
                    detail={"model_id": model_ref.id, "tenant": str(tenant)},
                )
        else:
            log.warning("gateway: model allowlist disabled by profile for tenant %s", tenant)

        ctx = MaskingContext()
        if prof.mask_pii:
            masking_cfg = self._masking_configs.get(str(tenant), MaskingConfig())
            mask_payload(payload or {}, masking_cfg, ctx)
            # First substitute the values of declared sensitive payload fields wherever they
            # appear verbatim in the prompt, then run the built-in PII detectors so that any
            # remaining free-text PII (PAN, Aadhaar, email, …) is masked too — even if it was
            # never declared as a structured field.
            masked_prompt_text = prompt_text
            for original, token in {v: k for k, v in ctx.token_map.items()}.items():
                masked_prompt_text = masked_prompt_text.replace(original, token)
            masked_prompt_text = mask_text(masked_prompt_text, masking_cfg, ctx)
        else:
            masked_prompt_text = prompt_text

        prompt = Prompt(text=masked_prompt_text, metadata={"tenant": str(tenant)})
        prompt_hash = hashlib.sha256(prompt.text.encode("utf-8")).hexdigest()

        log_id: str | None = None
        if prof.log_prompts:
            try:
                log_entry = self._prompt_log.write(
                    action_id=action_id,
                    tenant=tenant,
                    model_ref=model_ref,
                    prompt_hash=prompt_hash,
                )
                log_id = log_entry.log_id
            except GatewayLoggingError:
                raise
            except Exception as exc:
                raise GatewayLoggingError(
                    f"Prompt log write failed: {exc}",
                    detail={"tenant": str(tenant), "model_id": model_ref.id},
                ) from exc
        else:
            log.warning("gateway: prompt logging disabled by profile for tenant %s", tenant)

        if prof.enforce_budget:
            estimated_tokens = max(1, len(prompt.text.split()))
            self._budget.check_and_consume(tenant, tokens=estimated_tokens)

        log.info(
            "gateway: calling model %s for tenant %s (log_id=%s)",
            model_ref.id,
            tenant,
            log_id,
        )
        response = await self._inference.generate(prompt=prompt, model_ref=model_ref, tenant=tenant)

        response_hash = hashlib.sha256(response.content.encode("utf-8")).hexdigest()
        if log_id is not None:
            self._prompt_log.record_response(log_id, response_hash)

        rehydrated_content = ctx.rehydrate(response.content)

        recorded_output = {
            "log_id": log_id,
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "model_id": model_ref.id,
            "model_version": model_ref.version,
        }

        log.info("gateway: model call complete log_id=%s", log_id)

        return dataclasses.replace(
            response,
            content=rehydrated_content,
            recorded_output=recorded_output,
        )
