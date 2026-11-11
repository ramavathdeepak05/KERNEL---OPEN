"""Google Cloud DLP masking adapter — a `MaskingPort` that detects PII via Cloud DLP (W6-3).

Catches what the regex masker can't (person names, addresses, context-dependent entities, more
locales). boto…/the DLP SDK is lazily imported (``[gcp]`` extra) and the client is injectable for
tests, so this module imports with no extra dependency and is exercised without a real GCP project.

Detection model: ``inspect_content`` (with ``include_quote``) returns findings whose ``.quote`` is the
matched PII; we tokenize each quote into the supplied `MaskingContext` (reusing the same stable-token +
rehydration path as the regex masker), so the rest of the gateway is unchanged.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from quaicu.core.gateway.masking import MaskingConfig, MaskingContext

log = logging.getLogger("quaicu.masking.dlp")

# Default DLP info-types. DPDP/India-relevant + common international identifiers. Unknown types in a
# given DLP region are simply ignored by the service.
_DEFAULT_INFO_TYPES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "PERSON_NAME",
    "STREET_ADDRESS",
    "IBAN_CODE",
    "INDIA_AADHAAR_INDIVIDUAL",
    "INDIA_PAN_INDIVIDUAL",
)


class MaskingDependencyError(RuntimeError):
    """Raised when the Cloud DLP SDK (``google-cloud-dlp``, ``[gcp]`` extra) isn't installed."""


class CloudDLPMaskingAdapter:
    """`MaskingPort` backed by Google Cloud DLP. ``client`` is injectable for tests."""

    def __init__(
        self,
        project: str,
        *,
        location: str = "global",
        info_types: tuple[str, ...] = _DEFAULT_INFO_TYPES,
        min_likelihood: str = "POSSIBLE",
        client: Any | None = None,
    ) -> None:
        if not project:
            raise ValueError("CloudDLPMaskingAdapter requires a GCP project id.")
        self._project = project
        self._parent = f"projects/{project}/locations/{location}"
        self._info_types = tuple(info_types)
        self._min_likelihood = min_likelihood
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import dlp_v2  # lazy ([gcp] extra)
            except ImportError as exc:  # pragma: no cover - exercised via the no-SDK test
                raise MaskingDependencyError(
                    "Cloud DLP masking requires the 'gcp' extra: pip install quaicu-kernel[gcp]."
                ) from exc
            self._client = dlp_v2.DlpServiceClient()
        return self._client

    def _inspect_quotes(self, text: str) -> list[str]:
        """Blocking DLP inspect → the list of matched PII quotes (longest first, so nested spans win)."""
        client = self._get_client()
        request = {
            "parent": self._parent,
            "inspect_config": {
                "info_types": [{"name": t} for t in self._info_types],
                "min_likelihood": self._min_likelihood,
                "include_quote": True,
            },
            "item": {"value": text},
        }
        response = client.inspect_content(request=request)
        quotes = [f.quote for f in getattr(response.result, "findings", []) if getattr(f, "quote", "")]
        # Replace longer matches first so an overlapping shorter match can't truncate a token.
        return sorted(set(quotes), key=len, reverse=True)

    async def mask(self, text: str, *, config: MaskingConfig, ctx: MaskingContext) -> str:
        if not text:
            return text
        quotes = await asyncio.to_thread(self._inspect_quotes, text)
        masked = text
        for quote in quotes:
            masked = masked.replace(quote, ctx.tokenize(quote))
        return masked
