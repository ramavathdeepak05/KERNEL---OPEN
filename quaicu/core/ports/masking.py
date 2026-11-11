"""MaskingPort (K·05) — abstracts the PII-detection engine behind the gateway's masking step.

The gateway tokenizes PII out of prompts before they leave the kernel and rehydrates it in the
response (`MaskingContext` holds the token↔value map). *How* PII is detected is swappable: the default
is the in-process regex masker (`quaicu/core/gateway/masking.RegexMaskingAdapter`); a managed detector
(`quaicu/adapters/masking/gcp_dlp.CloudDLPMaskingAdapter`, Google Cloud DLP) catches what regex can't — person
names, addresses, context-dependent entities, more locales.

The method is **async** because a managed detector is a network call (run off the event loop). It must
tokenize detected spans into the supplied `ctx` so rehydration is unchanged regardless of engine.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.gateway.masking import MaskingConfig, MaskingContext


@runtime_checkable
class MaskingPort(Protocol):
    """Detect + tokenize PII in free text, recording the tokens in ``ctx`` for later rehydration."""

    async def mask(self, text: str, *, config: MaskingConfig, ctx: MaskingContext) -> str:
        """Return ``text`` with detected PII replaced by stable ``[MASKED:…]`` tokens (tracked in ``ctx``).

        Must be idempotent w.r.t. ``ctx`` (a repeated value maps to the same token) and never raise on
        ordinary input — a detector failure should fail closed at the call site, not corrupt the prompt.
        """
        ...
