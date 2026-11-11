from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field


# ── Built-in PII detectors ──────────────────────────────────────────────────────
#
# DPDP-oriented defaults plus common international identifiers. Each pattern matches a
# whole PII token; the gateway tokenizes every match before a prompt leaves the kernel,
# so PII is masked even when it was never declared as a structured payload field.
#
# Ordered most-specific first: PAN/Aadhaar before the generic credit-card digit run so a
# longer, structured identifier wins over an overlapping numeric match.
_DEFAULT_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "AADHAAR": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "INDIAN_PHONE": re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


@dataclass(frozen=True)
class MaskingConfig:
    """Per-tenant masking configuration.

    sensitive_fields: payload field names whose VALUES are masked wherever they appear.
    mask_patterns:    when True (default), built-in PII detectors also mask free-text PII.
    extra_patterns:   optional (label, regex) pairs to mask in addition to the built-ins.
    """

    sensitive_fields: frozenset[str] = field(default_factory=frozenset)
    mask_patterns: bool = True
    extra_patterns: tuple[tuple[str, str], ...] = ()


@dataclass
class MaskingContext:
    """Holds the token→value map for a single request. Never transmitted; stays in-process."""

    token_map: dict[str, str] = field(default_factory=dict)
    # Reverse index so a repeated value always maps to the SAME token — this keeps
    # rehydration stable and avoids leaking how many distinct occurrences there were.
    _value_to_token: dict[str, str] = field(default_factory=dict)

    def tokenize(self, value: str) -> str:
        existing = self._value_to_token.get(value)
        if existing is not None:
            return existing
        token = f"[MASKED:{uuid.uuid4().hex[:8]}]"
        self.token_map[token] = value
        self._value_to_token[value] = token
        return token

    def rehydrate(self, text: str) -> str:
        for token, original in self.token_map.items():
            text = text.replace(token, original)
        return text


def _iter_patterns(config: MaskingConfig) -> list[re.Pattern[str]]:
    patterns: list[re.Pattern[str]] = []
    if config.mask_patterns:
        patterns.extend(_DEFAULT_PATTERNS.values())
    for _label, raw in config.extra_patterns:
        patterns.append(re.compile(raw))
    return patterns


def mask_text(text: str, config: MaskingConfig, ctx: MaskingContext) -> str:
    """Tokenize any PII the configured detectors find in free text.

    Each match is replaced with a stable per-value token tracked in ``ctx`` so the response
    can be rehydrated. Returns the text unchanged when no detector matches.
    """
    if not text:
        return text
    masked = text
    for pattern in _iter_patterns(config):
        masked = pattern.sub(lambda m: ctx.tokenize(m.group(0)), masked)
    return masked


def mask_payload(payload: dict, config: MaskingConfig, ctx: MaskingContext) -> dict:
    """Tokenize sensitive fields in a payload dict."""
    masked = {}
    for k, v in payload.items():
        if k in config.sensitive_fields and isinstance(v, str):
            masked[k] = ctx.tokenize(v)
        else:
            masked[k] = v
    return masked


# ── MaskingPort: default (regex) adapter ─────────────────────────────────────────


class RegexMaskingAdapter:
    """The default `MaskingPort` (quaicu/core/ports/masking) — the in-process regex masker. No network, no
    dependency; this is what runs unless a managed detector (e.g. Cloud DLP) is configured."""

    async def mask(self, text: str, *, config: MaskingConfig, ctx: MaskingContext) -> str:
        return mask_text(text, config, ctx)


# Module singleton — the gateway's default masking engine.
DEFAULT_MASKING = RegexMaskingAdapter()
