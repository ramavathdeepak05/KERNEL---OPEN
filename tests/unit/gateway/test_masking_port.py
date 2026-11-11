"""MaskingPort (W6-3): regex default adapter + Cloud DLP adapter (injected fake client)."""

from __future__ import annotations

from quaicu.adapters.masking.gcp_dlp import CloudDLPMaskingAdapter, MaskingDependencyError
from quaicu.core.gateway.masking import DEFAULT_MASKING, MaskingConfig, MaskingContext, RegexMaskingAdapter
from quaicu.core.ports.masking import MaskingPort

_CFG = MaskingConfig()


def test_adapters_satisfy_the_port():
    assert isinstance(RegexMaskingAdapter(), MaskingPort)
    assert isinstance(CloudDLPMaskingAdapter("proj", client=object()), MaskingPort)


async def test_regex_adapter_masks_and_rehydrates():
    ctx = MaskingContext()
    masked = await DEFAULT_MASKING.mask("email alice@acme.io now", config=_CFG, ctx=ctx)
    assert "alice@acme.io" not in masked and "[MASKED:" in masked
    assert ctx.rehydrate(masked) == "email alice@acme.io now"


# ── Cloud DLP with an injected fake client (no google-cloud-dlp, no network) ────────


class _Finding:
    def __init__(self, quote):
        self.quote = quote


class _Result:
    def __init__(self, quotes):
        self.findings = [_Finding(q) for q in quotes]


class _FakeDlpResponse:
    def __init__(self, quotes):
        self.result = _Result(quotes)


class _FakeDlpClient:
    def __init__(self, quotes):
        self._quotes = quotes
        self.calls = 0

    def inspect_content(self, request=None):
        self.calls += 1
        _FakeDlpClient.last_request = request
        return _FakeDlpResponse(self._quotes)


async def test_dlp_adapter_tokenizes_findings_and_rehydrates():
    # DLP catches a person name a regex would miss.
    client = _FakeDlpClient(["Jane Roe"])
    adapter = CloudDLPMaskingAdapter("my-proj", client=client)
    ctx = MaskingContext()
    masked = await adapter.mask("call Jane Roe today", config=_CFG, ctx=ctx)
    assert "Jane Roe" not in masked and "[MASKED:" in masked
    assert ctx.rehydrate(masked) == "call Jane Roe today"
    # The request targeted the project parent + asked for quotes.
    req = _FakeDlpClient.last_request
    assert req["parent"] == "projects/my-proj/locations/global"
    assert req["inspect_config"]["include_quote"] is True


async def test_dlp_adapter_no_findings_returns_text_unchanged():
    adapter = CloudDLPMaskingAdapter("p", client=_FakeDlpClient([]))
    ctx = MaskingContext()
    assert await adapter.mask("nothing sensitive", config=_CFG, ctx=ctx) == "nothing sensitive"


async def test_dlp_adapter_missing_sdk_raises_dependency_error():
    # No client + google-cloud-dlp not installed in this env → clear dependency error.
    adapter = CloudDLPMaskingAdapter("p")
    try:
        await adapter.mask("x", config=_CFG, ctx=MaskingContext())
        raise AssertionError("expected MaskingDependencyError")
    except MaskingDependencyError:
        pass


def test_dlp_adapter_requires_project():
    try:
        CloudDLPMaskingAdapter("")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
