"""Unit tests for K·04 ConsentEngine.

Decision table from the skill contract:
  valid + not expired + purpose matches → grant (delegate to inner)
  missing (None)                        → DENY
  expired                               → DENY
  withdrawn                             → DENY
  port error / exception                → DENY (fail-closed, F-03)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from quaicu.core.consent.engine import ConsentEngine
from quaicu.core.errors import ConsentDeniedError
from quaicu.core.ports.consent import ConsentRecord
from quaicu.core.types import (
    Action,
    ActionId,
    Actor,
    ActorId,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    TenantId,
)

TENANT = TenantId("test-tenant")
NOW = datetime(2026, 6, 9, 12, 0, 0, tzinfo=timezone.utc)
FUTURE = NOW + timedelta(days=365)
PAST = NOW - timedelta(seconds=1)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_action(purpose: str = "ai_inference") -> Action:
    return Action(
        id=ActionId("act-1"),
        type="test.action",
        payload={"consent_purpose": purpose},
        actor=Actor(id=ActorId("alice"), tenant=TENANT),
        tenant=TENANT,
        idempotency_key=IdempotencyKey("key-1"),
    )


def _make_record(
    *,
    status: str = "active",
    expires_at: datetime | None = FUTURE,
    purpose: str = "ai_inference",
) -> ConsentRecord:
    return ConsentRecord(
        consent_id="c-001",
        tenant_id=str(TENANT),
        subject_id="alice",
        purpose=purpose,
        data_categories=("general",),
        status=status,
        granted_at=NOW - timedelta(days=10),
        expires_at=expires_at,
        withdrawn_at=None,
        policy_ref="dpdp-2023-s4",
    )


class _OKInner:
    """Fake inner evaluator that always returns ALLOW."""

    async def evaluate(self, action: Action) -> EvaluationResult:
        return EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",))


class _DenyInner:
    async def evaluate(self, action: Action) -> EvaluationResult:
        return EvaluationResult(decision=Decision.DENY, policy_versions=("v1",))


class _FakeConsentPort:
    """Configurable in-memory ConsentPort."""

    def __init__(
        self,
        record: ConsentRecord | None = None,
        raise_exc: bool = False,
    ) -> None:
        self._record = record
        self._raise_exc = raise_exc
        self.calls: list[dict[str, Any]] = []

    async def get_consent(
        self, *, tenant_id: str, subject_id: str, purpose: str
    ) -> ConsentRecord | None:
        self.calls.append(
            {"tenant_id": tenant_id, "subject_id": subject_id, "purpose": purpose}
        )
        if self._raise_exc:
            raise RuntimeError("injected port error")
        return self._record

    async def record_consent(self, record: ConsentRecord) -> None:
        pass

    async def withdraw_consent(
        self, *, tenant_id: str, subject_id: str, purpose: str, withdrawn_at: datetime
    ) -> None:
        pass


# ── Happy path ────────────────────────────────────────────────────────────────


async def test_valid_consent_delegates_to_inner():
    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    assert result.decision == Decision.ALLOW


async def test_consent_state_injected_into_metadata():
    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    assert "consent_state" in result.metadata
    assert result.metadata["consent_state"]["consent_id"] == "c-001"


async def test_inner_policy_versions_preserved():
    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    assert result.policy_versions == ("v1",)


async def test_inner_deny_propagates_after_consent_granted():
    """Consent is necessary but not sufficient — K·01 deny still wins."""
    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_DenyInner())
    result = await engine.evaluate(_make_action())
    assert result.decision == Decision.DENY


async def test_perpetual_consent_no_expiry():
    """expires_at=None means consent is perpetual until withdrawn."""
    record = _make_record(expires_at=None)
    port = _FakeConsentPort(record=record)
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    assert result.decision == Decision.ALLOW


async def test_port_called_with_correct_tenant_and_subject():
    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    await engine.evaluate(_make_action())
    assert len(port.calls) == 1
    assert port.calls[0]["tenant_id"] == str(TENANT)
    assert port.calls[0]["subject_id"] == "alice"
    assert port.calls[0]["purpose"] == "ai_inference"


# ── Fail-closed: DENY paths ───────────────────────────────────────────────────


async def test_missing_consent_is_denied():
    port = _FakeConsentPort(record=None)
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_make_action())
    assert exc_info.value.detail["reason"] == "missing"


async def test_expired_consent_is_denied():
    port = _FakeConsentPort(record=_make_record(expires_at=PAST))
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_make_action())
    assert exc_info.value.detail["reason"] == "expired"


async def test_withdrawn_consent_is_denied():
    port = _FakeConsentPort(record=_make_record(status="withdrawn"))
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_make_action())
    assert exc_info.value.detail["reason"] == "withdrawn"


async def test_unknown_status_is_denied_fail_closed():
    """Any status other than 'active' must DENY — not just 'withdrawn'/'expired' (fail-closed allowlist)."""
    port = _FakeConsentPort(record=_make_record(status="pending"))
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_make_action())
    assert exc_info.value.detail["reason"] == "invalid"


async def test_port_error_is_denied_fail_closed():
    """Any port exception must result in DENY (F-03)."""
    port = _FakeConsentPort(raise_exc=True)
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_make_action())
    assert exc_info.value.detail["reason"] == "error"


async def test_inner_not_called_when_consent_denied():
    """The inner evaluator must NOT run when consent is denied."""
    called = []

    class _Spy:
        async def evaluate(self, action: Action) -> EvaluationResult:
            called.append(True)
            return EvaluationResult(decision=Decision.ALLOW, policy_versions=())

    port = _FakeConsentPort(record=None)
    engine = ConsentEngine(consent_port=port, inner=_Spy())
    with pytest.raises(ConsentDeniedError):
        await engine.evaluate(_make_action())
    assert not called, "Inner evaluator was called despite missing consent"


# ── Replay-safety (F-09) ──────────────────────────────────────────────────────


async def test_consent_state_is_json_safe():
    """consent_state must be serialisable (no datetime objects)."""
    import json

    port = _FakeConsentPort(record=_make_record())
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    json.dumps(result.metadata["consent_state"])  # must not raise


async def test_consent_state_snapshot_reflects_record_fields():
    record = _make_record(status="active", purpose="ai_inference")
    port = _FakeConsentPort(record=record)
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(_make_action())
    snap = result.metadata["consent_state"]
    assert snap["status"] == "active"
    assert snap["purpose"] == "ai_inference"
    assert snap["subject_id"] == "alice"


# ── Purpose handling ─────────────────────────────────────────────────────────


async def test_default_purpose_ai_inference_when_not_in_payload():
    """Action without consent_purpose key defaults to ai_inference."""
    action = Action(
        id=ActionId("act-2"),
        type="test.action",
        payload={},  # no consent_purpose key
        actor=Actor(id=ActorId("alice"), tenant=TENANT),
        tenant=TENANT,
        idempotency_key=IdempotencyKey("key-2"),
    )
    port = _FakeConsentPort(record=_make_record(purpose="ai_inference"))
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    result = await engine.evaluate(action)
    assert result.decision == Decision.ALLOW
    assert port.calls[0]["purpose"] == "ai_inference"


async def test_purpose_from_payload_used_in_lookup():
    action = _make_action(purpose="loan_evaluation")
    port = _FakeConsentPort(record=_make_record(purpose="loan_evaluation"))
    engine = ConsentEngine(consent_port=port, inner=_OKInner())
    await engine.evaluate(action)
    assert port.calls[0]["purpose"] == "loan_evaluation"
