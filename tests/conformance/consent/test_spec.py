"""K·04 conformance tests — spec-derived golden cases.

Tests the invariants from the Deterministic Decision Contract:
  - missing / expired / withdrawn / error → DENY (fail-closed).
  - consent state recorded in EvaluationResult.metadata (replay-safe).
  - per-tenant isolation: each lookup scoped to the requesting tenant.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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

# Relative to the real clock: the engine judges expiry against wall-clock time, so a fixed date
# here turns the default (30-day) consent into an expired one once that date has passed.
NOW = datetime.now(timezone.utc)


class _Inner:
    def __init__(self, decision: Decision = Decision.ALLOW) -> None:
        self._decision = decision

    async def evaluate(self, action: Action) -> EvaluationResult:
        return EvaluationResult(decision=self._decision, policy_versions=("v1",))


class _FakePort:
    def __init__(self, record: ConsentRecord | None = None, raise_exc: bool = False) -> None:
        self._record = record
        self._raise = raise_exc
        self.last_call: dict | None = None

    async def get_consent(self, *, tenant_id: str, subject_id: str, purpose: str):
        self.last_call = {"tenant_id": tenant_id, "subject_id": subject_id}
        if self._raise:
            raise RuntimeError("port down")
        return self._record

    async def record_consent(self, record): ...
    async def withdraw_consent(self, *, tenant_id, subject_id, purpose, withdrawn_at): ...


def _record(status: str = "active", expires_at: datetime | None = None) -> ConsentRecord:
    return ConsentRecord(
        consent_id="c-1",
        tenant_id="t-1",
        subject_id="bob",
        purpose="ai_inference",
        data_categories=("general",),
        status=status,
        granted_at=NOW - timedelta(days=1),
        expires_at=expires_at or (NOW + timedelta(days=30)),
        withdrawn_at=None,
        policy_ref=None,
    )


def _action(tenant: str = "t-1") -> Action:
    return Action(
        id=ActionId("a-1"),
        type="test",
        payload={"consent_purpose": "ai_inference"},
        actor=Actor(id=ActorId("bob"), tenant=TenantId(tenant)),
        tenant=TenantId(tenant),
        idempotency_key=IdempotencyKey("k-1"),
    )


@pytest.mark.conformance
async def test_missing_consent_denies():
    engine = ConsentEngine(consent_port=_FakePort(record=None), inner=_Inner())
    with pytest.raises(ConsentDeniedError):
        await engine.evaluate(_action())


@pytest.mark.conformance
async def test_expired_consent_denies():
    past = NOW - timedelta(seconds=1)
    engine = ConsentEngine(consent_port=_FakePort(record=_record(expires_at=past)), inner=_Inner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_action())
    assert exc_info.value.detail["reason"] == "expired"


@pytest.mark.conformance
async def test_withdrawn_consent_denies():
    engine = ConsentEngine(consent_port=_FakePort(record=_record(status="withdrawn")), inner=_Inner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_action())
    assert exc_info.value.detail["reason"] == "withdrawn"


@pytest.mark.conformance
async def test_port_error_denies_fail_closed():
    """Consent service down → DENY (F-03). Never allow on uncertainty."""
    engine = ConsentEngine(consent_port=_FakePort(raise_exc=True), inner=_Inner())
    with pytest.raises(ConsentDeniedError) as exc_info:
        await engine.evaluate(_action())
    assert exc_info.value.detail["reason"] == "error"


@pytest.mark.conformance
async def test_consent_state_in_evaluation_result_for_replay():
    """Consent state must be sealed into the evaluation result for ledger replay (F-09)."""
    engine = ConsentEngine(consent_port=_FakePort(record=_record()), inner=_Inner())
    result = await engine.evaluate(_action())
    assert "consent_state" in result.metadata
    assert result.metadata["consent_state"]["consent_id"] == "c-1"


@pytest.mark.conformance
async def test_tenant_id_scoped_in_lookup():
    """Consent port must be called with the requesting tenant_id — never cross-tenant."""
    port = _FakePort(record=_record())
    engine = ConsentEngine(consent_port=port, inner=_Inner())
    await engine.evaluate(_action(tenant="t-alpha"))
    assert port.last_call is not None
    assert port.last_call["tenant_id"] == "t-alpha"
