"""Unit tests for K·11 Explainability engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.explain.engine import derive_explanation
from quaicu.core.explain.model import Explanation
from quaicu.core.types import (
    ActionId,
    ActorId,
    Decision,
    LedgerEntry,
    TenantId,
)

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = TenantId("bank-a")


def _entry(
    decision: Decision = Decision.ALLOW,
    policy_versions: tuple[str, ...] = ("pol-1:v2",),
    recorded_result: dict | None = None,
    recorded_outputs: dict | None = None,
    approver: str | None = None,
    consent_state: dict | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=1,
        tenant=TENANT,
        action_id=ActionId("act-42"),
        action_type="ciro.ifrs9.stage_transition",
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=policy_versions,
        leaf_hash=b"\x00" * 32,
        sealed_at=NOW,
        approver=approver,
        consent_state=consent_state or {},
        recorded_result=recorded_result if recorded_result is not None else {"stage": 2},
        recorded_outputs=recorded_outputs if recorded_outputs is not None else {"model": "score=0.87"},
    )


# ── Happy path ────────────────────────────────────────────────────────────────────


def test_basic_explanation_derivable():
    expl = derive_explanation(_entry())
    assert expl.derivable is True


def test_action_id_preserved():
    expl = derive_explanation(_entry())
    assert expl.action_id == "act-42"


def test_tenant_id_preserved():
    expl = derive_explanation(_entry())
    assert expl.tenant_id == str(TENANT)


def test_decision_preserved():
    expl = derive_explanation(_entry(decision=Decision.DENY))
    assert expl.decision == "deny"


def test_policy_versions_preserved():
    expl = derive_explanation(_entry(policy_versions=("pol-1:v2", "pol-2:v1")))
    assert expl.policy_versions == ("pol-1:v2", "pol-2:v1")


def test_recorded_inputs_populated():
    expl = derive_explanation(_entry(recorded_result={"stage": 2, "exposure": 5000}))
    assert expl.recorded_inputs == {"stage": 2, "exposure": 5000}


def test_recorded_outputs_populated():
    expl = derive_explanation(_entry(recorded_outputs={"score": 0.87}))
    assert expl.recorded_outputs == {"score": 0.87}


def test_approver_captured():
    expl = derive_explanation(_entry(approver="user:alice"))
    assert expl.approver == "user:alice"


def test_consent_state_captured():
    expl = derive_explanation(_entry(consent_state={"purpose": "credit_scoring"}))
    assert expl.consent_state == {"purpose": "credit_scoring"}


def test_explanation_text_contains_decision():
    expl = derive_explanation(_entry(decision=Decision.DENY))
    assert "deny" in expl.explanation_text


def test_explanation_text_contains_action_type():
    expl = derive_explanation(_entry())
    assert "ciro.ifrs9.stage_transition" in expl.explanation_text


def test_explanation_text_contains_policy_versions():
    expl = derive_explanation(_entry(policy_versions=("pol-99:v1",)))
    assert "pol-99:v1" in expl.explanation_text


def test_explanation_text_contains_approver():
    expl = derive_explanation(_entry(approver="role:risk_head"))
    assert "risk_head" in expl.explanation_text


def test_derived_at_set():
    expl = derive_explanation(_entry())
    assert expl.derived_at is not None


# ── Insufficient data → not derivable ────────────────────────────────────────────


def test_no_recorded_data_not_derivable():
    entry = _entry(recorded_result={}, recorded_outputs={}, policy_versions=())
    expl = derive_explanation(entry)
    assert expl.derivable is False


def test_insufficient_data_explanation_text_says_so():
    entry = _entry(recorded_result={}, recorded_outputs={}, policy_versions=())
    expl = derive_explanation(entry)
    assert "insufficient" in expl.explanation_text.lower()


def test_partial_recorded_data_still_derivable():
    # Has policy_versions even if recorded_result empty → derivable
    entry = _entry(recorded_result={}, recorded_outputs={}, policy_versions=("pol-1:v1",))
    expl = derive_explanation(entry)
    assert expl.derivable is True


# ── Replay-safety (F-09) ─────────────────────────────────────────────────────────


def test_explanation_is_frozen():
    expl = derive_explanation(_entry())
    assert isinstance(expl, Explanation)
    # Frozen dataclass: cannot be mutated
    with pytest.raises((AttributeError, TypeError)):
        expl.decision = "deny"  # type: ignore[misc]


def test_same_entry_same_explanation():
    e = _entry()
    expl1 = derive_explanation(e, requested_at=NOW)
    expl2 = derive_explanation(e, requested_at=NOW)
    assert expl1.decision == expl2.decision
    assert expl1.policy_versions == expl2.policy_versions
    assert expl1.recorded_inputs == expl2.recorded_inputs
