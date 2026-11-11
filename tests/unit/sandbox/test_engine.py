"""Unit tests for K·13 Sandbox counterfactual backtest engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.sandbox.engine import run_counterfactual_backtest
from quaicu.core.sandbox.model import SandboxRun
from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = "bank-a"
OTHER_TENANT = "bank-b"


def _entry(
    action_id: str = "act-1",
    decision: Decision = Decision.ALLOW,
    tenant: str = TENANT,
    recorded_result: dict | None = None,
    recorded_outputs: dict | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=1,
        tenant=TenantId(tenant),
        action_id=ActionId(action_id),
        action_type="ciro.ifrs9.stage_transition",
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=("pol-1:v1",),
        leaf_hash=b"\x00" * 32,
        sealed_at=NOW,
        recorded_result=recorded_result or {"stage": 2},
        recorded_outputs=recorded_outputs or {"score": 0.87},
    )


def _always_allow(action_type, payload, recorded_outputs, actor_id, actor_roles) -> str:
    return "allow"


def _always_deny(action_type, payload, recorded_outputs, actor_id, actor_roles) -> str:
    return "deny"


def _same_as_recorded(action_type, payload, recorded_outputs, actor_id, actor_roles) -> str:
    return "allow"


# ── Happy path ────────────────────────────────────────────────────────────────────


def test_backtest_returns_run_and_decisions():
    entries = [_entry(decision=Decision.DENY)]
    run, decisions = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_always_allow,
        policy_id="pol-candidate",
        policy_version="v2",
        tenant_id=TENANT,
    )
    assert isinstance(run, SandboxRun)
    assert isinstance(decisions, list)
    assert len(decisions) == 1


def test_flipped_decision_detected():
    entries = [_entry(decision=Decision.DENY)]
    _, decisions = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_always_allow,
        policy_id="pol",
        policy_version="v2",
        tenant_id=TENANT,
    )
    assert decisions[0].flipped is True
    assert decisions[0].active_decision == "deny"
    assert decisions[0].candidate_decision == "allow"


def test_unchanged_decision_not_flipped():
    entries = [_entry(decision=Decision.ALLOW)]
    _, decisions = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_always_allow,
        policy_id="pol",
        policy_version="v2",
        tenant_id=TENANT,
    )
    assert decisions[0].flipped is False


def test_flip_rate_computed_correctly():
    entries = [
        _entry("act-1", Decision.DENY),
        _entry("act-2", Decision.ALLOW),
        _entry("act-3", Decision.DENY),
    ]
    run, _ = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_always_allow,  # deny→allow for 2, allow→allow unchanged
        policy_id="pol",
        policy_version="v2",
        tenant_id=TENANT,
    )
    assert run.decisions_flipped == 2
    assert run.decisions_unchanged == 1
    assert run.flip_rate == pytest.approx(2 / 3)


def test_run_metadata_preserved():
    run, _ = run_counterfactual_backtest(
        entries=[_entry()],
        candidate_evaluator=_always_allow,
        policy_id="my-policy",
        policy_version="v99",
        tenant_id=TENANT,
    )
    assert run.policy_id == "my-policy"
    assert run.policy_version == "v99"
    assert run.tenant_id == TENANT
    assert run.run_type == "backtest"


def test_run_id_assigned():
    run, _ = run_counterfactual_backtest(
        entries=[], candidate_evaluator=_always_allow,
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert run.run_id != ""


def test_empty_entries_zero_counts():
    run, decisions = run_counterfactual_backtest(
        entries=[], candidate_evaluator=_always_allow,
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert run.ledger_entries_evaluated == 0
    assert run.decisions_flipped == 0
    assert run.flip_rate == 0.0
    assert decisions == []


# ── Tenant isolation (F-07) ───────────────────────────────────────────────────────


def test_cross_tenant_entries_excluded():
    entries = [
        _entry("act-1", tenant=TENANT),
        _entry("act-2", tenant=OTHER_TENANT),
    ]
    run, decisions = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_always_allow,
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert run.ledger_entries_evaluated == 1
    assert all(d.tenant_id == TENANT for d in decisions)


# ── Recorded outputs used (F-09 — no model re-call) ──────────────────────────────


def test_recorded_outputs_passed_to_evaluator():
    received_outputs = []

    def capture_evaluator(action_type, payload, recorded_outputs, actor_id, actor_roles):
        received_outputs.append(dict(recorded_outputs))
        return "allow"

    entries = [_entry(recorded_outputs={"score": 0.95})]
    run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=capture_evaluator,
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert received_outputs[0] == {"score": 0.95}


def test_sandbox_decision_captures_policy_version():
    _, decisions = run_counterfactual_backtest(
        entries=[_entry()],
        candidate_evaluator=_always_allow,
        policy_id="p", policy_version="v-candidate",
        tenant_id=TENANT,
    )
    assert decisions[0].policy_version_used == "v-candidate"


def test_ran_at_set():
    run, _ = run_counterfactual_backtest(
        entries=[], candidate_evaluator=_always_allow,
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert run.ran_at is not None
