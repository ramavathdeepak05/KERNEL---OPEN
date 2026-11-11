"""K·13 Sandbox conformance tests — spec-derived golden cases.

Invariants tested:
  - F-09: uses recorded model outputs, never re-calls the model.
  - F-07: cross-tenant entries excluded from backtest.
  - F-10: flip_rate and decisions_flipped are available for K·01 impact report.
  - Zero production side effects: all decisions go to shadow decisions list only.
  - Deterministic: same entries + same evaluator → same run result.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.sandbox.engine import run_counterfactual_backtest
from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = "ciro-bank"


def _entry(action_id: str, decision: Decision, tenant: str = TENANT) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=1,
        tenant=TenantId(tenant),
        action_id=ActionId(action_id),
        action_type="ciro.ifrs9.stage_transition",
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=("ifrs9-v2",),
        leaf_hash=b"\x00" * 32,
        sealed_at=NOW,
        recorded_outputs={"score": 0.87},
    )


@pytest.mark.conformance
def test_backtest_uses_recorded_outputs_not_live_model():
    """F-09: evaluator receives recorded_outputs, not a live model call."""
    received = []

    def capture(action_type, payload, recorded_outputs, actor_id, actor_roles):
        received.append(recorded_outputs)
        return "allow"

    entries = [_entry("act-1", Decision.ALLOW)]
    run_counterfactual_backtest(
        entries=entries, candidate_evaluator=capture,
        policy_id="p", policy_version="v2", tenant_id=TENANT,
    )
    assert received[0] == {"score": 0.87}


@pytest.mark.conformance
def test_cross_tenant_entries_excluded_from_backtest():
    """F-07: only the target tenant's entries are evaluated."""
    entries = [
        _entry("act-a", Decision.ALLOW, tenant=TENANT),
        _entry("act-b", Decision.DENY, tenant="evil-bank"),
    ]
    run, decisions = run_counterfactual_backtest(
        entries=entries, candidate_evaluator=lambda t, p, o, a, r: "allow",
        policy_id="p", policy_version="v2", tenant_id=TENANT,
    )
    assert run.ledger_entries_evaluated == 1
    assert all(d.tenant_id == TENANT for d in decisions)


@pytest.mark.conformance
def test_flip_rate_available_for_impact_report():
    """F-10: flip_rate and decisions_flipped feed the K·01 impact report."""
    entries = [
        _entry("act-1", Decision.DENY),
        _entry("act-2", Decision.DENY),
        _entry("act-3", Decision.ALLOW),
    ]
    run, _ = run_counterfactual_backtest(
        entries=entries, candidate_evaluator=lambda t, p, o, a, r: "allow",
        policy_id="p", policy_version="v2", tenant_id=TENANT,
    )
    assert run.decisions_flipped == 2
    assert run.flip_rate == pytest.approx(2 / 3)


@pytest.mark.conformance
def test_backtest_is_deterministic():
    """F-09: same entries + same evaluator → same flip counts every run."""
    entries = [_entry("act-1", Decision.DENY), _entry("act-2", Decision.ALLOW)]
    kwargs = dict(
        entries=entries, candidate_evaluator=lambda t, p, o, a, r: "allow",
        policy_id="p", policy_version="v2", tenant_id=TENANT,
    )
    run1, _ = run_counterfactual_backtest(**kwargs)
    run2, _ = run_counterfactual_backtest(**kwargs)
    assert run1.decisions_flipped == run2.decisions_flipped
    assert run1.flip_rate == run2.flip_rate


@pytest.mark.conformance
def test_backtest_run_type_is_backtest():
    run, _ = run_counterfactual_backtest(
        entries=[], candidate_evaluator=lambda t, p, o, a, r: "allow",
        policy_id="p", policy_version="v1", tenant_id=TENANT,
    )
    assert run.run_type == "backtest"
