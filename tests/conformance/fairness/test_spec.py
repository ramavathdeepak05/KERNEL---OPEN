"""K·09 Fairness conformance tests — spec-derived golden cases.

Invariants tested:
  - Fairness metrics computed from recorded decisions only (F-09).
  - Per-tenant isolation: records from tenant B do not affect tenant A's metrics.
  - Fairness delta feeds the K·01 impact report — delta > threshold flags groups.
  - No model re-calls: engine accepts DecisionRecord projections, not live inference.
  - Async sweep: these computations must never appear in the propose→seal hot path.
"""

from __future__ import annotations

import pytest

from quaicu.core.fairness.engine import compute_fairness_delta, compute_fairness_metrics
from quaicu.core.fairness.model import DecisionRecord, FairnessMetrics

TENANT = "ciro-bank"
OTHER_TENANT = "rival-bank"


def _rec(decision: str, group: str, tenant: str = TENANT) -> DecisionRecord:
    return DecisionRecord(
        action_id="act-x",
        tenant_id=tenant,
        decision=decision,
        group_value=group,
    )


@pytest.mark.conformance
def test_deny_rate_computed_from_recorded_decisions():
    """Deny rate = deny_count / total for each group, derived from recordings (F-09)."""
    records = [_rec("deny", "A"), _rec("allow", "A"), _rec("deny", "B"), _rec("deny", "B")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.group_rates["A"] == pytest.approx(0.5)
    assert m.group_rates["B"] == pytest.approx(1.0)


@pytest.mark.conformance
def test_cross_tenant_isolation_in_fairness():
    """Records for tenant B must not pollute tenant A's fairness metrics (F-07)."""
    records = [
        _rec("deny", "A", tenant=TENANT),
        _rec("allow", "A", tenant=OTHER_TENANT),  # must be excluded
    ]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.total_decisions == 1
    assert m.group_rates["A"] == 1.0


@pytest.mark.conformance
def test_fairness_delta_feeds_impact_report():
    """A candidate with higher deny rate for a group produces a non-zero delta."""
    active = FairnessMetrics(
        tenant_id=TENANT, group_key="band",
        group_rates={"high-risk": 0.3, "low-risk": 0.05},
        group_counts={"high-risk": 100, "low-risk": 100},
        total_decisions=200,
    )
    candidate = FairnessMetrics(
        tenant_id=TENANT, group_key="band",
        group_rates={"high-risk": 0.5, "low-risk": 0.04},
        group_counts={"high-risk": 100, "low-risk": 100},
        total_decisions=200,
    )
    delta = compute_fairness_delta(active, candidate, threshold=0.05)
    assert "high-risk" in delta.groups_above_threshold
    assert delta.max_delta == pytest.approx(0.2, abs=1e-9)


@pytest.mark.conformance
def test_empty_decisions_produces_zero_metrics():
    """With no recorded decisions, metrics are empty — no fabricated values."""
    m = compute_fairness_metrics([], "band", TENANT)
    assert m.total_decisions == 0
    assert not m.group_rates  # must not fabricate a deny rate


@pytest.mark.conformance
def test_no_deny_decisions_produces_zero_rates():
    records = [_rec("allow", "A"), _rec("allow", "A"), _rec("require_approval", "B")]
    m = compute_fairness_metrics(records, "band", TENANT)
    for rate in m.group_rates.values():
        assert rate == 0.0


@pytest.mark.conformance
def test_delta_below_threshold_not_flagged_for_impact_report():
    """A small candidate change that stays within threshold should not flag any group."""
    active = FairnessMetrics(
        tenant_id=TENANT, group_key="band",
        group_rates={"A": 0.30}, group_counts={"A": 100}, total_decisions=100,
    )
    candidate = FairnessMetrics(
        tenant_id=TENANT, group_key="band",
        group_rates={"A": 0.32}, group_counts={"A": 100}, total_decisions=100,
    )
    delta = compute_fairness_delta(active, candidate, threshold=0.05)
    assert delta.groups_above_threshold == ()
