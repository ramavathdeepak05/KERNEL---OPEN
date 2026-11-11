"""Unit tests for K·09 Fairness engine."""

from __future__ import annotations

import pytest

from quaicu.core.fairness.engine import compute_fairness_delta, compute_fairness_metrics
from quaicu.core.fairness.model import DecisionRecord, FairnessMetrics

TENANT = "bank-a"


def _rec(decision: str, group: str, model_id: str = "gpt4o") -> DecisionRecord:
    return DecisionRecord(
        action_id="act-1",
        tenant_id=TENANT,
        decision=decision,
        group_value=group,
        model_id=model_id,
    )


# ── compute_fairness_metrics ─────────────────────────────────────────────────────


def test_all_allowed_deny_rate_zero():
    records = [_rec("allow", "A"), _rec("allow", "A"), _rec("allow", "B")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.group_rates.get("A", 0.0) == 0.0
    assert m.group_rates.get("B", 0.0) == 0.0


def test_all_denied_deny_rate_one():
    records = [_rec("deny", "A"), _rec("deny", "A")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.group_rates["A"] == 1.0


def test_mixed_deny_rate():
    records = [_rec("deny", "A"), _rec("allow", "A")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.group_rates["A"] == 0.5


def test_multiple_groups_computed_independently():
    records = [
        _rec("deny", "high"),
        _rec("deny", "high"),
        _rec("allow", "low"),
    ]
    m = compute_fairness_metrics(records, "risk_band", TENANT)
    assert m.group_rates["high"] == 1.0
    assert m.group_rates["low"] == 0.0


def test_total_decisions_count():
    records = [_rec("allow", "A"), _rec("deny", "B"), _rec("allow", "B")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.total_decisions == 3


def test_cross_tenant_records_excluded():
    records = [
        _rec("deny", "A"),
        DecisionRecord(action_id="x", tenant_id="other-bank", decision="allow", group_value="A"),
    ]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.total_decisions == 1


def test_model_id_filter():
    records = [
        _rec("deny", "A", model_id="gpt4o"),
        _rec("allow", "A", model_id="llama3"),
    ]
    m = compute_fairness_metrics(records, "band", TENANT, model_id="gpt4o")
    assert m.total_decisions == 1
    assert m.group_rates["A"] == 1.0


def test_empty_records_returns_zero_total():
    m = compute_fairness_metrics([], "band", TENANT)
    assert m.total_decisions == 0
    assert m.group_rates == {} or len(m.group_rates) == 0


def test_require_approval_not_counted_as_deny():
    records = [_rec("require_approval", "A"), _rec("allow", "A")]
    m = compute_fairness_metrics(records, "band", TENANT)
    assert m.group_rates["A"] == 0.0


def test_group_key_preserved_in_metrics():
    records = [_rec("deny", "X")]
    m = compute_fairness_metrics(records, "credit_band", TENANT)
    assert m.group_key == "credit_band"


def test_tenant_id_preserved_in_metrics():
    m = compute_fairness_metrics([], "band", TENANT)
    assert m.tenant_id == TENANT


# ── compute_fairness_delta ────────────────────────────────────────────────────────


def _metrics(rates: dict[str, float]) -> FairnessMetrics:
    return FairnessMetrics(
        tenant_id=TENANT,
        group_key="band",
        group_rates=rates,
        group_counts={g: 10 for g in rates},
        total_decisions=sum(10 for _ in rates),
    )


def test_no_delta_identical_distributions():
    active = _metrics({"A": 0.3, "B": 0.3})
    delta = compute_fairness_delta(active, active)
    assert delta.max_delta == 0.0
    assert delta.groups_above_threshold == ()


def test_delta_above_threshold_flagged():
    active = _metrics({"A": 0.1})
    candidate = _metrics({"A": 0.4})
    delta = compute_fairness_delta(active, candidate, threshold=0.05)
    assert "A" in delta.groups_above_threshold
    assert delta.max_delta == pytest.approx(0.3, abs=1e-9)


def test_delta_below_threshold_not_flagged():
    active = _metrics({"A": 0.30})
    candidate = _metrics({"A": 0.33})
    delta = compute_fairness_delta(active, candidate, threshold=0.05)
    assert delta.groups_above_threshold == ()


def test_missing_group_in_candidate_defaults_to_zero():
    active = _metrics({"A": 0.5, "B": 0.0})
    candidate = _metrics({"A": 0.5})  # B missing
    delta = compute_fairness_delta(active, candidate, threshold=0.01)
    # B: |0.0 - 0.0| = 0.0; A: |0.5 - 0.5| = 0.0
    assert delta.max_delta == 0.0


def test_new_group_in_candidate_contributes_delta():
    active = _metrics({"A": 0.2})
    candidate = _metrics({"A": 0.2, "B": 0.5})
    delta = compute_fairness_delta(active, candidate, threshold=0.01)
    assert "B" in delta.groups_above_threshold


def test_delta_threshold_preserved_in_output():
    active = _metrics({"A": 0.0})
    candidate = _metrics({"A": 0.0})
    delta = compute_fairness_delta(active, candidate, threshold=0.12)
    assert delta.threshold == 0.12
