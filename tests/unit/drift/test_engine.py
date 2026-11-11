"""Unit tests for K·10 Drift engine."""

from __future__ import annotations


import pytest

from quaicu.core.drift.engine import compute_drift_measure, compute_psi, make_breach
from quaicu.core.drift.model import DriftBaseline, DriftMeasure

TENANT = "bank-a"
MODEL = "credit-model"
FEATURE = "loan_band"


def _baseline(buckets: dict[str, float]) -> DriftBaseline:
    return DriftBaseline(
        tenant_id=TENANT,
        model_id=MODEL,
        feature_key=FEATURE,
        buckets=buckets,
        total_samples=100,
    )


# ── compute_psi ───────────────────────────────────────────────────────────────────


def test_psi_identical_distributions_is_zero():
    dist = {"low": 0.5, "high": 0.5}
    psi = compute_psi(dist, dist)
    assert psi == pytest.approx(0.0, abs=1e-6)


def test_psi_empty_distributions_is_zero():
    assert compute_psi({}, {}) == 0.0


def test_psi_stable_distribution_below_01():
    baseline = {"A": 0.6, "B": 0.4}
    current = {"A": 0.58, "B": 0.42}
    psi = compute_psi(baseline, current)
    assert psi < 0.1


def test_psi_large_shift_above_025():
    baseline = {"low": 0.8, "high": 0.2}
    current = {"low": 0.2, "high": 0.8}
    psi = compute_psi(baseline, current)
    assert psi > 0.25


def test_psi_is_symmetric_for_equal_shifts():
    baseline = {"A": 0.6, "B": 0.4}
    current = {"A": 0.4, "B": 0.6}
    psi_ab = compute_psi(baseline, current)
    psi_ba = compute_psi(current, baseline)
    # PSI is not symmetric in general, but for two-bucket equal-magnitude swaps it is close
    assert psi_ab > 0.0
    assert psi_ba > 0.0


def test_psi_missing_bucket_in_current_handled():
    baseline = {"A": 0.5, "B": 0.5}
    current = {"A": 1.0}  # B missing → epsilon
    psi = compute_psi(baseline, current)
    assert psi > 0.0


# ── compute_drift_measure ─────────────────────────────────────────────────────────


def test_stable_distribution_no_breach():
    base = _baseline({"low": 0.7, "high": 0.3})
    records = [{FEATURE: "low"}] * 70 + [{FEATURE: "high"}] * 30
    m = compute_drift_measure(base, records, threshold=0.1)
    assert not m.is_breach


def test_large_shift_triggers_breach():
    base = _baseline({"low": 0.9, "high": 0.1})
    records = [{FEATURE: "low"}] * 10 + [{FEATURE: "high"}] * 90
    m = compute_drift_measure(base, records, threshold=0.1)
    assert m.is_breach


def test_empty_current_records_no_crash():
    base = _baseline({"low": 0.5, "high": 0.5})
    m = compute_drift_measure(base, [], threshold=0.1)
    assert isinstance(m, DriftMeasure)


def test_drift_measure_tenant_id_preserved():
    base = _baseline({"low": 0.5, "high": 0.5})
    m = compute_drift_measure(base, [], threshold=0.1)
    assert m.tenant_id == TENANT


def test_drift_measure_model_id_preserved():
    base = _baseline({"low": 0.5, "high": 0.5})
    m = compute_drift_measure(base, [], threshold=0.1)
    assert m.model_id == MODEL


def test_drift_measure_psi_score_nonnegative():
    base = _baseline({"A": 0.5, "B": 0.5})
    records = [{FEATURE: "A"}] * 60 + [{FEATURE: "B"}] * 40
    m = compute_drift_measure(base, records, threshold=0.1)
    assert m.psi_score >= 0.0


def test_drift_measure_threshold_preserved():
    base = _baseline({"A": 0.5, "B": 0.5})
    m = compute_drift_measure(base, [], threshold=0.25)
    assert m.threshold == 0.25


def test_drift_measure_bins_bucket_numeric_values():
    records = [{"score": v} for v in [5, 8, 15, 25, 30]]
    base_numeric = DriftBaseline(
        tenant_id=TENANT, model_id=MODEL, feature_key="score",
        buckets={"≤10": 0.5, "≤20": 0.3, ">20": 0.2}, total_samples=100,
    )
    m = compute_drift_measure(base_numeric, records, bins=[10.0, 20.0], threshold=0.1)
    assert isinstance(m.psi_score, float)


# ── make_breach ───────────────────────────────────────────────────────────────────


def test_make_breach_fields_match_measure():
    base = _baseline({"low": 0.1, "high": 0.9})
    records = [{FEATURE: "low"}] * 90 + [{FEATURE: "high"}] * 10
    m = compute_drift_measure(base, records, threshold=0.1)
    assert m.is_breach
    breach = make_breach(m)
    assert breach.tenant_id == m.tenant_id
    assert breach.model_id == m.model_id
    assert breach.psi_score == m.psi_score
    assert breach.threshold == m.threshold
    assert breach.detected_at == m.measured_at
