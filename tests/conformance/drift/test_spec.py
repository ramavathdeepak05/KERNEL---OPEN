"""K·10 Drift conformance tests — spec-derived golden cases.

Invariants tested:
  - Drift measured against a recorded baseline (no live model calls).
  - Deterministic: same recorded inputs + same baseline → same PSI (F-09).
  - Breach when PSI ≥ threshold; stable when PSI < threshold.
  - Breach must route to K·12 incident (tested via DriftBreach shape, not side-effect).
  - Per-tenant: baseline is scoped to a tenant.
"""

from __future__ import annotations

import pytest

from quaicu.core.drift.engine import compute_drift_measure, compute_psi, make_breach
from quaicu.core.drift.model import DriftBaseline

TENANT = "ciro-bank"
MODEL = "ifrs9-risk-model"
FEATURE = "loan_band"


def _baseline(buckets: dict[str, float]) -> DriftBaseline:
    return DriftBaseline(
        tenant_id=TENANT, model_id=MODEL,
        feature_key=FEATURE, buckets=buckets, total_samples=500,
    )


@pytest.mark.conformance
def test_drift_deterministic_same_inputs_same_psi():
    """F-09: same recorded inputs → same drift measure every time."""
    base = _baseline({"low": 0.6, "high": 0.4})
    records = [{FEATURE: "low"}] * 60 + [{FEATURE: "high"}] * 40
    m1 = compute_drift_measure(base, records)
    m2 = compute_drift_measure(base, records)
    assert m1.psi_score == pytest.approx(m2.psi_score)
    assert m1.is_breach == m2.is_breach


@pytest.mark.conformance
def test_stable_distribution_no_breach():
    """A distribution close to the baseline must not breach (PSI < 0.1)."""
    base = _baseline({"low": 0.7, "medium": 0.2, "high": 0.1})
    records = [{FEATURE: "low"}] * 69 + [{FEATURE: "medium"}] * 21 + [{FEATURE: "high"}] * 10
    m = compute_drift_measure(base, records, threshold=0.1)
    assert not m.is_breach


@pytest.mark.conformance
def test_large_shift_triggers_breach_requires_k12_incident():
    """Severe drift (PSI ≥ threshold) must produce a DriftBreach to route to K·12."""
    base = _baseline({"low": 0.9, "high": 0.1})
    records = [{FEATURE: "low"}] * 10 + [{FEATURE: "high"}] * 90
    m = compute_drift_measure(base, records, threshold=0.1)
    assert m.is_breach
    breach = make_breach(m)
    # DriftBreach carries the fields K·12 needs to log an incident
    assert breach.tenant_id == TENANT
    assert breach.psi_score == m.psi_score
    assert breach.detected_at == m.measured_at


@pytest.mark.conformance
def test_baseline_tenant_scoped():
    """The DriftBaseline is per-tenant; compute preserves tenant_id in the measure."""
    base = _baseline({"A": 0.5, "B": 0.5})
    m = compute_drift_measure(base, [{FEATURE: "A"}] * 100)
    assert m.tenant_id == TENANT


@pytest.mark.conformance
def test_psi_zero_for_identical_distribution():
    """Identical distributions produce PSI = 0.0 (no drift)."""
    dist = {"A": 0.5, "B": 0.5}
    psi = compute_psi(dist, dict(dist))
    assert psi == pytest.approx(0.0, abs=1e-6)
