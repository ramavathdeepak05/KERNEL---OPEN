"""K·10 Drift — computation engine.

Uses Population Stability Index (PSI) as the drift metric.
PSI = Σ (current_i − baseline_i) × ln(current_i / baseline_i)

Rules:
  PSI < 0.1   → stable
  0.1 ≤ PSI < 0.25 → monitor
  PSI ≥ 0.25  → breach (K·12 incident)

Invariants:
- NEVER re-call a model; compute only from recorded inputs.
- ALWAYS deterministic: same recorded inputs + same baseline → same PSI.
- On breach, the caller must raise a K·12 incident; this layer computes, does not side-effect.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from quaicu.core.drift.model import DriftBaseline, DriftBreach, DriftMeasure

_EPSILON = 1e-9  # avoid ln(0)


def compute_psi(
    baseline: Mapping[str, float],
    current: Mapping[str, float],
) -> float:
    """Compute Population Stability Index between baseline and current distributions.

    Both dicts must map bucket labels to proportions. Missing buckets default to epsilon
    (not 0.0) to avoid ln(0). Input proportions need not sum to exactly 1.0 — they are
    re-normalized internally.
    """

    all_keys = set(baseline) | set(current)
    if not all_keys:
        return 0.0

    baseline_total = sum(baseline.values()) or 1.0
    current_total = sum(current.values()) or 1.0

    psi = 0.0
    for key in all_keys:
        b = (baseline.get(key, 0.0) / baseline_total) + _EPSILON
        c = (current.get(key, 0.0) / current_total) + _EPSILON
        psi += (c - b) * math.log(c / b)

    return round(psi, 9)


def _bucket_records(
    records: list[dict[str, Any]],
    feature_key: str,
    bins: list[float],
) -> dict[str, float]:
    """Bucket numeric feature values and return proportions.

    ``bins`` is a sorted list of upper-bounds (the last bucket catches everything above
    ``bins[-1]``). Returns a dict of ``"<bin_label>"`` → proportion.
    """
    labels = [f"≤{b}" for b in bins] + [f">{bins[-1]}"]
    counts: dict[str, int] = defaultdict(int)

    for rec in records:
        val = rec.get(feature_key)
        if val is None:
            continue
        try:
            fval = float(val)
        except (TypeError, ValueError):
            continue
        placed = False
        for i, upper in enumerate(bins):
            if fval <= upper:
                counts[labels[i]] += 1
                placed = True
                break
        if not placed:
            counts[labels[-1]] += 1

    total = sum(counts.values()) or 1
    return {k: v / total for k, v in counts.items()}


def compute_drift_measure(
    baseline: DriftBaseline,
    current_records: list[dict[str, Any]],
    bins: list[float] | None = None,
    threshold: float = 0.1,
) -> DriftMeasure:
    """Compute a drift measure from recorded inputs versus a recorded baseline.

    ``current_records`` is a list of recorded input dicts (e.g. action payloads).
    ``bins`` is used only when the current distribution must be built from raw records;
    if ``current_records`` contains pre-bucketed dicts (keyed by the same bucket labels as
    the baseline), ``bins`` may be omitted.

    Returns a DriftMeasure. The caller is responsible for checking ``is_breach`` and
    raising a K·12 incident accordingly.
    """
    if bins is not None:
        current_dist = _bucket_records(current_records, baseline.feature_key, bins)
    else:
        # Treat current_records as pre-bucketed: each record is {feature_key: bucket_label}
        counts: dict[str, int] = defaultdict(int)
        for rec in current_records:
            label = rec.get(baseline.feature_key)
            if label is not None:
                counts[str(label)] += 1
        total = sum(counts.values()) or 1
        current_dist = {k: v / total for k, v in counts.items()}

    psi = compute_psi(dict(baseline.buckets), current_dist)
    is_breach = psi >= threshold

    return DriftMeasure(
        tenant_id=baseline.tenant_id,
        model_id=baseline.model_id,
        feature_key=baseline.feature_key,
        psi_score=psi,
        is_breach=is_breach,
        threshold=threshold,
        baseline_recorded_at=baseline.recorded_at,
        measured_at=datetime.now(tz=timezone.utc),
        current_buckets=current_dist,
    )


def make_breach(measure: DriftMeasure) -> DriftBreach:
    """Construct a DriftBreach from a DriftMeasure that has ``is_breach=True``."""
    return DriftBreach(
        tenant_id=measure.tenant_id,
        model_id=measure.model_id,
        feature_key=measure.feature_key,
        psi_score=measure.psi_score,
        threshold=measure.threshold,
        detected_at=measure.measured_at,
    )
