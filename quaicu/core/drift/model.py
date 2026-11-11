"""K·10 Drift — domain models.

Drift is measured against a recorded baseline using Population Stability Index (PSI).
All computation is deterministic given recorded inputs (F-09). Breaches route to K·12.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class DriftBaseline:
    """A recorded reference distribution for a single input feature of a model.

    ``buckets`` maps discrete value buckets (e.g. ``"0-10"``, ``"10-20"``) to their
    proportion (must sum to 1.0). Recorded at a fixed point in time; never updated
    in place (create a new baseline to replace it).
    """

    tenant_id: str
    model_id: str
    feature_key: str
    buckets: Mapping[str, float] = field(default_factory=dict)
    total_samples: int = 0
    recorded_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DriftMeasure:
    """Result of comparing a current input distribution against the baseline.

    ``psi_score`` (Population Stability Index): < 0.1 stable, 0.1–0.25 monitor, > 0.25 breach.
    The threshold is configurable; the default follows PSI convention (0.1 for monitoring,
    0.25 for breach), but the caller may tighten it per-tenant.
    """

    tenant_id: str
    model_id: str
    feature_key: str
    psi_score: float
    is_breach: bool
    threshold: float
    baseline_recorded_at: datetime | None = None
    measured_at: datetime | None = None
    current_buckets: Mapping[str, float] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DriftBreach:
    """Emitted when drift exceeds threshold.

    Callers must route this to K·12 Incident. The breach is deterministic — same
    inputs always produce the same breach record (F-09).
    """

    tenant_id: str
    model_id: str
    feature_key: str
    psi_score: float
    threshold: float
    detected_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
