"""K·09 Fairness — computation engine.

Invariants (from the assurance skill contract):
- NEVER re-call a model; all inputs come from recorded LedgerEntry projections.
- ALWAYS deterministic: same recorded inputs → same metrics.
- NEVER block a live action; this runs as an async sweep.
- NEVER mutate a sealed ledger entry; outputs are new records only.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from quaicu.core.fairness.model import DecisionRecord, FairnessDelta, FairnessMetrics

_DENY_DECISIONS: frozenset[str] = frozenset({"deny"})


def compute_fairness_metrics(
    records: list[DecisionRecord],
    group_key: str,
    tenant_id: str,
    model_id: str | None = None,
) -> FairnessMetrics:
    """Compute per-group deny rates over a list of recorded decisions.

    If ``records`` is empty, returns a FairnessMetrics with zero counts and no
    group rates — the caller should treat this as "insufficient data" and
    withhold the signal rather than fabricating metrics.
    """
    group_total: dict[str, int] = defaultdict(int)
    group_deny: dict[str, int] = defaultdict(int)

    for rec in records:
        if rec.tenant_id != tenant_id:
            continue
        if model_id is not None and rec.model_id != model_id:
            continue
        group_total[rec.group_value] += 1
        if rec.decision in _DENY_DECISIONS:
            group_deny[rec.group_value] += 1

    group_rates: dict[str, float] = {
        g: group_deny[g] / group_total[g] for g in group_total if group_total[g] > 0
    }

    return FairnessMetrics(
        tenant_id=tenant_id,
        group_key=group_key,
        group_rates=group_rates,
        group_counts=dict(group_total),
        total_decisions=sum(group_total.values()),
        model_id=model_id,
        computed_at=datetime.now(tz=timezone.utc),
    )


def compute_fairness_delta(
    active: FairnessMetrics,
    candidate: FairnessMetrics,
    threshold: float = 0.05,
) -> FairnessDelta:
    """Compute the delta between active and candidate policy decision distributions.

    The delta is computed as |active_rate − candidate_rate| for each group present
    in either distribution. Missing groups default to 0.0.
    """
    all_groups = set(active.group_rates) | set(candidate.group_rates)
    deltas: dict[str, float] = {}
    for g in all_groups:
        a = active.group_rates.get(g, 0.0)
        c = candidate.group_rates.get(g, 0.0)
        deltas[g] = abs(a - c)

    max_delta = max(deltas.values(), default=0.0)
    groups_above = tuple(sorted(g for g, d in deltas.items() if d > threshold))

    return FairnessDelta(
        tenant_id=active.tenant_id,
        group_key=active.group_key,
        active_rates=dict(active.group_rates),
        candidate_rates=dict(candidate.group_rates),
        max_delta=max_delta,
        groups_above_threshold=groups_above,
        threshold=threshold,
        computed_at=datetime.now(tz=timezone.utc),
    )
