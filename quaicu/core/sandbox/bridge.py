"""K·13 → K·01 bridge: convert a SandboxRun + optional FairnessDelta into an ImpactReport.

The ImpactReport is the artifact F-10 requires before a REVIEW policy can be ACTIVATED.
This bridge assembles it from the counterfactual replay output without any I/O.

Rules:
- Pure function — no I/O, no async, no imports from delivery or adapters.
- `acknowledged` defaults to False — a human reviewer must set it True via the API.
- `decision_distribution` is derived from flip/unchanged counts as a conservative proxy.
"""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.core.fairness.model import FairnessDelta
from quaicu.core.policy.model import ImpactReport
from quaicu.core.sandbox.model import SandboxRun


def assemble_impact_report(
    run: SandboxRun,
    *,
    reviewed_by: str,
    reviewed_at: datetime | None = None,
    fairness_delta: FairnessDelta | None = None,
    acknowledged: bool = False,
) -> ImpactReport:
    """Assemble a K·01 ImpactReport from a K·13 SandboxRun and optional K·09 FairnessDelta.

    ``decision_distribution`` is a two-bucket approximation: unchanged decisions map to
    ``"allow"`` (they agree with the active policy) and flipped decisions map to ``"deny"``
    (they would change outcome). This is conservative — it treats any flip as a potential
    denial, giving reviewers a worst-case view. The exact per-decision breakdown is available
    in the SandboxDecision list returned by ``run_counterfactual_backtest``.

    ``acknowledged`` defaults to False. The F-10 gate requires True — the reviewer must
    explicitly acknowledge the report (via ``PUT …/impact-report`` or the inline ``activate``
    body) before activation is permitted.
    """
    total = run.ledger_entries_evaluated
    if total == 0:
        distribution: dict[str, float] = {"allow": 1.0}
    else:
        unchanged_rate = run.decisions_unchanged / total
        flipped_rate = run.decisions_flipped / total
        distribution = {}
        if unchanged_rate > 0:
            distribution["allow"] = round(unchanged_rate, 6)
        if flipped_rate > 0:
            distribution["deny"] = round(flipped_rate, 6)
        if not distribution:
            distribution = {"allow": 1.0}

    delta_value = fairness_delta.max_delta if fairness_delta is not None else 0.0

    return ImpactReport(
        policy_id=run.policy_id,
        policy_version=int(run.policy_version) if run.policy_version.isdigit() else 1,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at or datetime.now(tz=timezone.utc),
        decision_distribution=distribution,
        flip_count=run.decisions_flipped,
        fairness_delta=delta_value,
        acknowledged=acknowledged,
    )
