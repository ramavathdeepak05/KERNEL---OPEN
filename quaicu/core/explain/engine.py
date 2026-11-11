"""K·11 Explainability — derivation engine.

Invariants:
- NEVER re-call a model. The explanation uses only what was sealed in the LedgerEntry.
- ALWAYS point-in-time: the explanation reflects the policies and inputs as they were
  when the action was governed, not as they are now.
- If recorded data is insufficient, set derivable=False and return partial explanation.
  NEVER approximate with a fresh model call to fill gaps.
"""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.core.explain.model import Explanation
from quaicu.core.types import LedgerEntry


def derive_explanation(
    entry: LedgerEntry,
    requested_at: datetime | None = None,
) -> Explanation:
    """Derive a point-in-time explanation from a sealed LedgerEntry.

    Composes ``explanation_text`` from recorded fields: decision, action type,
    actor, policy versions, and recorded result. No model is called.
    """
    now = requested_at or datetime.now(tz=timezone.utc)

    # Determine if we have sufficient recorded data to explain the decision
    has_inputs = bool(entry.recorded_result) or bool(entry.recorded_outputs)
    has_policy = bool(entry.policy_versions)
    derivable = has_inputs or has_policy

    parts: list[str] = [
        f"Action '{entry.action_type}' by actor '{entry.actor_id}' for tenant '{entry.tenant}'",
        f"was decided '{entry.decision.value}' at {entry.sealed_at.isoformat()}.",
    ]

    if entry.policy_versions:
        pv = ", ".join(entry.policy_versions)
        parts.append(f"Policies evaluated: {pv}.")

    if entry.approver:
        parts.append(f"Approved by: {entry.approver}.")

    if entry.consent_state:
        parts.append(f"Consent state: {entry.consent_state}.")

    if entry.recorded_outputs:
        parts.append("Model output was recorded and is available for replay.")

    if not derivable:
        parts.append(
            "Insufficient recorded data to fully explain this decision — "
            "recorded_result and recorded_outputs are both empty."
        )

    return Explanation(
        action_id=str(entry.action_id),
        tenant_id=str(entry.tenant),
        decision=entry.decision.value,
        policy_versions=entry.policy_versions,
        recorded_inputs=dict(entry.recorded_result),
        recorded_outputs=dict(entry.recorded_outputs),
        consent_state=dict(entry.consent_state),
        approver=str(entry.approver) if entry.approver else None,
        explanation_text=" ".join(parts),
        derivable=derivable,
        derived_at=now,
    )
