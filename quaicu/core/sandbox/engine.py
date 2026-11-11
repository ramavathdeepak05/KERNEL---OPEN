"""K·13 Sandbox — counterfactual replay engine.

Rules:
- NEVER re-call a model. Use the recorded_outputs from each LedgerEntry (F-09).
- NEVER write to the production ledger or trigger real effects. All results go to
  an in-process shadow list (the caller's responsibility to discard).
- Decisions are re-derived by calling the candidate policy evaluator with the
  recorded action payload and recorded outputs — same inputs, different policy.
- This is what powers K·01's mandatory backtest gate (F-10).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

from quaicu.core.sandbox.model import SandboxDecision, SandboxRun
from quaicu.core.types import LedgerEntry


class CandidateEvaluator(Protocol):
    """Callable that evaluates a recorded action payload against the candidate policy.

    Must be deterministic and side-effect-free. Receives the recorded payload, recorded outputs,
    and the recorded actor identity (id + roles) so no model re-call is needed and policies that
    gate on the actor can be faithfully replayed (``actor_id`` / ``actor_roles`` are sealed on the
    ``LedgerEntry`` — see ADR-0006). Returns the candidate decision string.
    """

    def __call__(
        self,
        action_type: str,
        payload: dict[str, Any],
        recorded_outputs: dict[str, Any],
        actor_id: str,
        actor_roles: tuple[str, ...],
    ) -> str: ...


def run_counterfactual_backtest(
    *,
    entries: list[LedgerEntry],
    candidate_evaluator: CandidateEvaluator,
    policy_id: str,
    policy_version: str,
    tenant_id: str,
) -> tuple[SandboxRun, list[SandboxDecision]]:
    """Re-evaluate a list of sealed LedgerEntries against a candidate policy.

    Returns a (SandboxRun, [SandboxDecision]) pair. The shadow decisions are returned
    to the caller — nothing is written to the production ledger.

    Only entries matching ``tenant_id`` are evaluated; cross-tenant entries are skipped
    (F-07). ``candidate_evaluator`` must not call the model — it receives recorded outputs.
    """
    shadow_decisions: list[SandboxDecision] = []
    flipped = 0

    for entry in entries:
        if str(entry.tenant) != tenant_id:
            continue  # never cross tenant boundaries

        candidate_decision = candidate_evaluator(
            entry.action_type,
            dict(entry.recorded_result),
            dict(entry.recorded_outputs),
            str(entry.actor_id),
            tuple(entry.actor_roles),
        )
        active_decision = entry.decision.value
        did_flip = candidate_decision != active_decision
        if did_flip:
            flipped += 1

        shadow_decisions.append(
            SandboxDecision(
                action_id=str(entry.action_id),
                tenant_id=str(entry.tenant),
                active_decision=active_decision,
                candidate_decision=candidate_decision,
                flipped=did_flip,
                policy_version_used=policy_version,
                recorded_outputs_used=dict(entry.recorded_outputs),
            )
        )

    total = len(shadow_decisions)
    flip_rate = flipped / total if total > 0 else 0.0

    run = SandboxRun(
        run_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        policy_id=policy_id,
        policy_version=policy_version,
        run_type="backtest",
        ledger_entries_evaluated=total,
        decisions_flipped=flipped,
        decisions_unchanged=total - flipped,
        flip_rate=flip_rate,
        ran_at=datetime.now(tz=timezone.utc),
    )
    return run, shadow_decisions
