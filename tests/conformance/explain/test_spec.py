"""K·11 Explainability conformance tests — spec-derived golden cases.

Invariants tested:
  - Explanation derivable from recorded inputs/results only — no model re-call (F-09).
  - Point-in-time: explanation reflects policies and inputs as recorded, not current.
  - Insufficient recorded data → derivable=False; caller must NOT re-call the model.
  - Explanation attached to audit replay: must carry action_id, policy_versions, decision.
  - Per-tenant: explanation scoped to tenant.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.explain.engine import derive_explanation
from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = TenantId("ciro-bank")


def _entry(
    decision: Decision = Decision.ALLOW,
    policy_versions: tuple[str, ...] = ("ifrs9-v2",),
    recorded_result: dict | None = None,
    recorded_outputs: dict | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=1,
        tenant=TENANT,
        action_id=ActionId("act-99"),
        action_type="ciro.ifrs9.stage_transition",
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=policy_versions,
        leaf_hash=b"\x00" * 32,
        sealed_at=NOW,
        recorded_result=recorded_result if recorded_result is not None else {"stage": 2},
        recorded_outputs=recorded_outputs if recorded_outputs is not None else {"score": 0.87},
    )


@pytest.mark.conformance
def test_explanation_derived_from_recorded_data_only():
    """Explanation must use only sealed entry fields — no model re-call (F-09)."""
    expl = derive_explanation(_entry())
    assert expl.derivable is True
    assert expl.action_id == "act-99"
    assert expl.decision == "allow"


@pytest.mark.conformance
def test_explanation_carries_policy_versions_for_replay():
    """Policy versions are the point-in-time reference for audit replay."""
    expl = derive_explanation(_entry(policy_versions=("ifrs9-v2", "aml-v1")))
    assert "ifrs9-v2" in expl.policy_versions
    assert "aml-v1" in expl.policy_versions


@pytest.mark.conformance
def test_insufficient_recorded_data_sets_derivable_false():
    """When recorded_result and recorded_outputs are empty AND no policy versions,
    the explanation is not fully derivable — the caller must not re-call the model."""
    entry = _entry(recorded_result={}, recorded_outputs={}, policy_versions=())
    expl = derive_explanation(entry)
    assert expl.derivable is False


@pytest.mark.conformance
def test_explanation_tenant_scoped():
    """The Explanation carries the tenant_id from the sealed entry."""
    expl = derive_explanation(_entry())
    assert expl.tenant_id == str(TENANT)


@pytest.mark.conformance
def test_deny_explanation_text_communicates_denial():
    """Denial decisions must be clearly surfaced in the explanation text."""
    expl = derive_explanation(_entry(decision=Decision.DENY))
    assert "deny" in expl.explanation_text.lower()


@pytest.mark.conformance
def test_explanation_is_immutable_audit_record():
    """Explanation is a frozen dataclass — once derived it cannot be mutated."""
    expl = derive_explanation(_entry())
    with pytest.raises((AttributeError, TypeError)):
        expl.decision = "allow"  # type: ignore[misc]
