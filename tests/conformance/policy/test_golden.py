"""Conformance — spec §10 golden cases for the IFRS9 loan stage-transition policy.

These tests derive directly from the worked example in the build spec. They are the canonical
acceptance criteria for K·01: if these fail, the engine is not spec-compliant, regardless of
the unit tests passing.

The IFRS9 policy:
  governs: "ciro.ifrs9.stage_transition"
  condition: "payload_to_stage > payload_from_stage && payload_exposure > 5000000"
  decision: require_approval
  approvers: ["role:risk_head"]

Golden inputs (from spec §10):
  1. {to_stage: 2, from_stage: 1, exposure: 7_500_000} → condition TRUE → require_approval
  2. {to_stage: 2, from_stage: 1, exposure: 3_000_000} → exposure false → no match → DENY
  3. {to_stage: 1, from_stage: 2, exposure: 7_500_000} → to_stage < from_stage → false → DENY
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.errors import PolicyNotFoundError
from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ActionId, Actor, ActorId, ApproverRef, Decision, IdempotencyKey, TenantId

TENANT = TenantId("ciro-bank")
IFRS9_CONDITION = "payload_to_stage > payload_from_stage && payload_exposure > 5000000"
IFRS9_APPROVERS: tuple[ApproverRef, ...] = (ApproverRef("role:risk_head"),)


def _build_ifrs9_engine() -> PolicyEngine:
    """Build a `PolicyEngine` with the single IFRS9 stage-transition policy activated."""
    policy = PolicyEnvelope(
        id="ciro.ifrs9.stage_transition",
        version=1,
        governs="ciro.ifrs9.stage_transition",
        scope={"tenant": "*"},
        condition=IFRS9_CONDITION,
        decision=Decision.REQUIRE_APPROVAL,
        approvers=IFRS9_APPROVERS,
        regulatory_refs=("RBI/IFRS9/2024-01",),
        lifecycle=PolicyLifecycle.REVIEW,
    )

    store = PolicyStore()
    stored = store.register(policy)

    report = ImpactReport(
        policy_id=stored.id,
        policy_version=stored.version,
        reviewed_by="reviewer:chief_risk_officer",
        reviewed_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
        decision_distribution={"require_approval": 0.78, "deny": 0.0, "allow": 0.0},
        flip_count=3,
        fairness_delta=0.005,
        acknowledged=True,
    )
    store.activate(stored.id, stored.version, report)
    return PolicyEngine(store)


def _loan_action(*, to_stage: int, from_stage: int, exposure: int) -> Action:
    return Action(
        id=ActionId("act-golden"),
        type="ciro.ifrs9.stage_transition",
        payload={
            "loan_id": "L-4471",
            "from_stage": from_stage,
            "to_stage": to_stage,
            "exposure": exposure,
        },
        actor=Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:risk_analyst",)),
        tenant=TENANT,
        idempotency_key=IdempotencyKey("golden-1"),
    )


@pytest.mark.conformance
async def test_ifrs9_upgrade_above_threshold_requires_approval() -> None:
    """spec §10 case 1: upgrade (1→2) + exposure 7.5M → condition true → require_approval."""
    engine = _build_ifrs9_engine()
    action = _loan_action(to_stage=2, from_stage=1, exposure=7_500_000)
    result = await engine.evaluate(action)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert ApproverRef("role:risk_head") in result.approvers
    assert "ciro.ifrs9.stage_transition@v1" in result.policy_versions


@pytest.mark.conformance
async def test_ifrs9_upgrade_below_threshold_is_denied() -> None:
    """spec §10 case 2: upgrade (1→2) but exposure 3M → exposure clause false → no match → DENY."""
    engine = _build_ifrs9_engine()
    action = _loan_action(to_stage=2, from_stage=1, exposure=3_000_000)
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(action)


@pytest.mark.conformance
async def test_ifrs9_downgrade_is_denied() -> None:
    """spec §10 case 3: downgrade (2→1) → to_stage < from_stage → condition false → DENY."""
    engine = _build_ifrs9_engine()
    action = _loan_action(to_stage=1, from_stage=2, exposure=7_500_000)
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(action)
