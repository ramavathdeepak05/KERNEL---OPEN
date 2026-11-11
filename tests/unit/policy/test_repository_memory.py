"""InMemoryPolicyRepository — durable-store stand-in round-trip tests."""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.types import ApproverRef, Decision


def _envelope(
    policy_id: str = "p.test",
    version: int = 1,
    lifecycle: PolicyLifecycle = PolicyLifecycle.REVIEW,
    condition: str = "payload_amount > 1000",
) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=policy_id,
        version=version,
        governs="payments.wire",
        scope={"tenant": "*"},
        condition=condition,
        decision=Decision.REQUIRE_APPROVAL,
        approvers=(ApproverRef("role:risk_head"),),
        regulatory_refs=("RBI-PV-2025",),
        lifecycle=lifecycle,
    )


def _impact(policy_id: str = "p.test", version: int = 1) -> ImpactReport:
    return ImpactReport(
        policy_id=policy_id,
        policy_version=version,
        reviewed_by="reviewer:alice",
        reviewed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        decision_distribution={"allow": 0.7, "require_approval": 0.3},
        flip_count=4,
        fairness_delta=0.01,
        acknowledged=True,
    )


async def test_save_and_load_envelope_round_trip() -> None:
    repo = InMemoryPolicyRepository()
    await repo.save_envelope(_envelope())
    loaded = await repo.load_all()
    assert len(loaded) == 1
    env = loaded[0]
    assert env.id == "p.test"
    assert env.governs == "payments.wire"
    assert env.decision is Decision.REQUIRE_APPROVAL
    assert env.approvers == (ApproverRef("role:risk_head"),)
    assert env.compiled_condition is None  # never persists the compiled program


async def test_save_envelope_is_idempotent_upsert() -> None:
    repo = InMemoryPolicyRepository()
    await repo.save_envelope(_envelope())
    await repo.save_envelope(_envelope(condition="payload_amount > 5000"))  # same (id, version)
    loaded = await repo.load_all()
    assert len(loaded) == 1
    assert loaded[0].condition == "payload_amount > 5000"  # overwritten


async def test_set_lifecycle_updates_envelope() -> None:
    repo = InMemoryPolicyRepository()
    await repo.save_envelope(_envelope(lifecycle=PolicyLifecycle.REVIEW))
    await repo.set_lifecycle("p.test", 1, PolicyLifecycle.ACTIVATED)
    loaded = await repo.load_all()
    assert loaded[0].lifecycle is PolicyLifecycle.ACTIVATED


async def test_impact_report_round_trip() -> None:
    repo = InMemoryPolicyRepository()
    await repo.save_impact_report(_impact())
    reports = await repo.load_impact_reports()
    assert len(reports) == 1
    assert reports[0].reviewed_by == "reviewer:alice"
    assert reports[0].acknowledged is True


async def test_satisfies_policy_repository_protocol() -> None:
    from quaicu.core.policy.repository import PolicyRepository

    assert isinstance(InMemoryPolicyRepository(), PolicyRepository)
