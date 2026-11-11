"""Unit tests for PostgresPolicyRepository — no real database required.

All asyncpg calls are patched with AsyncMock (mirrors test_postgres_storage.py) so these run in the
standard pytest-asyncio suite without any external services.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from quaicu.adapters.policy.postgres import (
    PostgresPolicyRepository,
    _row_to_envelope,
    _row_to_impact_report,
)
from quaicu.core.errors import PolicyPersistenceError
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.types import ApproverRef, Decision

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _fake_pool(conn: AsyncMock) -> MagicMock:
    pool = MagicMock()
    acquire_cm = MagicMock()
    acquire_cm.__aenter__ = AsyncMock(return_value=conn)
    acquire_cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire_cm)
    return pool


def _envelope() -> PolicyEnvelope:
    return PolicyEnvelope(
        id="p.wire",
        version=2,
        governs="payments.wire",
        scope={"tenant": "acme"},
        condition="payload_amount > 1000",
        decision=Decision.REQUIRE_APPROVAL,
        approvers=(ApproverRef("role:risk_head"),),
        regulatory_refs=("RBI-PV-2025",),
        lifecycle=PolicyLifecycle.ACTIVATED,
    )


# ── Row mappers ────────────────────────────────────────────────────────────────


def test_row_to_envelope_round_trip() -> None:
    row = {
        "id": "p.wire",
        "version": 2,
        "governs": "payments.wire",
        "scope": '{"tenant": "acme"}',
        "condition": "payload_amount > 1000",
        "decision": "require_approval",
        "approvers": ["role:risk_head"],
        "regulatory_refs": ["RBI-PV-2025"],
        "lifecycle": "ACTIVATED",
    }
    env = _row_to_envelope(row)
    assert env.id == "p.wire"
    assert env.version == 2
    assert env.decision is Decision.REQUIRE_APPROVAL
    assert env.approvers == (ApproverRef("role:risk_head"),)
    assert env.lifecycle is PolicyLifecycle.ACTIVATED
    assert env.compiled_condition is None


def test_row_to_impact_report_round_trip() -> None:
    row = {
        "policy_id": "p.wire",
        "version": 2,
        "reviewed_by": "reviewer:alice",
        "reviewed_at": NOW,
        "decision_distribution": '{"allow": 0.7}',
        "flip_count": 3,
        "fairness_delta": 0.01,
        "acknowledged": True,
    }
    report = _row_to_impact_report(row)
    assert report.policy_id == "p.wire"
    assert report.decision_distribution == {"allow": 0.7}
    assert report.acknowledged is True


# ── save_envelope ──────────────────────────────────────────────────────────────


async def test_save_envelope_executes_upsert() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    await repo.save_envelope(_envelope())
    conn.execute.assert_awaited_once()
    args = conn.execute.await_args.args
    # args[0] is the SQL; $1.. follow → id, version, governs, scope, condition, decision, approvers
    assert args[1] == "p.wire"  # id
    assert args[2] == 2  # version
    assert args[6] == "require_approval"  # decision
    assert args[7] == ["role:risk_head"]  # approvers as TEXT[]


async def test_save_envelope_wraps_errors() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(side_effect=Exception("db down"))
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    with pytest.raises(PolicyPersistenceError):
        await repo.save_envelope(_envelope())


# ── load_all ───────────────────────────────────────────────────────────────────


async def test_load_all_maps_rows() -> None:
    row = {
        "id": "p.wire", "version": 2, "governs": "payments.wire",
        "scope": '{"tenant": "acme"}', "condition": "payload_amount > 1000",
        "decision": "deny", "approvers": [], "regulatory_refs": [],
        "lifecycle": "ACTIVATED",
    }
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[row])
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    envelopes = await repo.load_all()
    assert len(envelopes) == 1
    assert envelopes[0].decision is Decision.DENY


# ── set_lifecycle ──────────────────────────────────────────────────────────────


async def test_set_lifecycle_raises_when_zero_rows() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="UPDATE 0")
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    with pytest.raises(PolicyPersistenceError):
        await repo.set_lifecycle("missing", 1, PolicyLifecycle.ACTIVATED)


async def test_set_lifecycle_ok_when_one_row() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="UPDATE 1")
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    await repo.set_lifecycle("p.wire", 2, PolicyLifecycle.DEPRECATED)
    args = conn.execute.await_args.args
    assert args[3] == "DEPRECATED"


# ── save_impact_report ───────────────────────────────────────────────────────


async def test_save_impact_report_executes_upsert() -> None:
    conn = AsyncMock()
    conn.execute = AsyncMock(return_value="INSERT 0 1")
    repo = PostgresPolicyRepository(dsn="postgresql://fake/fake")
    repo._pool = _fake_pool(conn)

    report = ImpactReport(
        policy_id="p.wire",
        policy_version=2,
        reviewed_by="reviewer:alice",
        reviewed_at=NOW,
        decision_distribution={"allow": 0.7},
        flip_count=3,
        fairness_delta=0.01,
        acknowledged=True,
    )
    await repo.save_impact_report(report)
    conn.execute.assert_awaited_once()
    args = conn.execute.await_args.args
    assert args[1] == "p.wire"
    assert args[8] is True  # acknowledged


async def test_satisfies_policy_repository_protocol() -> None:
    from quaicu.core.policy.repository import PolicyRepository

    assert isinstance(PostgresPolicyRepository(dsn="postgresql://fake/fake"), PolicyRepository)
