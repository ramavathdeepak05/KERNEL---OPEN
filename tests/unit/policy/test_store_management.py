"""Unit tests for the PolicyStore management API (reads, submit-for-review, persisted variants).

These cover the additions made for the policy management HTTP surface: get / list_policies /
list_versions / get_impact_report, the DRAFT→REVIEW transition, the persisted impact-report write,
and the register immutability guard (including its ordering relative to the durable write).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.errors import PolicyTransitionError
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Decision

TENANT = "acme"


def _envelope(
    pid: str = "p.wire",
    version: int = 1,
    lifecycle: PolicyLifecycle = PolicyLifecycle.DRAFT,
    governs: str = "payments.wire",
) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=pid,
        version=version,
        governs=governs,
        scope={"tenant": "*"},
        condition="true",
        decision=Decision.ALLOW,
        approvers=(),
        regulatory_refs=(),
        lifecycle=lifecycle,
    )


def _report(pid: str = "p.wire", version: int = 1, acknowledged: bool = True) -> ImpactReport:
    return ImpactReport(
        policy_id=pid,
        policy_version=version,
        reviewed_by="user:reviewer",
        reviewed_at=datetime(2026, 6, 5, tzinfo=timezone.utc),
        decision_distribution={"allow": 1.0},
        flip_count=0,
        fairness_delta=0.0,
        acknowledged=acknowledged,
    )


# ── Reads ───────────────────────────────────────────────────────────────────────


def test_get_returns_none_when_absent() -> None:
    store = PolicyStore()
    assert store.get("missing", 1) is None


def test_get_returns_registered_envelope() -> None:
    store = PolicyStore()
    store.register(_envelope())
    got = store.get("p.wire", 1)
    assert got is not None and got.id == "p.wire" and got.version == 1


def test_list_policies_filters_by_lifecycle() -> None:
    store = PolicyStore()
    store.register(_envelope("p.a", 1, PolicyLifecycle.DRAFT))
    store.register(_envelope("p.b", 1, PolicyLifecycle.REVIEW))
    assert {e.id for e in store.list_policies()} == {"p.a", "p.b"}
    drafts = store.list_policies(PolicyLifecycle.DRAFT)
    assert [e.id for e in drafts] == ["p.a"]


def test_list_policies_sorted_by_id_version() -> None:
    store = PolicyStore()
    store.register(_envelope("p.b", 1))
    store.register(_envelope("p.a", 2))
    store.register(_envelope("p.a", 1))
    assert [(e.id, e.version) for e in store.list_policies()] == [
        ("p.a", 1),
        ("p.a", 2),
        ("p.b", 1),
    ]


def test_list_versions_sorted_ascending() -> None:
    store = PolicyStore()
    store.register(_envelope("p.x", 3))
    store.register(_envelope("p.x", 1))
    store.register(_envelope("p.x", 2))
    store.register(_envelope("p.y", 9))
    assert [e.version for e in store.list_versions("p.x")] == [1, 2, 3]


def test_get_impact_report_roundtrip() -> None:
    store = PolicyStore()
    assert store.get_impact_report("p.wire", 1) is None
    store.store_impact_report(_report())
    got = store.get_impact_report("p.wire", 1)
    assert got is not None and got.reviewed_by == "user:reviewer"


# ── submit_for_review ─────────────────────────────────────────────────────────────


def test_submit_for_review_transitions_draft() -> None:
    store = PolicyStore()
    store.register(_envelope())
    reviewing = store.submit_for_review("p.wire", 1)
    assert reviewing.lifecycle is PolicyLifecycle.REVIEW
    assert store.get("p.wire", 1).lifecycle is PolicyLifecycle.REVIEW
    # compiled_condition preserved across the transition
    assert store.get("p.wire", 1).compiled_condition is not None


def test_submit_for_review_missing_raises() -> None:
    store = PolicyStore()
    with pytest.raises(PolicyTransitionError):
        store.submit_for_review("nope", 1)


def test_submit_for_review_non_draft_raises() -> None:
    store = PolicyStore()
    store.register(_envelope())
    store.submit_for_review("p.wire", 1)  # now REVIEW
    with pytest.raises(PolicyTransitionError):
        store.submit_for_review("p.wire", 1)


# ── Immutability guard ───────────────────────────────────────────────────────────


def test_register_over_activated_raises() -> None:
    store = PolicyStore()
    store.register(_envelope(lifecycle=PolicyLifecycle.ACTIVATED))
    with pytest.raises(PolicyTransitionError):
        store.register(_envelope())


def test_register_over_deprecated_raises() -> None:
    store = PolicyStore()
    store.register(_envelope(lifecycle=PolicyLifecycle.DEPRECATED))
    with pytest.raises(PolicyTransitionError):
        store.register(_envelope())


def test_register_over_draft_allowed() -> None:
    store = PolicyStore()
    store.register(_envelope(governs="old"))
    updated = store.register(_envelope(governs="new"))
    assert updated.governs == "new"


# ── Persisted variants ───────────────────────────────────────────────────────────


class _SpyRepo:
    """Records repository calls; can raise to inject a persistence fault."""

    def __init__(self) -> None:
        self.saved_envelopes: list[PolicyEnvelope] = []
        self.saved_reports: list[ImpactReport] = []
        self.lifecycle_calls: list[tuple[str, int, PolicyLifecycle]] = []

    async def load_all(self) -> list[PolicyEnvelope]:
        return []

    async def load_impact_reports(self) -> list[ImpactReport]:
        return []

    async def save_envelope(self, envelope: PolicyEnvelope) -> None:
        self.saved_envelopes.append(envelope)

    async def save_impact_report(self, report: ImpactReport) -> None:
        self.saved_reports.append(report)

    async def set_lifecycle(self, policy_id: str, version: int, lifecycle: PolicyLifecycle) -> None:
        self.lifecycle_calls.append((policy_id, version, lifecycle))

    async def close(self) -> None:
        return None


async def test_register_persisted_guard_fires_before_save() -> None:
    """A re-register of an ACTIVATED version must NOT touch the durable store."""
    repo = _SpyRepo()
    store = PolicyStore(repository=repo)
    store.register(_envelope(lifecycle=PolicyLifecycle.ACTIVATED))  # cache only
    with pytest.raises(PolicyTransitionError):
        await store.register_persisted(_envelope())
    assert repo.saved_envelopes == []  # guard ran before save_envelope


async def test_submit_for_review_persisted_sets_lifecycle() -> None:
    repo = _SpyRepo()
    store = PolicyStore(repository=repo)
    store.register(_envelope())
    await store.submit_for_review_persisted("p.wire", 1)
    assert repo.lifecycle_calls == [("p.wire", 1, PolicyLifecycle.REVIEW)]


async def test_store_impact_report_persisted_saves_then_caches() -> None:
    repo = _SpyRepo()
    store = PolicyStore(repository=repo)
    await store.store_impact_report_persisted(_report())
    assert len(repo.saved_reports) == 1
    assert store.get_impact_report("p.wire", 1) is not None


async def test_hydrate_over_activated_rows() -> None:
    """Hydrate registers ACTIVATED rows into an empty cache without tripping the guard."""
    from quaicu.adapters.policy.memory import InMemoryPolicyRepository

    repo = InMemoryPolicyRepository()
    await repo.save_envelope(_envelope(lifecycle=PolicyLifecycle.ACTIVATED))
    store = PolicyStore(repository=repo)
    await store.hydrate()
    got = store.get("p.wire", 1)
    assert got is not None and got.lifecycle is PolicyLifecycle.ACTIVATED
