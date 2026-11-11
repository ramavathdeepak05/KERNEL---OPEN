"""Unit tests for the K·13 → K·01 bridge (assemble_impact_report)."""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.core.fairness.model import FairnessDelta
from quaicu.core.sandbox.bridge import assemble_impact_report
from quaicu.core.sandbox.model import SandboxRun

TENANT = "bank-a"


def _run(*, evaluated: int, flipped: int, policy_version: str = "3") -> SandboxRun:
    return SandboxRun(
        run_id="run-1",
        tenant_id=TENANT,
        policy_id="p.wire",
        policy_version=policy_version,
        run_type="backtest",
        ledger_entries_evaluated=evaluated,
        decisions_flipped=flipped,
        decisions_unchanged=evaluated - flipped,
        flip_rate=(flipped / evaluated) if evaluated else 0.0,
        ran_at=datetime(2026, 6, 5, tzinfo=timezone.utc),
    )


def test_acknowledged_defaults_false():
    report = assemble_impact_report(_run(evaluated=10, flipped=2), reviewed_by="user:rev")
    assert report.acknowledged is False


def test_flip_count_propagated():
    report = assemble_impact_report(_run(evaluated=10, flipped=3), reviewed_by="user:rev")
    assert report.flip_count == 3


def test_identity_fields_from_run():
    report = assemble_impact_report(_run(evaluated=1, flipped=0), reviewed_by="user:rev")
    assert report.policy_id == "p.wire"
    assert report.policy_version == 3
    assert report.reviewed_by == "user:rev"


def test_distribution_all_unchanged_is_all_allow():
    report = assemble_impact_report(_run(evaluated=4, flipped=0), reviewed_by="user:rev")
    assert report.decision_distribution == {"allow": 1.0}


def test_distribution_splits_flips_to_deny():
    report = assemble_impact_report(_run(evaluated=4, flipped=1), reviewed_by="user:rev")
    assert report.decision_distribution["allow"] == 0.75
    assert report.decision_distribution["deny"] == 0.25


def test_empty_run_distribution_defaults_allow():
    report = assemble_impact_report(_run(evaluated=0, flipped=0), reviewed_by="user:rev")
    assert report.decision_distribution == {"allow": 1.0}
    assert report.flip_count == 0


def test_fairness_delta_zero_when_absent():
    report = assemble_impact_report(_run(evaluated=5, flipped=1), reviewed_by="user:rev")
    assert report.fairness_delta == 0.0


def test_fairness_delta_taken_from_object():
    delta = FairnessDelta(
        tenant_id=TENANT,
        group_key="band",
        max_delta=0.42,
        groups_above_threshold=("A",),
    )
    report = assemble_impact_report(
        _run(evaluated=5, flipped=1), reviewed_by="user:rev", fairness_delta=delta
    )
    assert report.fairness_delta == 0.42


def test_non_numeric_version_defaults_to_one():
    report = assemble_impact_report(
        _run(evaluated=1, flipped=0, policy_version="draft"), reviewed_by="user:rev"
    )
    assert report.policy_version == 1


def test_explicit_reviewed_at_preserved():
    ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
    report = assemble_impact_report(
        _run(evaluated=1, flipped=0), reviewed_by="user:rev", reviewed_at=ts
    )
    assert report.reviewed_at == ts
