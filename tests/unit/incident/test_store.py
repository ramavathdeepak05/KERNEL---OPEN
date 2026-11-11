"""Unit tests for K·12 Incident store."""

from __future__ import annotations

import pytest

from quaicu.core.incident.model import Incident, IncidentSeverity, IncidentStatus
from quaicu.core.incident.store import IncidentNotFoundError, IncidentStore

TENANT = "bank-a"
OTHER_TENANT = "bank-b"


def _open(store: IncidentStore, tenant: str = TENANT, severity: IncidentSeverity = IncidentSeverity.HIGH) -> "Incident":
    return store.open_incident(
        tenant_id=tenant,
        trigger_type="drift_breach",
        severity=severity,
        description="PSI exceeded threshold for loan_band feature",
        triggering_ledger_seq=42,
        triggering_action_id="act-42",
    )


# ── Open incident ─────────────────────────────────────────────────────────────────


def test_open_incident_returns_incident():
    store = IncidentStore()
    inc = _open(store)
    assert isinstance(inc, Incident)
    assert inc.status == IncidentStatus.OPEN


def test_open_incident_assigns_id():
    store = IncidentStore()
    inc = _open(store)
    assert inc.incident_id != ""


def test_open_incident_links_ledger_seq():
    store = IncidentStore()
    inc = _open(store)
    assert inc.triggering_ledger_seq == 42
    assert inc.triggering_action_id == "act-42"


def test_open_incident_trigger_type_preserved():
    store = IncidentStore()
    inc = _open(store)
    assert inc.trigger_type == "drift_breach"


def test_open_incident_severity_preserved():
    store = IncidentStore()
    inc = _open(store, severity=IncidentSeverity.CRITICAL)
    assert inc.severity == IncidentSeverity.CRITICAL


def test_open_incident_sets_opened_at():
    store = IncidentStore()
    inc = _open(store)
    assert inc.opened_at is not None


# ── Get / list ────────────────────────────────────────────────────────────────────


def test_get_returns_incident():
    store = IncidentStore()
    inc = _open(store)
    found = store.get(TENANT, inc.incident_id)
    assert found is not None
    assert found.incident_id == inc.incident_id


def test_get_returns_none_for_missing():
    store = IncidentStore()
    assert store.get(TENANT, "nonexistent") is None


def test_list_for_tenant_returns_all():
    store = IncidentStore()
    _open(store)
    _open(store)
    assert len(store.list_for_tenant(TENANT)) == 2


def test_list_for_tenant_isolated():
    store = IncidentStore()
    _open(store, tenant=TENANT)
    _open(store, tenant=OTHER_TENANT)
    assert len(store.list_for_tenant(TENANT)) == 1
    assert len(store.list_for_tenant(OTHER_TENANT)) == 1


def test_require_raises_for_missing():
    store = IncidentStore()
    with pytest.raises(IncidentNotFoundError):
        store.require(TENANT, "ghost")


# ── Status transitions ────────────────────────────────────────────────────────────


def test_update_status_to_investigating():
    store = IncidentStore()
    inc = _open(store)
    updated = store.update_status(TENANT, inc.incident_id, IncidentStatus.INVESTIGATING)
    assert updated.status == IncidentStatus.INVESTIGATING


def test_resolve_sets_resolved_at():
    store = IncidentStore()
    inc = _open(store)
    resolved = store.update_status(TENANT, inc.incident_id, IncidentStatus.RESOLVED)
    assert resolved.status == IncidentStatus.RESOLVED
    assert resolved.resolved_at is not None


def test_update_status_raises_for_missing():
    store = IncidentStore()
    with pytest.raises(IncidentNotFoundError):
        store.update_status(TENANT, "ghost", IncidentStatus.RESOLVED)


# ── Rollback action linking ───────────────────────────────────────────────────────


def test_link_rollback_action():
    store = IncidentStore()
    inc = _open(store)
    updated = store.link_rollback_action(TENANT, inc.incident_id, "rollback-act-1")
    assert "rollback-act-1" in updated.rollback_action_ids


def test_multiple_rollback_actions_accumulated():
    store = IncidentStore()
    inc = _open(store)
    store.link_rollback_action(TENANT, inc.incident_id, "r-1")
    updated = store.link_rollback_action(TENANT, inc.incident_id, "r-2")
    assert "r-1" in updated.rollback_action_ids
    assert "r-2" in updated.rollback_action_ids


def test_link_rollback_raises_for_missing():
    store = IncidentStore()
    with pytest.raises(IncidentNotFoundError):
        store.link_rollback_action(TENANT, "ghost", "r-1")
