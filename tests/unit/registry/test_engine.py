"""Unit tests for K·08 Model Registry (InMemoryModelRegistry).

Decision table from the skill contract:
  model ACTIVE on allowlist               → permitted
  model not registered for tenant         → DENY (ModelNotFoundError)
  model DEPRECATED / RETIRED / PENDING    → DENY (ModelNotPermittedError)
  model approved for tenant A             → must NOT be approved for tenant B
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.errors import ModelNotFoundError, ModelNotPermittedError
from quaicu.core.registry.model import ModelRecord, ModelStatus
from quaicu.core.registry.store import InMemoryModelRegistry
from quaicu.core.types import ModelRef

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT_A = "tenant-alpha"
TENANT_B = "tenant-beta"


def _record(
    model_id: str = "llama3",
    version: str = "3.1",
    tenant_id: str = TENANT_A,
    status: ModelStatus = ModelStatus.ACTIVE,
) -> ModelRecord:
    return ModelRecord(
        model_id=model_id,
        version=version,
        tenant_id=tenant_id,
        status=status,
        registered_at=NOW,
    )


def _ref(model_id: str = "llama3", version: str = "3.1") -> ModelRef:
    return ModelRef(id=model_id, version=version)


# ── Happy path ────────────────────────────────────────────────────────────────


def test_active_model_is_permitted():
    reg = InMemoryModelRegistry()
    reg.register(_record())
    assert reg.is_permitted(tenant_id=TENANT_A, model_ref=_ref())


def test_require_permitted_returns_record_for_active():
    reg = InMemoryModelRegistry()
    reg.register(_record())
    record = reg.require_permitted(tenant_id=TENANT_A, model_ref=_ref())
    assert record.model_id == "llama3"
    assert record.status == ModelStatus.ACTIVE


def test_list_for_tenant_returns_all_records():
    reg = InMemoryModelRegistry()
    reg.register(_record(model_id="m1", version="1.0"))
    reg.register(_record(model_id="m2", version="2.0"))
    records = reg.list_for_tenant(tenant_id=TENANT_A)
    assert len(records) == 2


def test_get_returns_exact_record():
    reg = InMemoryModelRegistry()
    r = _record()
    reg.register(r)
    got = reg.get(tenant_id=TENANT_A, model_id="llama3", version="3.1")
    assert got is not None
    assert got.model_id == "llama3"


# ── Fail-closed: DENY paths ───────────────────────────────────────────────────


def test_unregistered_model_is_not_permitted():
    reg = InMemoryModelRegistry()
    assert not reg.is_permitted(tenant_id=TENANT_A, model_ref=_ref())


def test_require_permitted_raises_for_unregistered():
    reg = InMemoryModelRegistry()
    with pytest.raises(ModelNotFoundError):
        reg.require_permitted(tenant_id=TENANT_A, model_ref=_ref())


def test_deprecated_model_is_not_permitted():
    reg = InMemoryModelRegistry()
    reg.register(_record(status=ModelStatus.DEPRECATED))
    assert not reg.is_permitted(tenant_id=TENANT_A, model_ref=_ref())


def test_require_permitted_raises_for_deprecated():
    reg = InMemoryModelRegistry()
    reg.register(_record(status=ModelStatus.DEPRECATED))
    with pytest.raises(ModelNotPermittedError) as exc_info:
        reg.require_permitted(tenant_id=TENANT_A, model_ref=_ref())
    assert exc_info.value.detail["status"] == "DEPRECATED"


def test_retired_model_is_denied():
    reg = InMemoryModelRegistry()
    reg.register(_record(status=ModelStatus.RETIRED))
    with pytest.raises(ModelNotPermittedError):
        reg.require_permitted(tenant_id=TENANT_A, model_ref=_ref())


def test_pending_model_is_denied():
    reg = InMemoryModelRegistry()
    reg.register(_record(status=ModelStatus.PENDING))
    with pytest.raises(ModelNotPermittedError):
        reg.require_permitted(tenant_id=TENANT_A, model_ref=_ref())


# ── Tenant isolation (F-07) ───────────────────────────────────────────────────


def test_model_approved_for_a_not_approved_for_b():
    reg = InMemoryModelRegistry()
    reg.register(_record(tenant_id=TENANT_A))
    # TENANT_B has no records
    assert not reg.is_permitted(tenant_id=TENANT_B, model_ref=_ref())


def test_require_permitted_tenant_b_raises():
    reg = InMemoryModelRegistry()
    reg.register(_record(tenant_id=TENANT_A))
    with pytest.raises(ModelNotFoundError):
        reg.require_permitted(tenant_id=TENANT_B, model_ref=_ref())


def test_same_model_different_tenants_independent():
    reg = InMemoryModelRegistry()
    reg.register(_record(tenant_id=TENANT_A, status=ModelStatus.ACTIVE))
    reg.register(_record(tenant_id=TENANT_B, status=ModelStatus.DEPRECATED))
    assert reg.is_permitted(tenant_id=TENANT_A, model_ref=_ref())
    assert not reg.is_permitted(tenant_id=TENANT_B, model_ref=_ref())


def test_list_for_tenant_isolated():
    reg = InMemoryModelRegistry()
    reg.register(_record(tenant_id=TENANT_A))
    reg.register(_record(model_id="x", tenant_id=TENANT_B))
    assert len(reg.list_for_tenant(tenant_id=TENANT_A)) == 1
    assert len(reg.list_for_tenant(tenant_id=TENANT_B)) == 1


# ── Status transitions ────────────────────────────────────────────────────────


def test_update_status_to_deprecated():
    reg = InMemoryModelRegistry()
    reg.register(_record())
    updated = reg.update_status(
        tenant_id=TENANT_A, model_id="llama3", version="3.1", status=ModelStatus.DEPRECATED
    )
    assert updated.status == ModelStatus.DEPRECATED
    assert updated.deprecated_at is not None


def test_update_status_raises_for_unknown():
    reg = InMemoryModelRegistry()
    with pytest.raises(ModelNotFoundError):
        reg.update_status(
            tenant_id=TENANT_A, model_id="ghost", version="0.0", status=ModelStatus.DEPRECATED
        )


def test_get_returns_none_for_missing():
    reg = InMemoryModelRegistry()
    assert reg.get(tenant_id=TENANT_A, model_id="ghost", version="0.0") is None
