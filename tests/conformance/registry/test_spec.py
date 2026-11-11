"""K·08 Model Registry conformance tests — spec-derived golden cases.

Invariants:
  - per-tenant allowlist: no cross-tenant approval leakage (F-07).
  - unapproved model → DENY at registry, no fallback (F-03).
  - model id + version must be fully recorded (for ledger replay, F-09).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.errors import ModelNotFoundError, ModelNotPermittedError
from quaicu.core.registry.model import ModelRecord, ModelStatus
from quaicu.core.registry.store import InMemoryModelRegistry
from quaicu.core.types import ModelRef

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)


def _register(reg: InMemoryModelRegistry, tenant: str, model_id: str, version: str,
               status: ModelStatus = ModelStatus.ACTIVE) -> None:
    reg.register(ModelRecord(
        model_id=model_id, version=version, tenant_id=tenant,
        status=status, registered_at=NOW,
    ))


@pytest.mark.conformance
def test_active_model_permitted():
    reg = InMemoryModelRegistry()
    _register(reg, "bank-a", "gpt4o", "2024-11")
    assert reg.is_permitted(tenant_id="bank-a", model_ref=ModelRef(id="gpt4o", version="2024-11"))


@pytest.mark.conformance
def test_unapproved_model_denied_no_fallback():
    """No fallback to an unapproved model — the registry must DENY outright (F-03)."""
    reg = InMemoryModelRegistry()
    with pytest.raises(ModelNotFoundError):
        reg.require_permitted(
            tenant_id="bank-a",
            model_ref=ModelRef(id="unknown-model", version="1.0"),
        )


@pytest.mark.conformance
def test_cross_tenant_approval_impossible():
    """A model approved for tenant A must NOT be permitted for tenant B."""
    reg = InMemoryModelRegistry()
    _register(reg, "bank-a", "llama3", "3.1")
    with pytest.raises(ModelNotFoundError):
        reg.require_permitted(
            tenant_id="bank-b",
            model_ref=ModelRef(id="llama3", version="3.1"),
        )


@pytest.mark.conformance
def test_deprecated_model_denied():
    reg = InMemoryModelRegistry()
    _register(reg, "bank-a", "old-model", "1.0", status=ModelStatus.DEPRECATED)
    with pytest.raises(ModelNotPermittedError):
        reg.require_permitted(
            tenant_id="bank-a",
            model_ref=ModelRef(id="old-model", version="1.0"),
        )


@pytest.mark.conformance
def test_model_record_has_id_and_version_for_replay():
    """model_id + version must be capturable from the record (needed by ledger, F-09)."""
    reg = InMemoryModelRegistry()
    _register(reg, "bank-a", "mistral-7b", "0.2")
    record = reg.require_permitted(
        tenant_id="bank-a",
        model_ref=ModelRef(id="mistral-7b", version="0.2"),
    )
    assert record.model_id == "mistral-7b"
    assert record.version == "0.2"
