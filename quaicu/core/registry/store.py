"""K·08 Model Registry — InMemoryModelRegistry.

Thread-safe, per-tenant, in-memory store. The production path replaces this
with a StoragePort-backed adapter; the interface is the same.

Tenant isolation (F-07): every method takes ``tenant_id`` explicitly. The store
never mixes records across tenants.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from quaicu.core.errors import ModelNotFoundError, ModelNotPermittedError
from quaicu.core.registry.model import ModelRecord, ModelStatus
from quaicu.core.types import ModelRef


class InMemoryModelRegistry:
    """In-memory per-tenant model registry. Satisfies the registry interface structurally."""

    def __init__(self) -> None:
        # tenant_id → model_id → version → ModelRecord
        self._records: dict[str, dict[str, dict[str, ModelRecord]]] = {}
        self._lock = threading.Lock()

    # ── Write ──────────────────────────────────────────────────────────────────

    def register(self, record: ModelRecord) -> None:
        """Add or update a model record for a tenant."""
        with self._lock:
            tenant = self._records.setdefault(record.tenant_id, {})
            versions = tenant.setdefault(record.model_id, {})
            versions[record.version] = record

    def update_status(
        self,
        *,
        tenant_id: str,
        model_id: str,
        version: str,
        status: ModelStatus,
    ) -> ModelRecord:
        """Return an updated record with the new status.

        Raises:
            ModelNotFoundError: if the record does not exist.
        """
        with self._lock:
            existing = self._get_locked(tenant_id, model_id, version)
            if existing is None:
                raise ModelNotFoundError(
                    f"Model {model_id!r} v{version!r} not registered for tenant {tenant_id!r}",
                    detail={"tenant_id": tenant_id, "model_id": model_id, "version": version},
                )
            now = datetime.now(tz=timezone.utc)
            updated = ModelRecord(
                model_id=existing.model_id,
                version=existing.version,
                tenant_id=existing.tenant_id,
                status=status,
                registered_at=existing.registered_at,
                deprecated_at=now if status == ModelStatus.DEPRECATED else existing.deprecated_at,
                retired_at=now if status == ModelStatus.RETIRED else existing.retired_at,
                metadata=existing.metadata,
            )
            self._records[tenant_id][model_id][version] = updated
            return updated

    # ── Read ───────────────────────────────────────────────────────────────────

    def get(
        self, *, tenant_id: str, model_id: str, version: str
    ) -> ModelRecord | None:
        with self._lock:
            return self._get_locked(tenant_id, model_id, version)

    def list_for_tenant(self, *, tenant_id: str) -> list[ModelRecord]:
        with self._lock:
            tenant = self._records.get(tenant_id, {})
            return [
                record
                for versions in tenant.values()
                for record in versions.values()
            ]

    def is_permitted(self, *, tenant_id: str, model_ref: ModelRef) -> bool:
        """Return True iff the model is registered and ACTIVE for this tenant."""
        record = self.get(
            tenant_id=tenant_id,
            model_id=model_ref.id,
            version=model_ref.version,
        )
        return record is not None and record.status == ModelStatus.ACTIVE

    def require_permitted(self, *, tenant_id: str, model_ref: ModelRef) -> ModelRecord:
        """Raise ModelNotPermittedError if not ACTIVE; raise ModelNotFoundError if absent.

        The Gateway calls this before any inference. Fail-closed (F-03).
        """
        record = self.get(
            tenant_id=tenant_id,
            model_id=model_ref.id,
            version=model_ref.version,
        )
        if record is None:
            raise ModelNotFoundError(
                f"Model {model_ref.id!r} v{model_ref.version!r} not registered "
                f"for tenant {tenant_id!r}",
                detail={"tenant_id": tenant_id, "model_id": model_ref.id, "version": model_ref.version},
            )
        if record.status != ModelStatus.ACTIVE:
            raise ModelNotPermittedError(
                f"Model {model_ref.id!r} v{model_ref.version!r} is {record.status.value} "
                f"for tenant {tenant_id!r} — DENY",
                detail={
                    "tenant_id": tenant_id,
                    "model_id": model_ref.id,
                    "version": model_ref.version,
                    "status": record.status.value,
                },
            )
        return record

    # ── Internal ───────────────────────────────────────────────────────────────

    def _get_locked(
        self, tenant_id: str, model_id: str, version: str
    ) -> ModelRecord | None:
        return self._records.get(tenant_id, {}).get(model_id, {}).get(version)
