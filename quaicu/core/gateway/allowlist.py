from __future__ import annotations

from dataclasses import dataclass, field

from quaicu.core.types import ModelRef, TenantId


@dataclass
class InMemoryModelAllowlist:
    """Per-tenant registry of permitted models. K·08 will replace this."""

    _allowlist: dict[str, set[str]] = field(default_factory=dict)

    def permit(self, tenant: TenantId, model_id: str) -> None:
        self._allowlist.setdefault(str(tenant), set()).add(model_id)

    def is_permitted(self, tenant: TenantId, model_ref: ModelRef) -> bool:
        return model_ref.id in self._allowlist.get(str(tenant), set())

    def permitted_models(self, tenant: TenantId) -> frozenset[str]:
        return frozenset(self._allowlist.get(str(tenant), set()))
