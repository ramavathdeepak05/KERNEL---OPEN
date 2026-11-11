from __future__ import annotations

import threading
from dataclasses import dataclass

from quaicu.core.errors import GatewayBudgetExceededError
from quaicu.core.types import TenantId


@dataclass
class TenantBudget:
    max_tokens: int
    used_tokens: int = 0
    max_cost_usd: float = 0.0
    used_cost_usd: float = 0.0


class InMemoryBudgetTracker:
    """Per-tenant token and cost budget. Defaults to unlimited."""

    def __init__(self) -> None:
        self._budgets: dict[str, TenantBudget] = {}
        self._lock = threading.Lock()

    def set_budget(self, tenant: TenantId, *, max_tokens: int = 0, max_cost_usd: float = 0.0) -> None:
        with self._lock:
            self._budgets[str(tenant)] = TenantBudget(max_tokens=max_tokens, max_cost_usd=max_cost_usd)

    def check_and_consume(self, tenant: TenantId, *, tokens: int, cost_usd: float = 0.0) -> None:
        """Raise GatewayBudgetExceededError if budget exceeded, else consume."""
        with self._lock:
            b = self._budgets.get(str(tenant))
            if b is None:
                return
            if b.max_tokens > 0 and (b.used_tokens + tokens) > b.max_tokens:
                raise GatewayBudgetExceededError(
                    f"Tenant {tenant!r} token budget exhausted ({b.used_tokens}/{b.max_tokens}).",
                    detail={"tenant": str(tenant), "used": b.used_tokens, "max": b.max_tokens},
                )
            if b.max_cost_usd > 0 and (b.used_cost_usd + cost_usd) > b.max_cost_usd:
                raise GatewayBudgetExceededError(
                    f"Tenant {tenant!r} cost budget exhausted.",
                    detail={"tenant": str(tenant)},
                )
            b.used_tokens += tokens
            b.used_cost_usd += cost_usd

    def usage(self, tenant: TenantId) -> dict:
        with self._lock:
            b = self._budgets.get(str(tenant))
            if b is None:
                return {"tokens": 0, "cost_usd": 0.0}
            return {"tokens": b.used_tokens, "cost_usd": b.used_cost_usd}
