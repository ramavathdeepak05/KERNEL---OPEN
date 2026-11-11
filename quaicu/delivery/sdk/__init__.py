"""QUAICU Kernel Python SDK.

Primary exports:
  - ``Kernel`` — holds all port adapters; the entry point for SDK users.
  - ``governed`` — decorator factory exposed on a ``Kernel`` instance.

Usage::

    from quaicu.delivery.sdk import Kernel

    kernel = Kernel.from_config("kernel.toml")

    @kernel.governed(policy="ciro.ifrs9.stage_transition")
    async def reclassify_loan(loan_id: str, from_stage: int, to_stage: int, *, actor):
        await ledger_db.update_stage(loan_id, to_stage)
"""

from quaicu.core.errors import (
    LifecycleDeniedError,
    LifecycleError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
    QUAICUError,
)
from quaicu.core.lifecycle.context import async_actor_scope, get_current_actor
from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.delivery.sdk.errors import SdkUsageError
from quaicu.delivery.sdk.kernel import BoundAgent, Kernel
from quaicu.delivery.sdk.proxy import GovernedProxy

__all__ = [
    "Kernel",
    "BoundAgent",
    "GovernanceProfile",
    "AuthorizationResult",
    "GovernedProxy",
    "async_actor_scope",
    "get_current_actor",
    # Error surface — governance outcomes to catch, plus SDK misuse.
    "QUAICUError",
    "LifecycleError",
    "LifecycleDeniedError",
    "LifecycleHaltedError",
    "LifecyclePendingApprovalError",
    "SdkUsageError",
]
