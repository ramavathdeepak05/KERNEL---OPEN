"""QUAICU — an AI governance kernel you run yourself.

Every governed action goes through one lifecycle — propose → evaluate → gate → execute → seal →
emit — and anything that fails along the way denies or halts the action (fail-closed).

In-process::

    from quaicu import Kernel

    kernel = Kernel.local(policies="policies.toml")

    @kernel.guard(policy="payments.wire")
    async def send_wire(*, amount: int) -> dict: ...

    async with kernel.actor_context("alice", roles=("analyst",)):
        await send_wire(amount=500)

As a local HTTP service for any language: ``quaicu init && quaicu serve`` (needs the ``server``
extra). See the README.
"""

from quaicu.core.errors import (
    LifecycleDeniedError,
    LifecycleError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
    QUAICUError,
)
from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.types import Actor, ActorId, Decision, TenantId
from quaicu.delivery.sdk.errors import SdkUsageError
from quaicu.delivery.sdk.kernel import Kernel

__version__ = "0.1.0"

__all__ = [
    "Actor",
    "ActorId",
    "AuthorizationResult",
    "Decision",
    "GovernanceProfile",
    "Kernel",
    "LifecycleDeniedError",
    "LifecycleError",
    "LifecycleHaltedError",
    "LifecyclePendingApprovalError",
    "QUAICUError",
    "SdkUsageError",
    "TenantId",
    "__version__",
]
