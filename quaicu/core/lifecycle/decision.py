"""AuthorizationResult — the verdict from a side-effect-free policy decision.

Returned by ``LifecycleEngine.decide`` and ``Kernel.check``. The caller is the enforcement point
(PEP); this type carries only the verdict, never a state-machine transition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from quaicu.core.types import ActorId, ApproverRef, Decision


@dataclass(frozen=True)
class AuthorizationResult:
    """The verdict from a policy decision query — no side effects, no action execution.

    ``allowed`` is the fast-path convenience (True iff decision is ALLOW). ``sealed`` is True when
    the decision was written to the transparency log as a monitoring record; ``ledger_seq`` is the
    sequence number of that entry.
    """

    decision: Decision
    allowed: bool
    actor_id: ActorId
    reason: str | None = None
    policy_versions: tuple[str, ...] = ()
    approvers: tuple[ApproverRef, ...] = ()
    enforced_layers: tuple[str, ...] = ()
    consent_state: Mapping[str, Any] = field(default_factory=dict)
    sealed: bool = False
    ledger_seq: int | None = None
