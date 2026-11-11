"""K·01 Policy Engine — data model.

`PolicyEnvelope` is the authoritative, immutable representation of a policy as stored and evaluated
by the kernel. `ImpactReport` is the simulation artifact required by F-10 before any policy may
transition from REVIEW → ACTIVATED.

This file is governed by the same freeze rules as `quaicu/core/types.py`: changes require an ADR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from quaicu.core.types import ApproverRef, Decision


class PolicyLifecycle(str, Enum):
    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    ACTIVATED = "ACTIVATED"
    DEPRECATED = "DEPRECATED"


@dataclass(frozen=True)
class PolicyEnvelope:
    """An immutable, versioned policy.

    Once ACTIVATED, `id` + `version` together identify the exact rule that governed an action — the
    version is sealed to the ledger so any future replay evaluates the same rule (F-09). A change to
    the condition or decision always creates a new `version`; the old one is DEPRECATED, not mutated.
    """

    id: str
    version: int
    governs: str                                # action type; "*" is a wildcard
    scope: dict[str, str]                       # e.g. {"tenant": "*"} or {"tenant": "ciro-bank"}
    condition: str                              # CEL source, stored verbatim
    decision: Decision
    approvers: tuple[ApproverRef, ...]          # non-empty only when decision == REQUIRE_APPROVAL
    regulatory_refs: tuple[str, ...]
    lifecycle: PolicyLifecycle
    # Populated by the store at registration time; excluded from equality / hashing because it is a
    # derived, non-serialisable object — the `condition` field is the canonical source of truth.
    compiled_condition: Any = field(default=None, compare=False, hash=False)


@dataclass(frozen=True)
class ImpactReport:
    """The reviewed simulation artefact required by F-10.

    `acknowledged` must be True and the `policy_id` / `policy_version` must match the target
    envelope before `PolicyStore.activate` will accept it. This prevents any policy from going live
    without a human reviewer signing off on the simulated impact distribution.
    """

    policy_id: str
    policy_version: int
    reviewed_by: str
    reviewed_at: datetime
    decision_distribution: dict[str, float]     # e.g. {"allow": 0.6, "deny": 0.3, ...}
    flip_count: int
    fairness_delta: float
    acknowledged: bool                          # must be True to pass the F-10 gate
