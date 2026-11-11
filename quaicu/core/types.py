"""QUAICU kernel shared value types — FROZEN contract surface.

These are the value types that cross layer boundaries: the lifecycle spine, the port signatures
(spec §5), and the integration shapes (Action, EvaluationResult, LedgerEntry) every layer agrees on.

Design rules (see AGENTS.md §3 and the `clean-code` skill contract):
- Domain models are immutable: `@dataclass(frozen=True)`. Express a state change by constructing a new
  value with `dataclasses.replace(...)` (or the provided `with_state` helper) — never mutate in place.
- This file is FROZEN. Changing a field, a signature, or an enum member requires the orchestrator +
  an ADR. Layers may freely *construct* and *consume* these; they may not redefine them.
- Per-layer internal shapes (e.g. the full K·01 policy envelope, the K·06 step DSL) are owned by their
  layer and are NOT defined here — only what is genuinely shared lives in this file.

Source of truth: build spec §5, the Glossary, and the lifecycle/ledger/gateway/process skills.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, NewType, Protocol, runtime_checkable

# ── Identifiers (newtypes keep tenant/action/actor ids from being mixed up) ──────

TenantId = NewType("TenantId", str)
ActionId = NewType("ActionId", str)
ActorId = NewType("ActorId", str)
PolicyId = NewType("PolicyId", str)
IdempotencyKey = NewType("IdempotencyKey", str)
ApproverRef = NewType("ApproverRef", str)  # e.g. "role:risk_head" or "user:alice"


# ── Enums ────────────────────────────────────────────────────────────────────


class ActionState(str, Enum):
    """The lifecycle state of an action. See the Glossary and the worked example (spec §10)."""

    PROPOSED = "PROPOSED"
    EVALUATING = "EVALUATING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTING = "EXECUTING"
    SEALING = "SEALING"
    SEALED = "SEALED"
    COMPLETED = "COMPLETED"
    # terminal failure / cancel states
    DENIED = "DENIED"
    HALTED = "HALTED"
    CANCELLED = "CANCELLED"


TERMINAL_STATES: frozenset[ActionState] = frozenset(
    {ActionState.COMPLETED, ActionState.DENIED, ActionState.HALTED, ActionState.CANCELLED}
)


class Decision(str, Enum):
    """A policy's output for an action. Distinct from ActionState (a state is where the action *is*;
    a decision is what a policy *returned*)."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ApprovalDecision(str, Enum):
    """The outcome of a HITL gate. TIMED_OUT is treated as REJECTED by the lifecycle (fail-closed)."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"


# ── Identity (resolved via IdentityPort) ────────────────────────────────────────


@dataclass(frozen=True)
class Actor:
    """The authenticated identity on whose behalf an action is proposed."""

    id: ActorId
    tenant: TenantId
    roles: tuple[str, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RequestContext:
    """Opaque, host-supplied context the IdentityPort resolves an Actor from. The kernel does NOT
    own authentication — it takes identity from the host."""

    headers: Mapping[str, str] = field(default_factory=dict)
    source_ip: str | None = None
    raw_token: str | None = None
    tenant_hint: TenantId | None = None


# ── The governed action (the atomic unit the kernel governs) ─────────────────────


@dataclass(frozen=True)
class Action:
    """A proposed change to institutional state — the atomic unit the kernel governs.

    Immutable: progress through the lifecycle is expressed with `with_state` / `dataclasses.replace`,
    not in-place mutation.
    """

    id: ActionId
    type: str
    payload: Mapping[str, Any]
    actor: Actor
    tenant: TenantId
    idempotency_key: IdempotencyKey
    state: ActionState = ActionState.PROPOSED
    proposed_at: datetime | None = None

    def with_state(self, state: ActionState) -> "Action":
        """Return a new Action in the given state. The canonical way to advance the lifecycle."""
        return dataclasses.replace(self, state=state)


# ── Evaluation result (K·01 → lifecycle) ─────────────────────────────────────────


@dataclass(frozen=True)
class EvaluationResult:
    """The resolved outcome of evaluating an action against all applicable active policies.

    Carries the policy *versions* that produced the decision so the action is replayable
    point-in-time (F-09). `approvers` is populated only when `decision == REQUIRE_APPROVAL`.
    """

    decision: Decision
    policy_versions: tuple[str, ...] = ()
    approvers: tuple[ApproverRef, ...] = ()
    reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ── Ledger entry (K·02) — the sealed, replay-sufficient record ────────────────────


@dataclass(frozen=True)
class LedgerEntry:
    """A sealed entry in the per-tenant RFC 6962 transparency log.

    Records inputs AND results (not just outcomes) so the decision is fully re-derivable on replay
    (F-09 / spec §3.13). `recorded_result` holds the execute result; `recorded_outputs` holds any
    non-deterministic results (chiefly model outputs) captured at original execution.
    """

    ledger_seq: int
    tenant: TenantId
    action_id: ActionId
    action_type: str
    actor_id: ActorId
    decision: Decision
    policy_versions: tuple[str, ...]
    leaf_hash: bytes
    sealed_at: datetime
    approver: ApproverRef | None = None
    consent_state: Mapping[str, Any] = field(default_factory=dict)
    recorded_result: Mapping[str, Any] = field(default_factory=dict)
    recorded_outputs: Mapping[str, Any] = field(default_factory=dict)
    # The actor's roles at seal time. Sealed into the Merkle leaf alongside `actor_id` so a
    # point-in-time replay (and the K·13 counterfactual backtest) can re-evaluate policies that
    # gate on roles. Added under ADR-0006 (ADR-0001 incremental-freeze rule).
    actor_roles: tuple[str, ...] = ()


# ── Inference types (K·05 / InferencePort) ───────────────────────────────────────


@dataclass(frozen=True)
class Prompt:
    """An already-masked prompt. PII masking happens in the Gateway before this type is constructed;
    the InferencePort never receives unmasked content."""

    text: str
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelRef:
    """Identifies which model to invoke. Routing/approval is enforced by the Gateway + Model Registry."""

    id: str
    version: str
    runtime: str | None = None


@dataclass(frozen=True)
class ModelResponse:
    """A model response. `recorded_output` is the canonical value sealed to the ledger and reused on
    replay — never recompute a model call (F-09)."""

    content: str
    model_id: str
    recorded_output: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)


# ── HITL types (K·03 / HITLPort) ─────────────────────────────────────────────────


@dataclass(frozen=True)
class ApprovalHandle:
    """An opaque handle returned by HITLPort.request_approval, used to poll for a decision."""

    id: str
    tenant: TenantId
    created_at: datetime | None = None


@dataclass(frozen=True)
class ApprovalOutcome:
    """The result of polling a HITL gate: the decision and who made it (K·03).

    `decided_by` is the approver's actor id when the gate has been decided (APPROVED/REJECTED by a
    known actor); it is None while PENDING or on a TIMED_OUT with no decider. The lifecycle seals it
    as the approving identity on the `LedgerEntry` (ADR-0007)."""

    decision: ApprovalDecision
    decided_by: ActorId | None = None


# ── Workflow types (K·06 / WorkflowPort) ─────────────────────────────────────────


@dataclass(frozen=True)
class ProcessDef:
    """A durable process definition. Minimal frozen shape; the full step/transition DSL is owned by
    K·06 (`quaicu/core/process`) and extends this under the same freeze rule."""

    id: str
    version: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WorkflowHandle:
    """A handle to a running durable workflow instance."""

    id: str
    tenant: TenantId


@dataclass(frozen=True)
class Signal:
    """A signal sent to a running workflow (e.g. an approval decision)."""

    name: str
    payload: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProcessState:
    """The current state of a durable process, reconstructable purely from recorded events."""

    status: str
    current_step: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)


# ── Storage transaction (K· / StoragePort) ───────────────────────────────────────


@runtime_checkable
class Transaction(Protocol):
    """A unit of work over kernel-owned storage, obtained from `StoragePort.transaction()`.

    The transaction's commit/rollback is driven by the async context manager that yields it
    (commit on clean exit, rollback on exception). Per-layer data-access (repository) methods are
    layered onto the concrete transaction by the storage adapter and the owning layer, added under
    the same freeze discipline as each layer is designed (see AGENTS.md §3). This Protocol is the
    minimal shared marker; it intentionally does not enumerate every layer's repository calls.
    """

    ...
