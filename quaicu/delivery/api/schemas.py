"""Pydantic request/response schemas for the QUAICU Kernel REST API.

All schemas are versioned under /v1. Breaking changes require a new major version.
Pydantic v2 is required.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from quaicu.core.types import Decision


# ── Request schemas ───────────────────────────────────────────────────────────────


class ProposeRequest(BaseModel):
    """Body for POST /v1/actions/propose.

    The actor is NEVER supplied by the caller: identity is resolved from the bearer token by the
    configured IdentityPort. There is intentionally no actor_id / actor_roles field.
    """

    type: str = Field(..., description="Action type (e.g. 'ciro.ifrs9.stage_transition')")
    payload: dict[str, Any] = Field(default_factory=dict, description="Action payload")
    idempotency_key: str = Field(..., description="Caller-supplied idempotency key (UUID recommended)")


class ApproveRequest(BaseModel):
    """Body for POST /v1/actions/{action_id}/approve."""

    approver_ref: str = Field(..., description="Approver reference, e.g. 'user:alice' or 'role:risk_head'")
    decision: str = Field("approved", description="'approved' or 'rejected'")


class InferenceRequest(BaseModel):
    """Body for POST /v1/inference — a governed model call."""

    model_id: str = Field(..., description="Model id, e.g. 'gpt-4' or 'llama3'")
    model_version: str = Field("", description="Optional model version")
    prompt_text: str = Field(..., description="Raw prompt; PII is masked by the gateway before transmission")
    payload: dict[str, Any] = Field(default_factory=dict, description="Optional structured payload (sensitive fields masked)")
    idempotency_key: str = Field(..., description="Caller-supplied idempotency key (UUID recommended)")


# ── Response schemas ──────────────────────────────────────────────────────────────


class ActionResponse(BaseModel):
    """Response for propose and action status endpoints."""

    action_id: str
    state: str
    type: str
    tenant: str
    actor_id: str


class InferenceResponse(BaseModel):
    """Response for POST /v1/inference."""

    content: str
    model_id: str
    prompt_hash: str
    response_hash: str
    action_id: str
    state: str


class LedgerEntryResponse(BaseModel):
    """One sealed ledger entry."""

    ledger_seq: int
    action_id: str
    action_type: str
    actor_id: str
    decision: str
    policy_versions: list[str]
    sealed_at: str  # ISO 8601
    approver: str | None = None


class LedgerTrailResponse(BaseModel):
    """Response for GET /v1/ledger/{tenant}/trail."""

    tenant: str
    entries: list[LedgerEntryResponse]
    count: int


class AuthorizeRequest(BaseModel):
    """Body for POST /v1/authorize — a pure policy-decision query.

    The actor is NEVER supplied by the caller; it is resolved from the bearer token. ``record``
    overrides the profile's ``seal_to_ledger`` flag: None = follow the profile (default all() seals
    every decision), True = always seal, False = never seal.
    """

    type: str = Field(..., description="Action type to authorize (e.g. 'payments.wire')")
    payload: dict[str, Any] = Field(default_factory=dict, description="Optional action payload")
    idempotency_key: str | None = Field(None, description="Optional caller-supplied key")
    record: bool | None = Field(None, description="Override whether to seal this decision to the ledger")


class AuthorizeResponse(BaseModel):
    """Response for POST /v1/authorize.

    Always returns 200 — the HTTP status never encodes the verdict. Check ``allowed`` or
    ``decision`` in the body. The caller is the enforcement point.
    """

    decision: str
    allowed: bool
    actor_id: str
    reason: str | None = None
    policy_versions: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    enforced_layers: list[str] = Field(default_factory=list)
    sealed: bool = False
    ledger_seq: int | None = None


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    error: str
    code: str
    detail: dict[str, Any] = Field(default_factory=dict)


# ── Policy management (K·01 authoring API) ─────────────────────────────────────────

_VALID_DECISIONS = {d.value for d in Decision}


class PolicyRegisterRequest(BaseModel):
    """Body for POST /v1/policies — register a new policy version.

    The server always registers as DRAFT; there is intentionally no ``lifecycle`` field. Lifecycle
    advances only via the explicit submit / activate / deprecate endpoints.
    """

    id: str = Field(..., description="Policy id, dot-namespaced (e.g. 'ciro.ifrs9.stage_transition')")
    version: int = Field(..., ge=1, description="Monotonic version number (>= 1)")
    governs: str = Field(..., description="Action type this policy governs; '*' is a wildcard")
    scope: dict[str, str] = Field(..., description="e.g. {'tenant': '*'} or {'tenant': 'ciro-bank'}")
    condition: str = Field(..., description="CEL expression; compiled at registration")
    decision: str = Field(..., description="One of: allow | deny | require_approval")
    approvers: list[str] = Field(default_factory=list, description="Required only for require_approval")
    regulatory_refs: list[str] = Field(default_factory=list, description="K·14 regulation references")

    @field_validator("decision")
    @classmethod
    def _decision_is_valid(cls, v: str) -> str:
        normalized = v.lower()
        if normalized not in _VALID_DECISIONS:
            raise ValueError(f"decision must be one of {sorted(_VALID_DECISIONS)}, got {v!r}")
        return normalized

    @model_validator(mode="after")
    def _approvers_required_for_approval(self) -> "PolicyRegisterRequest":
        if self.decision == Decision.REQUIRE_APPROVAL.value and not self.approvers:
            raise ValueError("decision 'require_approval' requires a non-empty approvers list")
        return self


class ImpactReportRequest(BaseModel):
    """Body for PUT /v1/policies/{id}/versions/{v}/impact-report (and the inline activate report).

    ``policy_id`` / ``policy_version`` are taken from the URL path, not the body — this eliminates
    the mismatch class of F-10 errors entirely.
    """

    reviewed_by: str = Field(..., description="Reviewer identity (e.g. 'user:compliance_officer')")
    reviewed_at: datetime = Field(..., description="Review timestamp (ISO 8601)")
    decision_distribution: dict[str, float] = Field(default_factory=dict)
    flip_count: int = Field(0, ge=0)
    fairness_delta: float = 0.0
    acknowledged: bool = Field(..., description="Must be True to pass the F-10 activation gate")


class ActivateRequest(BaseModel):
    """Body for POST /v1/policies/{id}/versions/{v}/activate.

    Provide ``impact_report`` inline, or omit it to use a report previously uploaded via PUT.
    """

    impact_report: ImpactReportRequest | None = None


class PolicyResponse(BaseModel):
    """A policy envelope, sans the non-serialisable compiled condition."""

    id: str
    version: int
    governs: str
    scope: dict[str, str]
    condition: str
    decision: str
    approvers: list[str]
    regulatory_refs: list[str]
    lifecycle: str


class PolicyListResponse(BaseModel):
    """Response for the policy list / versions endpoints."""

    policies: list[PolicyResponse]
    count: int


class ImpactReportResponse(BaseModel):
    """An echo of a stored impact report."""

    policy_id: str
    policy_version: int
    reviewed_by: str
    reviewed_at: str  # ISO 8601
    decision_distribution: dict[str, float]
    flip_count: int
    fairness_delta: float
    acknowledged: bool


class SimulateRequest(BaseModel):
    """Body for POST /v1/policies/{id}/versions/{v}/simulate.

    Runs a K·13 counterfactual backtest of the candidate policy version against the tenant's
    sealed ledger entries, assembles an F-10 ImpactReport, and (optionally) stores it. The
    assembled report is NOT acknowledged — a reviewer must acknowledge it before activation.
    """

    reviewed_by: str = Field(..., description="Reviewer identity recorded on the assembled report")
    group_key: str | None = Field(
        None,
        description="Protected-attribute payload key; when set, a K·09 fairness sweep is run "
        "and its max delta is recorded on the report",
    )
    auto_store: bool = Field(
        False, description="Persist the assembled report immediately so activate can reference it"
    )


class SimulateResponse(BaseModel):
    """Response for the simulate endpoint — the assembled report plus the backtest stats."""

    impact_report: ImpactReportResponse
    run_id: str
    ledger_entries_evaluated: int
    decisions_flipped: int
    flip_rate: float
    fairness_delta: float | None = None
    stored: bool


# ── Dashboard read-models ───────────────────────────────────────────────────────────


class DashboardOverviewResponse(BaseModel):
    """Aggregate governance snapshot for a tenant."""

    tenant: str
    total_governed: int
    decision_counts: dict[str, int]
    denial_rate: float
    last_ledger_seq: int | None = None


class DayBucket(BaseModel):
    """Decision counts for a single UTC day."""

    date: str  # YYYY-MM-DD
    decision_counts: dict[str, int]
    total: int


class DecisionTimelineResponse(BaseModel):
    """Per-day decision counts over a trailing window."""

    tenant: str
    window_days: int
    buckets: list[DayBucket]


class TopActionEntry(BaseModel):
    """One action type with its volume and denial count."""

    action_type: str
    total: int
    denials: int


class TopActionsResponse(BaseModel):
    """Top action types by volume and by denial count."""

    tenant: str
    by_volume: list[TopActionEntry]
    by_denials: list[TopActionEntry]


class HitlQueueResponse(BaseModel):
    """Current HITL approval queue depth."""

    tenant: str
    pending: int


# ── HITL approvals (operator queue) ─────────────────────────────────────────────────


class ApprovalRecordResponse(BaseModel):
    """One pending/decided HITL approval record."""

    handle_id: str
    action_id: str
    tenant: str
    required_approvers: list[str]
    requested_at: str  # ISO 8601
    decision: str
    decided_by: str | None = None
    decided_at: str | None = None
    expires_at: str | None = None
    proposed_by: str | None = None


class ApprovalListResponse(BaseModel):
    """Response for GET /v1/approvals."""

    approvals: list[ApprovalRecordResponse]
    count: int


# ── Starter policy packs (import a regulatory baseline as DRAFTs) ────────────────


class PolicyPackPolicyResponse(BaseModel):
    """One rule inside a starter pack (preview only — not yet registered)."""

    id: str
    title: str
    description: str
    governs: str
    condition: str
    decision: str
    approvers: list[str] = Field(default_factory=list)
    regulatory_refs: list[str] = Field(default_factory=list)


class PolicyPackActionTypeResponse(BaseModel):
    """How to invoke one of the pack's governed action types — the payload contract + an example."""

    name: str
    use_case: str
    payload: str
    example: str


class PolicyPackResponse(BaseModel):
    """A starter policy pack the tenant can import into their own DRAFT policies."""

    id: str
    name: str
    regulation: str
    description: str
    summary: str = ""
    usage: str = ""
    action_types: list[str]
    action_specs: list[PolicyPackActionTypeResponse] = Field(default_factory=list)
    policy_count: int
    policies: list[PolicyPackPolicyResponse] = Field(default_factory=list)


class PolicyPackListResponse(BaseModel):
    packs: list[PolicyPackResponse]
    count: int


class PolicyPackImportResponse(BaseModel):
    """Result of importing a pack: which policies were registered as DRAFTs, which were skipped."""

    pack_id: str
    imported: list[str]
    skipped: list[dict[str, str]] = Field(default_factory=list)
    count: int
