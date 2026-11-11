"""Policy management routes — the K·01 authoring API (gaps #3 + #6).

A thin REST surface over the Kernel's policy write-through primitives, with route-level
control-plane authorization. The caller is the actor the API authenticated, and every endpoint
requires that actor to hold a policy-admin role (``kernel.policy_admin_roles``).

    POST /v1/policies                                  → 201 register a DRAFT version
    GET  /v1/policies?lifecycle=ACTIVATED              → 200 list policies (optional filter)
    GET  /v1/policies/{id}                             → 200 list all versions of a policy
    GET  /v1/policies/{id}/versions/{v}                → 200 one version
    POST /v1/policies/{id}/versions/{v}/submit         → 200 DRAFT → REVIEW
    PUT  /v1/policies/{id}/versions/{v}/impact-report  → 200 store an F-10 impact report
    POST /v1/policies/{id}/versions/{v}/activate       → 200 REVIEW → ACTIVATED (F-10 gate)
    POST /v1/policies/{id}/versions/{v}/deprecate      → 200 → DEPRECATED

Why route-level role checks (not governed actions): policy CRUD bootstraps the policy store, so an
empty fail-closed store could never register its first policy if CRUD were itself policy-governed.
"""

from __future__ import annotations

from typing import Any

from celpy import celtypes
from fastapi import APIRouter, HTTPException, Query, Request, status

from quaicu.core.errors import (
    PolicyActivationError,
    PolicyCompileError,
    PolicyTransitionError,
)
from quaicu.core.fairness.engine import compute_fairness_delta, compute_fairness_metrics
from quaicu.core.fairness.model import DecisionRecord
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.sandbox.bridge import assemble_impact_report
from quaicu.core.sandbox.engine import run_counterfactual_backtest
from quaicu.core.types import Actor, ApproverRef, Decision
from quaicu.delivery.api.deps import current_actor, enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import (
    ActivateRequest,
    ImpactReportRequest,
    ImpactReportResponse,
    PolicyListResponse,
    PolicyRegisterRequest,
    PolicyResponse,
    SimulateRequest,
    SimulateResponse,
)
from quaicu.delivery.api.scopes import POLICY_ADMIN
from quaicu.delivery.sdk.kernel import Kernel

router = APIRouter(prefix="/v1/policies", tags=["policies"])


# ── Control-plane authorization ─────────────────────────────────────────────────


async def _require_policy_admin(request: Request) -> tuple[Kernel, Actor]:
    """Require the authenticated caller to hold a policy-admin role.

    Returns (kernel, actor). Raises:
      - 503 if no policy store is configured.
      - 403 if the actor holds none of ``kernel.policy_admin_roles`` (or a host principal lacks
        the ``policy:admin`` scope).
    """
    kernel: Kernel = get_kernel(request)
    if not kernel.has_policy_store:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Policy management requires the CEL policy engine (policy = \"cel_policy\")",
                "code": "POLICY_STORE_NOT_CONFIGURED",
            },
        )
    enforce_scope(request, POLICY_ADMIN)
    actor = current_actor(request)

    actor_roles = {r if r.startswith("role:") else f"role:{r}" for r in actor.roles}
    if not actor_roles & set(kernel.policy_admin_roles):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Policy administration requires a policy-admin role",
                "code": "POLICY_ADMIN_REQUIRED",
                "detail": {"required_any_of": list(kernel.policy_admin_roles)},
            },
        )
    return kernel, actor


# ── Converters ──────────────────────────────────────────────────────────────────


def _to_envelope(req: PolicyRegisterRequest, tenant: str) -> PolicyEnvelope:
    """Build a DRAFT envelope from a register request (server always forces DRAFT lifecycle).

    Stamps ``scope.tenant`` to this kernel's tenant: the server — not the caller-supplied scope —
    owns tenant attribution, so a policy can never be authored for a different tenant.
    """
    return PolicyEnvelope(
        id=req.id,
        version=req.version,
        governs=req.governs,
        scope={**dict(req.scope), "tenant": tenant},
        condition=req.condition,
        decision=Decision(req.decision),
        approvers=tuple(ApproverRef(a) for a in req.approvers),
        regulatory_refs=tuple(req.regulatory_refs),
        lifecycle=PolicyLifecycle.DRAFT,
    )


def _to_report(policy_id: str, version: int, req: ImpactReportRequest) -> ImpactReport:
    """Build an ImpactReport, injecting the policy id/version from the URL path."""
    return ImpactReport(
        policy_id=policy_id,
        policy_version=version,
        reviewed_by=req.reviewed_by,
        reviewed_at=req.reviewed_at,
        decision_distribution=dict(req.decision_distribution),
        flip_count=req.flip_count,
        fairness_delta=req.fairness_delta,
        acknowledged=req.acknowledged,
    )


def _policy_response(env: PolicyEnvelope) -> PolicyResponse:
    return PolicyResponse(
        id=env.id,
        version=env.version,
        governs=env.governs,
        scope=dict(env.scope),
        condition=env.condition,
        decision=env.decision.value,
        approvers=[str(a) for a in env.approvers],
        regulatory_refs=list(env.regulatory_refs),
        lifecycle=env.lifecycle.value,
    )


def _impact_report_response(report: ImpactReport) -> ImpactReportResponse:
    return ImpactReportResponse(
        policy_id=report.policy_id,
        policy_version=report.policy_version,
        reviewed_by=report.reviewed_by,
        reviewed_at=report.reviewed_at.isoformat(),
        decision_distribution=dict(report.decision_distribution),
        flip_count=report.flip_count,
        fairness_delta=report.fairness_delta,
        acknowledged=report.acknowledged,
    )


def _cel_activation(
    action_type: str, payload: dict[str, Any], actor_id: str, actor_roles: tuple[str, ...]
) -> dict[str, Any]:
    """Build a dot-free CEL activation from a recorded action's type, payload, and actor identity.

    Mirrors ``quaicu/core/policy/evaluator._build_activation``'s payload flattening (``payload_<key>``)
    and its bare ``actor_id`` / ``actor_roles`` variables. Both actor fields are replayed from the
    sealed ``LedgerEntry`` (``actor_id`` + ``actor_roles``, sealed under ADR-0006), so candidate
    policies that gate on the actor re-evaluate faithfully.
    """
    activation: dict[str, Any] = {
        "action_type": celtypes.StringType(action_type),
        "actor_id": celtypes.StringType(actor_id),
        "actor_roles": celtypes.ListType([celtypes.StringType(r) for r in actor_roles]),
    }
    for key, val in payload.items():
        cel_key = f"payload_{key}"
        if isinstance(val, bool):
            activation[cel_key] = celtypes.BoolType(val)
        elif isinstance(val, int):
            activation[cel_key] = celtypes.IntType(val)
        elif isinstance(val, float):
            activation[cel_key] = celtypes.DoubleType(val)
        elif isinstance(val, str):
            activation[cel_key] = celtypes.StringType(val)
        else:
            activation[cel_key] = celtypes.StringType(str(val))
    return activation


def _candidate_evaluator(envelope: PolicyEnvelope):
    """Return a side-effect-free CandidateEvaluator that re-derives this policy's decision.

    Fail-closed: a missing compiled program or any CEL fault scores the entry as ``"deny"`` —
    a backtest must never silently treat an un-evaluable entry as allowed.
    """

    def evaluate(
        action_type: str,
        payload: dict[str, Any],
        recorded_outputs: dict[str, Any],
        actor_id: str,
        actor_roles: tuple[str, ...],
    ) -> str:
        prog = envelope.compiled_condition
        if prog is None:
            return Decision.DENY.value
        try:
            matched = bool(prog.evaluate(_cel_activation(action_type, payload, actor_id, actor_roles)))
        except Exception:  # noqa: BLE001 — any CEL fault → fail-closed deny in the shadow run
            return Decision.DENY.value
        # Condition true → this policy's decision applies; false → it does not govern, so the
        # action would fall through to a fail-closed deny (no other policy is simulated here).
        return envelope.decision.value if matched else Decision.DENY.value

    return evaluate


def _get_or_404(kernel: Kernel, policy_id: str, version: int) -> PolicyEnvelope:
    assert kernel.policy_store is not None  # guaranteed by _require_policy_admin
    env = kernel.policy_store.get(policy_id, version)
    if env is None:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Policy {policy_id}@v{version} not found", "code": "POLICY_NOT_FOUND"},
        )
    return env


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=PolicyResponse,
    summary="Register a new policy version (DRAFT)",
)
async def register_policy(body: PolicyRegisterRequest, request: Request) -> PolicyResponse:
    """Compile and persist a new DRAFT policy version.

    400 if the CEL condition fails to compile; 409 if the (id, version) is already finalised.
    """
    kernel, _ = await _require_policy_admin(request)
    tenant = get_request_tenant(request)
    try:
        env = await kernel.register_policy(_to_envelope(body, str(tenant)))
    except PolicyCompileError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc), "code": exc.code, "detail": exc.detail})
    except PolicyTransitionError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc), "code": exc.code, "detail": exc.detail})
    return _policy_response(env)


@router.get(
    "",
    response_model=PolicyListResponse,
    summary="List policies (optionally filtered by lifecycle)",
)
async def list_policies(
    request: Request,
    lifecycle: str | None = Query(None, description="Filter: DRAFT | REVIEW | ACTIVATED | DEPRECATED"),
) -> PolicyListResponse:
    kernel, _ = await _require_policy_admin(request)
    assert kernel.policy_store is not None
    lc: PolicyLifecycle | None = None
    if lifecycle is not None:
        try:
            lc = PolicyLifecycle(lifecycle.upper())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": f"Invalid lifecycle {lifecycle!r}",
                    "code": "INVALID_LIFECYCLE",
                    "detail": {"valid": [s.value for s in PolicyLifecycle]},
                },
            )
    envelopes = kernel.policy_store.list_policies(lc)
    return PolicyListResponse(
        policies=[_policy_response(e) for e in envelopes], count=len(envelopes)
    )


@router.get(
    "/{policy_id}",
    response_model=PolicyListResponse,
    summary="List all versions of a policy",
)
async def list_versions(policy_id: str, request: Request) -> PolicyListResponse:
    kernel, _ = await _require_policy_admin(request)
    assert kernel.policy_store is not None
    envelopes = kernel.policy_store.list_versions(policy_id)
    if not envelopes:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Policy {policy_id!r} not found", "code": "POLICY_NOT_FOUND"},
        )
    return PolicyListResponse(
        policies=[_policy_response(e) for e in envelopes], count=len(envelopes)
    )


@router.get(
    "/{policy_id}/versions/{version}",
    response_model=PolicyResponse,
    summary="Get a single policy version",
)
async def get_version(policy_id: str, version: int, request: Request) -> PolicyResponse:
    kernel, _ = await _require_policy_admin(request)
    return _policy_response(_get_or_404(kernel, policy_id, version))


@router.post(
    "/{policy_id}/versions/{version}/submit",
    response_model=PolicyResponse,
    summary="Submit a DRAFT policy for review",
)
async def submit_for_review(policy_id: str, version: int, request: Request) -> PolicyResponse:
    """Transition DRAFT → REVIEW. 404 if absent; 409 if not in DRAFT."""
    kernel, _ = await _require_policy_admin(request)
    _get_or_404(kernel, policy_id, version)
    try:
        env = await kernel.submit_policy_for_review(policy_id, version)
    except PolicyTransitionError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc), "code": exc.code, "detail": exc.detail})
    return _policy_response(env)


@router.put(
    "/{policy_id}/versions/{version}/impact-report",
    response_model=ImpactReportResponse,
    summary="Store an F-10 impact report for a policy version",
)
async def upload_impact_report(
    policy_id: str, version: int, body: ImpactReportRequest, request: Request
) -> ImpactReportResponse:
    """Persist the backtest impact report a later activation can reference. 404 if policy absent."""
    kernel, _ = await _require_policy_admin(request)
    _get_or_404(kernel, policy_id, version)
    report = _to_report(policy_id, version, body)
    await kernel.store_policy_impact_report(report)
    return _impact_report_response(report)


@router.post(
    "/{policy_id}/versions/{version}/activate",
    response_model=PolicyResponse,
    summary="Activate a REVIEW policy (F-10 gate)",
)
async def activate_policy(
    policy_id: str, version: int, body: ActivateRequest, request: Request
) -> PolicyResponse:
    """Run the F-10 activation gate and transition REVIEW → ACTIVATED.

    Uses the inline ``impact_report`` if provided, else a previously uploaded report. 404 if the
    policy is absent; 409 if no report is on file or the F-10 gate fails (e.g. not acknowledged).
    """
    kernel, _ = await _require_policy_admin(request)
    assert kernel.policy_store is not None
    _get_or_404(kernel, policy_id, version)

    if body.impact_report is not None:
        report = _to_report(policy_id, version, body.impact_report)
    else:
        report = kernel.policy_store.get_impact_report(policy_id, version)
        if report is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": f"No impact report on file for {policy_id}@v{version}; "
                    "upload one or pass it inline.",
                    "code": "POLICY_ACTIVATION_BLOCKED",
                },
            )
    try:
        env = await kernel.activate_policy(policy_id, version, report)
    except PolicyActivationError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc), "code": exc.code, "detail": exc.detail})
    return _policy_response(env)


@router.post(
    "/{policy_id}/versions/{version}/simulate",
    response_model=SimulateResponse,
    summary="Backtest a REVIEW policy and assemble an F-10 impact report",
)
async def simulate_policy(
    policy_id: str, version: int, body: SimulateRequest, request: Request
) -> SimulateResponse:
    """Run a K·13 counterfactual backtest and assemble the F-10 ImpactReport.

    Re-evaluates the candidate policy version against the tenant's sealed ledger entries (no
    model re-calls — recorded outputs are reused, F-09), assembles an ImpactReport from the
    flip statistics (and an optional K·09 fairness sweep), and optionally stores it. The
    assembled report is NOT acknowledged — activation still requires a reviewer to acknowledge
    it. 404 if the policy is absent; 409 if it is not in REVIEW.
    """
    kernel, _ = await _require_policy_admin(request)
    tenant = get_request_tenant(request)
    envelope = _get_or_404(kernel, policy_id, version)
    if envelope.lifecycle is not PolicyLifecycle.REVIEW:
        raise HTTPException(
            status_code=409,
            detail={
                "error": f"Policy {policy_id}@v{version} is {envelope.lifecycle.value}; "
                "only REVIEW policies can be simulated.",
                "code": "POLICY_NOT_IN_REVIEW",
                "detail": {"lifecycle": envelope.lifecycle.value},
            },
        )

    ledger = kernel.engine._ledger  # type: ignore[attr-defined]
    entries = ledger.get_entries(tenant)

    run, shadow = run_counterfactual_backtest(
        entries=entries,
        candidate_evaluator=_candidate_evaluator(envelope),
        policy_id=policy_id,
        policy_version=str(version),
        tenant_id=str(tenant),
    )

    fairness_delta = None
    if body.group_key and entries:
        entry_by_id = {str(e.action_id): e for e in entries}
        active_records: list[DecisionRecord] = []
        candidate_records: list[DecisionRecord] = []
        for sd in shadow:
            entry = entry_by_id.get(sd.action_id)
            if entry is None:
                continue
            group_value = str(entry.recorded_result.get(body.group_key, "__unknown__"))
            active_records.append(
                DecisionRecord(
                    action_id=sd.action_id,
                    tenant_id=sd.tenant_id,
                    decision=sd.active_decision,
                    group_value=group_value,
                )
            )
            candidate_records.append(
                DecisionRecord(
                    action_id=sd.action_id,
                    tenant_id=sd.tenant_id,
                    decision=sd.candidate_decision,
                    group_value=group_value,
                )
            )
        active_metrics = compute_fairness_metrics(active_records, body.group_key, str(tenant))
        candidate_metrics = compute_fairness_metrics(
            candidate_records, body.group_key, str(tenant)
        )
        fairness_delta = compute_fairness_delta(active_metrics, candidate_metrics)

    report = assemble_impact_report(
        run, reviewed_by=body.reviewed_by, fairness_delta=fairness_delta
    )

    stored = False
    if body.auto_store:
        await kernel.store_policy_impact_report(report)
        stored = True

    return SimulateResponse(
        impact_report=_impact_report_response(report),
        run_id=run.run_id,
        ledger_entries_evaluated=run.ledger_entries_evaluated,
        decisions_flipped=run.decisions_flipped,
        flip_rate=run.flip_rate,
        fairness_delta=fairness_delta.max_delta if fairness_delta is not None else None,
        stored=stored,
    )


@router.post(
    "/{policy_id}/versions/{version}/deprecate",
    response_model=PolicyResponse,
    summary="Deprecate a policy version",
)
async def deprecate_policy(policy_id: str, version: int, request: Request) -> PolicyResponse:
    """Transition a policy to DEPRECATED (stops matching in evaluation). 404 if absent."""
    kernel, _ = await _require_policy_admin(request)
    _get_or_404(kernel, policy_id, version)
    env = await kernel.deprecate_policy(policy_id, version)
    return _policy_response(env)
