"""Dashboard read-model routes — governance aggregates over the transparency log (gap #5).

Thin, read-only projections computed on demand from the tenant-scoped ledger entries and the
HITL queue. Every endpoint requires a bearer token and the path tenant must equal this kernel's
tenant (F-07) — a mismatch is 403, never a silent empty result.

    GET /v1/dashboard/{tenant}/overview        → 200 aggregate snapshot
    GET /v1/dashboard/{tenant}/decisions        → 200 per-day decision counts
    GET /v1/dashboard/{tenant}/actions/top      → 200 top action types
    GET /v1/dashboard/{tenant}/hitl/queue       → 200 pending approval depth

These are full-scan projections (acceptable for the MVP); a materialized read-model replaces the
scan when ledger volume warrants it.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query, Request

from quaicu.core.types import TenantId
from quaicu.delivery.api.deps import enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import (
    DashboardOverviewResponse,
    DayBucket,
    DecisionTimelineResponse,
    HitlQueueResponse,
    TopActionEntry,
    TopActionsResponse,
)
from quaicu.delivery.api.scopes import DASHBOARD_READ

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])


def _authorize_tenant(request: Request, tenant: str):
    """Enforce tenant isolation (the caller is already authenticated). Returns (kernel, entries)."""
    enforce_scope(request, DASHBOARD_READ)
    kernel = get_kernel(request)
    if tenant != str(get_request_tenant(request)):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Cannot read another tenant's dashboard",
                "code": "TENANT_ISOLATION",
            },
        )
    ledger = kernel.engine._ledger  # type: ignore[attr-defined]
    return kernel, ledger.get_entries(TenantId(tenant))


@router.get(
    "/{tenant}/overview",
    response_model=DashboardOverviewResponse,
    summary="Aggregate governance snapshot",
)
async def overview(tenant: str, request: Request) -> DashboardOverviewResponse:
    _, entries = _authorize_tenant(request, tenant)
    counts: dict[str, int] = defaultdict(int)
    for e in entries:
        counts[e.decision.value] += 1
    total = len(entries)
    denials = counts.get("deny", 0)
    last_seq = max((e.ledger_seq for e in entries), default=None)
    return DashboardOverviewResponse(
        tenant=tenant,
        total_governed=total,
        decision_counts=dict(counts),
        denial_rate=(denials / total) if total else 0.0,
        last_ledger_seq=last_seq,
    )


@router.get(
    "/{tenant}/decisions",
    response_model=DecisionTimelineResponse,
    summary="Per-day decision counts over a trailing window",
)
async def decisions_timeline(
    tenant: str,
    request: Request,
    window_days: int = Query(7, ge=1, le=365, description="Trailing window length in days"),
) -> DecisionTimelineResponse:
    _, entries = _authorize_tenant(request, tenant)
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=window_days)
    by_day: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in entries:
        if e.sealed_at < cutoff:
            continue
        day = e.sealed_at.date().isoformat()
        by_day[day][e.decision.value] += 1
    buckets = [
        DayBucket(date=day, decision_counts=dict(dc), total=sum(dc.values()))
        for day, dc in sorted(by_day.items())
    ]
    return DecisionTimelineResponse(tenant=tenant, window_days=window_days, buckets=buckets)


@router.get(
    "/{tenant}/actions/top",
    response_model=TopActionsResponse,
    summary="Top action types by volume and by denials",
)
async def top_actions(
    tenant: str,
    request: Request,
    limit: int = Query(10, ge=1, le=100, description="Max action types per ranking"),
) -> TopActionsResponse:
    _, entries = _authorize_tenant(request, tenant)
    totals: dict[str, int] = defaultdict(int)
    denials: dict[str, int] = defaultdict(int)
    for e in entries:
        totals[e.action_type] += 1
        if e.decision.value == "deny":
            denials[e.action_type] += 1

    def _entry(at: str) -> TopActionEntry:
        return TopActionEntry(action_type=at, total=totals[at], denials=denials.get(at, 0))

    by_volume = [
        _entry(at) for at, _ in sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    ]
    by_denials = [
        _entry(at)
        for at, cnt in sorted(denials.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
        if cnt > 0
    ]
    return TopActionsResponse(tenant=tenant, by_volume=by_volume, by_denials=by_denials)


@router.get(
    "/{tenant}/hitl/queue",
    response_model=HitlQueueResponse,
    summary="Pending HITL approval queue depth",
)
async def hitl_queue(tenant: str, request: Request) -> HitlQueueResponse:
    kernel, _ = _authorize_tenant(request, tenant)
    return HitlQueueResponse(tenant=tenant, pending=kernel.hitl_queue_depth)
