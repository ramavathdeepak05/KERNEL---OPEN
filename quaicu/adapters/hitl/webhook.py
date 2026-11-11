"""Webhook HITLPort adapter.

POSTs an approval request to a configured URL; polls a callback or status URL
for the decision. Timeout → TIMED_OUT, which the lifecycle maps to DENIED (fail-closed F-03).

This adapter is intentionally stateless — the approval state lives on the webhook
receiver, not in the kernel. The handle carries the URL to poll.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from quaicu.core.errors import HITLPortError, PortTimeoutError
from quaicu.core.types import (
    Action,
    ActorId,
    ApprovalDecision,
    ApprovalHandle,
    ApprovalOutcome,
    ApproverRef,
    TenantId,
)


class WebhookHITLAdapter:
    """HITLPort adapter that dispatches approval requests over HTTP webhooks.

    Args:
        dispatch_url: Endpoint that receives the approval request (POST).
        poll_url: Endpoint to poll for a decision (GET ``{poll_url}/{handle_id}``).
        timeout: HTTP request timeout in seconds (fail-closed on breach).
        api_key: Optional bearer token for the webhook receiver.
    """

    def __init__(
        self,
        dispatch_url: str = "http://localhost:8080/hitl/dispatch",
        poll_url: str = "http://localhost:8080/hitl/status",
        timeout: float = 10.0,
        api_key: str = "",
    ) -> None:
        self._dispatch_url = dispatch_url
        self._poll_url = poll_url
        self._timeout = timeout
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    async def request_approval(
        self,
        *,
        action: Action,
        approvers: list[ApproverRef],
        tenant: TenantId,
    ) -> ApprovalHandle:
        """POST the approval request to the dispatch URL; return a poll handle."""
        body = {
            "action_id": str(action.id),
            "action_type": action.type,
            "tenant": str(tenant),
            "approvers": list(approvers),
            "payload": dict(action.payload),
            "requested_at": datetime.now(tz=timezone.utc).isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._dispatch_url, json=body, headers=self._headers()
                )
        except httpx.TimeoutException as exc:
            raise PortTimeoutError(
                f"HITL dispatch timed out after {self._timeout}s",
                detail={"action_id": str(action.id)},
            ) from exc
        except Exception as exc:
            raise HITLPortError(
                f"HITL dispatch failed: {exc}",
                detail={"action_id": str(action.id)},
            ) from exc

        if resp.status_code not in (200, 201, 202):
            raise HITLPortError(
                f"HITL dispatch returned HTTP {resp.status_code}",
                detail={"body": resp.text[:500]},
            )

        data: dict[str, Any] = resp.json() if resp.content else {}
        handle_id = data.get("handle_id", str(action.id))

        return ApprovalHandle(
            id=handle_id,
            tenant=tenant,
            created_at=datetime.now(tz=timezone.utc),
        )

    async def poll(self, handle: ApprovalHandle) -> ApprovalOutcome:
        """GET the approval status; map the response to an ApprovalOutcome.

        Reads the decider from a ``decided_by`` field in the response body when present, so the
        approving identity is sealed to the ledger (ADR-0007). Unknown or error responses are
        treated as TIMED_OUT (fail-closed).
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(
                    f"{self._poll_url}/{handle.id}",
                    headers=self._headers(),
                )
        except Exception:
            return ApprovalOutcome(ApprovalDecision.TIMED_OUT)  # fail-closed: unreachable webhook

        if resp.status_code != 200:
            return ApprovalOutcome(ApprovalDecision.TIMED_OUT)

        data: dict[str, Any] = resp.json() if resp.content else {}
        raw = str(data.get("decision", "pending")).lower()
        decision = {
            "approved": ApprovalDecision.APPROVED,
            "rejected": ApprovalDecision.REJECTED,
            "timed_out": ApprovalDecision.TIMED_OUT,
        }.get(raw, ApprovalDecision.PENDING)

        raw_decider = data.get("decided_by")
        decided_by = ActorId(str(raw_decider)) if raw_decider else None
        return ApprovalOutcome(decision, decided_by=decided_by)
