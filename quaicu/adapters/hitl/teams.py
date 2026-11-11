"""Microsoft Teams HITLPort adapter (K·03) — Adaptive Card with approve/reject actions.

Extends `InProcessHITLPort` (like the email adapter) so the approval store, poll/approve/reject, the
deferred-resume flow, and `/v1/approvals` all keep working unchanged. The only addition: on
`request_approval`, POST an Adaptive Card to a configured Teams **incoming webhook**. The card's two
actions are `Action.OpenUrl` links to the existing signed confirm-page flow
(`/v1/approvals/link/{token}`), so the decision round-trip, single-use, and tenant isolation (the token
encodes the tenant; the route enforces it) are the same as the email channel — no new decision route.

A non-2xx response or transport error raises `HITLPortError` (fail-closed — the HITLPort contract halts
the action on dispatch failure).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.hitl.links import ApprovalLinkSigner
from quaicu.core.hitl.store import ApprovalStore
from quaicu.core.types import Action, ApprovalHandle, ApproverRef, TenantId

log = logging.getLogger("quaicu.hitl.teams")

# (url, json_body) -> HTTP status code. Injectable so tests need no network.
HttpPost = Callable[[str, dict[str, Any]], Awaitable[int]]


async def _httpx_post(url: str, body: dict[str, Any]) -> int:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, json=body)
        return resp.status_code


class MicrosoftTeamsHITLAdapter(InProcessHITLPort):
    """In-process HITL port that also posts an approval Adaptive Card to a Teams webhook."""

    def __init__(
        self,
        *,
        webhook_url: str,
        signer: ApprovalLinkSigner,
        link_base_url: str,
        approver_id: str,
        approver_roles: tuple[str, ...] = (),
        link_ttl_seconds: int = 604800,  # 7 days
        timeout_seconds: int = 0,  # 0 = no expiry: a pending approval waits until a human decides (D1-4)
        store: ApprovalStore | None = None,
        http_post: HttpPost = _httpx_post,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds, store=store)
        if not webhook_url:
            raise ValueError("MicrosoftTeamsHITLAdapter requires a webhook_url.")
        self._webhook_url = webhook_url
        self._signer = signer
        self._base_url = link_base_url.rstrip("/")
        self._approver_id = approver_id
        self._approver_roles = tuple(approver_roles)
        self._link_ttl = int(link_ttl_seconds)
        self._http_post = http_post

    async def request_approval(
        self,
        *,
        action: Action,
        approvers: list[ApproverRef],
        tenant: TenantId,
    ) -> ApprovalHandle:
        handle_id = self._new_handle_id()
        approve = self._link(handle_id=handle_id, tenant=str(tenant), decision="approve")
        reject = self._link(handle_id=handle_id, tenant=str(tenant), decision="reject")
        record = self._build_record(
            handle_id=handle_id,
            action=action,
            approvers=approvers,
            tenant=tenant,
            notify_channel="teams",
            notify_target=self._webhook_url,
            resume_link=approve,
        )
        # Post FIRST (fail-closed): persist a PENDING record only once the card was delivered, so a
        # PENDING record always implies a delivered notification and a post failure leaves no orphan.
        card = self._card(action=action, approve=approve, reject=reject)
        try:
            status = await self._http_post(self._webhook_url, card)
        except Exception as exc:  # noqa: BLE001 — dispatch failure must fail-closed (HALT the action)
            raise HITLPortError(
                f"HITL Teams post failed: {exc}",
                detail={"action_id": str(action.id), "handle_id": handle_id},
            ) from exc
        if not 200 <= status < 300:
            raise HITLPortError(
                f"HITL Teams webhook returned HTTP {status}",
                detail={"action_id": str(action.id), "handle_id": handle_id, "status": status},
            )
        self._store.put(record)
        log.info("HITL Teams card posted: handle=%s action=%s", handle_id, action.id)
        return ApprovalHandle(id=handle_id, tenant=tenant, created_at=record.requested_at)

    def _link(self, *, handle_id: str, tenant: str, decision: str) -> str:
        token = self._signer.sign(
            handle_id=handle_id,
            tenant=tenant,
            decision=decision,
            approver_id=self._approver_id,
            approver_roles=self._approver_roles,
            ttl_seconds=self._link_ttl,
        )
        return f"{self._base_url}/v1/approvals/link/{token}"

    def _card(self, *, action: Action, approve: str, reject: str) -> dict[str, Any]:
        adaptive = {
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": "1.4",
            "body": [
                {"type": "TextBlock", "size": "Medium", "weight": "Bolder",
                 "text": "Approval needed"},
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Action", "value": action.type},
                        {"title": "Action id", "value": str(action.id)},
                        {"title": "Requested by", "value": str(action.actor.id)},
                    ],
                },
                {"type": "TextBlock", "isSubtle": True, "wrap": True, "size": "Small",
                 "text": "Each link opens a confirmation page and can be used once. Links expire."},
            ],
            "actions": [
                {"type": "Action.OpenUrl", "title": "Review & approve", "url": approve},
                {"type": "Action.OpenUrl", "title": "Review & reject", "url": reject},
            ],
        }
        # Teams incoming-webhook envelope for an Adaptive Card.
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": adaptive,
                }
            ],
        }
