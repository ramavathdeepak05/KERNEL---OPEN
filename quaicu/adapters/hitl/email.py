"""Email HITLPort adapter (K·03) — signed, single-use approve/reject links.

Extends `InProcessHITLPort` so the approval store, `poll`/`approve`/`reject`, the deferred-resume flow
(`kernel.decide_approval` → `resume_after_approval`), and the `/v1/approvals` operator queue all keep
working unchanged. The only addition: on `request_approval`, email the configured approver an approve
link and a reject link, each an HMAC-signed, expiring token (`ApprovalLinkSigner`). Clicking a link
opens a confirm page served by `/v1/approvals/link/{token}`; the decision is committed by a POST there.

Single-use is enforced by the store (an already-decided record can't be decided again). A send failure
raises `HITLPortError` (fail-closed — the HITLPort contract halts the action on dispatch failure).

Recipient (MVP): a single configured `approver_email` (the compliance inbox) with a configured approver
identity encoded in the link so the decision seals a real approver + honors separation-of-duties.
Per-member routing is a later step (member maker/checker).
"""

from __future__ import annotations

import logging

from quaicu.core.email.port import EmailMessage, EmailSender
from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.hitl.links import ApprovalLinkSigner
from quaicu.core.hitl.store import ApprovalStore
from quaicu.core.types import Action, ApprovalHandle, ApproverRef, TenantId

log = logging.getLogger("quaicu.hitl.email")


class EmailHITLAdapter(InProcessHITLPort):
    """In-process HITL port that also emails signed approve/reject links to the approver."""

    def __init__(
        self,
        *,
        sender: EmailSender,
        signer: ApprovalLinkSigner,
        link_base_url: str,
        approver_email: str,
        approver_id: str,
        approver_roles: tuple[str, ...] = (),
        link_ttl_seconds: int = 604800,  # 7 days
        timeout_seconds: int = 0,  # 0 = no expiry: a pending approval waits until a human decides (D1-4)
        store: ApprovalStore | None = None,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds, store=store)
        if not approver_email:
            raise ValueError("EmailHITLAdapter requires an approver_email.")
        self._sender = sender
        self._signer = signer
        self._base_url = link_base_url.rstrip("/")
        self._approver_email = approver_email
        self._approver_id = approver_id
        self._approver_roles = tuple(approver_roles)
        self._link_ttl = int(link_ttl_seconds)

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
            notify_channel="email",
            notify_target=self._approver_email,
            resume_link=approve,
        )
        # Send FIRST (fail-closed): persist a PENDING record only once the approver was notified, so a
        # PENDING record always implies a delivered notification and a send failure leaves no orphan.
        message = self._build_message(action=action, approve=approve, reject=reject)
        try:
            await self._sender.send(message)
        except Exception as exc:  # noqa: BLE001 — dispatch failure must fail-closed (HALT the action)
            raise HITLPortError(
                f"HITL email dispatch failed: {exc}",
                detail={"action_id": str(action.id), "handle_id": handle_id},
            ) from exc
        self._store.put(record)
        log.info(
            "HITL email sent: handle=%s action=%s to=%s", handle_id, action.id, self._approver_email
        )
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

    def _build_message(self, *, action: Action, approve: str, reject: str) -> EmailMessage:
        subject = f"[QUAICU] Approval needed: {action.type}"
        html = (
            f"<p>An action requires your approval.</p>"
            f"<ul><li><b>Action:</b> {action.type}</li>"
            f"<li><b>Action id:</b> {action.id}</li>"
            f"<li><b>Requested by:</b> {action.actor.id}</li></ul>"
            f'<p><a href="{approve}">Review &amp; approve</a> &nbsp;|&nbsp; '
            f'<a href="{reject}">Review &amp; reject</a></p>'
            f"<p style='color:#666;font-size:12px'>Each link opens a confirmation page and can be used "
            f"once. Links expire.</p>"
        )
        text = (
            f"An action requires your approval.\n"
            f"Action: {action.type} ({action.id})\nRequested by: {action.actor.id}\n\n"
            f"Approve: {approve}\nReject:  {reject}\n\n"
            f"Each link opens a confirmation page, is single-use, and expires."
        )
        return EmailMessage(to=self._approver_email, subject=subject, html=html, text=text)
