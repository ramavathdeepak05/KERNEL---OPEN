"""Email adapters — Resend (REST) and a log-only dev fallback.

`ResendEmailAdapter` POSTs to the Resend REST API directly (no SDK, no new dependency — a blocking
``urllib`` call offloaded to a worker thread). Auth is a bearer API key. `LogOnlyEmailSender` writes
the message to the log instead of sending — the default when no provider is configured, so the email
approval channel is testable locally (the approval link appears in the server log).
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable, Mapping

from quaicu.core.email.port import EmailMessage
from quaicu.core.errors import EmailPortError

log = logging.getLogger("quaicu.email")

# (url, body_bytes, headers) -> (status_code, response_text). Injectable for tests.
HttpPost = Callable[[str, bytes, Mapping[str, str]], Awaitable[tuple[int, str]]]


async def _urllib_post(url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, str]:
    def _do() -> tuple[int, str]:
        req = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 — fixed provider host
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    return await asyncio.to_thread(_do)


class ResendEmailAdapter:
    """Send transactional email via the Resend REST API (https://resend.com/docs/api-reference)."""

    def __init__(
        self,
        *,
        api_key: str,
        sender: str,
        http_post: HttpPost = _urllib_post,
        api_base: str = "https://api.resend.com",
    ) -> None:
        if not api_key:
            raise ValueError("ResendEmailAdapter requires an api_key.")
        self._api_key = api_key
        self._sender = sender
        self._http_post = http_post
        self._api_base = api_base.rstrip("/")

    async def send(self, message: EmailMessage) -> None:
        payload: dict[str, object] = {
            "from": self._sender,
            "to": [message.to],
            "subject": message.subject,
            "html": message.html,
        }
        if message.text:
            payload["text"] = message.text
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Resend's API is behind Cloudflare, which 403s (error 1010) the default
            # "Python-urllib/x" agent as a bot signature. Identify as the kernel instead.
            "User-Agent": "quaicu-kernel/1.0 (+https://quaicu.org)",
        }
        try:
            status, text = await self._http_post(f"{self._api_base}/emails", body, headers)
        except Exception as exc:  # noqa: BLE001 — transport failure → fail-closed for the caller
            raise EmailPortError(f"Resend transport error: {exc}", detail={"to": message.to}) from exc
        if status >= 300:
            raise EmailPortError(
                f"Resend rejected the send (HTTP {status}): {text[:300]}",
                detail={"to": message.to, "status": status},
            )
        log.info("email sent via Resend: to=%s subject=%s", message.to, message.subject)


class LogOnlyEmailSender:
    """Dev/test fallback: log the email instead of sending it (its content becomes visible in the log)."""

    async def send(self, message: EmailMessage) -> None:
        log.warning(
            "EMAIL (log-only, not sent) → to=%s | subject=%s | text=%s",
            message.to,
            message.subject,
            message.text or message.html,
        )
