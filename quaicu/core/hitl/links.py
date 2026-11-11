"""Signed, expiring approval links (K·03) — pure stdlib, core-safe.

An `ApprovalLinkSigner` mints and verifies a compact, URL-safe, HMAC-signed token that carries just
enough to resolve + authorize a single approval decision: the approval `handle_id`, the `tenant`, the
`decision` (approve|reject), and the intended approver's identity + roles. The token is
tamper-evident (HMAC-SHA256) and time-bounded (`exp`); **single-use** is enforced downstream by the
approval store (a decided record can't be decided again) — the token itself only proves authenticity.

Used by the email HITL adapter (D1-2) to build approve/reject links, and reusable by the signed
resume link (D1-4). No infrastructure imports — hmac/hashlib/json/base64/time only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ApprovalLinkSigner:
    """HMAC-SHA256 signer for single-decision approval links.

    ``secret`` is a strong server-side secret (e.g. ``QUAICU_APPROVAL_LINK_SECRET``). An empty secret
    is rejected — an unsigned/guessable link must never authorize an approval.
    """

    def __init__(self, secret: str) -> None:
        if not secret:
            raise ValueError("ApprovalLinkSigner requires a non-empty secret.")
        self._key = secret.encode("utf-8")

    def sign(
        self,
        *,
        handle_id: str,
        tenant: str,
        decision: str,
        approver_id: str,
        approver_roles: tuple[str, ...] = (),
        ttl_seconds: int = 604800,  # 7 days
    ) -> str:
        """Return a URL-safe ``<payload>.<sig>`` token for one approval decision."""
        if decision not in ("approve", "reject"):
            raise ValueError(f"decision must be 'approve' or 'reject', got {decision!r}")
        payload = {
            "h": handle_id,
            "t": tenant,
            "d": decision,
            "aid": approver_id,
            "ar": list(approver_roles),
            "exp": int(time.time()) + int(ttl_seconds),
        }
        body = _b64u_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = _b64u_encode(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, *, now: float | None = None) -> dict[str, Any] | None:
        """Return the payload dict if the token is authentic + unexpired, else ``None``.

        Fail-closed: any malformed token, signature mismatch, or expiry yields ``None`` (never raises).
        """
        try:
            body, sig = token.split(".", 1)
        except (ValueError, AttributeError):
            return None
        expected = _b64u_encode(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            return None
        try:
            payload: dict[str, Any] = json.loads(_b64u_decode(body))
        except (ValueError, json.JSONDecodeError):
            return None
        exp = payload.get("exp")
        if not isinstance(exp, int) or (now or time.time()) >= exp:
            return None
        return payload
