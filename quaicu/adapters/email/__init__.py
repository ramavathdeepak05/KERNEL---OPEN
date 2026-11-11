"""Email adapters: Resend (REST, no SDK) + a log-only dev fallback."""

from __future__ import annotations

from quaicu.adapters.email.resend import LogOnlyEmailSender, ResendEmailAdapter

__all__ = ["LogOnlyEmailSender", "ResendEmailAdapter"]
