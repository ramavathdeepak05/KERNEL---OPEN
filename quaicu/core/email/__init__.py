"""Transactional email seam (approval-request emails).

A single outbound port. Core never imports an email SDK — only `EmailSender` + `EmailMessage`.
Adapters live in `quaicu/adapters/email/` (Resend REST, plus a log-only dev fallback).
"""

from __future__ import annotations

from quaicu.core.email.port import EmailMessage, EmailSender

__all__ = ["EmailMessage", "EmailSender"]
