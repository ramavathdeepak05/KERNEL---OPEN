"""EmailSender port — the kernel's only outbound transactional-email seam.

Used by the email approval channel (`quaicu/adapters/hitl/email.py`) to send an approver the link
for a pending decision. Async because the production adapter makes a network call (a provider REST
API); the kernel awaits it from the request path. Adapters must raise `core.errors.EmailPortError` on
any send failure so the caller decides fail-open vs fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class EmailMessage:
    """A single transactional email. ``text`` is an optional plain-text alternative to ``html``."""

    to: str
    subject: str
    html: str
    text: str | None = None


@runtime_checkable
class EmailSender(Protocol):
    """Send a transactional email. Raises `EmailPortError` on failure."""

    async def send(self, message: EmailMessage) -> None: ...
