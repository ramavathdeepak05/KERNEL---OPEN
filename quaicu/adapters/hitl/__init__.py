"""HITLPort adapters — approvals handed to another system: `webhook`, `email` and `teams`.

(The built-in approvals queue is `quaicu.core.hitl.engine.InProcessHITLPort`.)

The adapters are loaded on first use, not when this package is imported: `webhook` and `teams` need
httpx (the ``server`` extra).
"""

from __future__ import annotations

from typing import Any

_LAZY = {
    "EmailHITLAdapter": "quaicu.adapters.hitl.email",
    "MicrosoftTeamsHITLAdapter": "quaicu.adapters.hitl.teams",
    "WebhookHITLAdapter": "quaicu.adapters.hitl.webhook",
}

__all__ = ["EmailHITLAdapter", "MicrosoftTeamsHITLAdapter", "WebhookHITLAdapter"]


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        import importlib

        return getattr(importlib.import_module(_LAZY[name]), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
