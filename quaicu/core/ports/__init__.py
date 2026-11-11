"""QUAICU kernel ports — FROZEN contract surface.

The five interfaces `core/` depends on. Core imports ONLY these — never a concrete adapter, model
SDK, DB driver, or queue (F-08). Adapters in `adapters/` implement them; config selects which.

Every port method honors fail-closed: on error, timeout, or ambiguity it RAISES (a typed
`core.errors` subtype) — it never returns a permissive default or `None`. Returning `None` instead of
raising is a `PortContractError` caught by the adapter conformance suite.

This package is FROZEN. Changing a port signature requires the orchestrator + an ADR (AGENTS.md §3).

Source of truth: build spec §5 and the `quaicu-kernel-arch` skill.
"""

from __future__ import annotations

from quaicu.core.ports.hitl import HITLPort
from quaicu.core.ports.identity import IdentityPort
from quaicu.core.ports.inference import InferencePort
from quaicu.core.ports.storage import StoragePort
from quaicu.core.ports.workflow import WorkflowPort

__all__ = [
    "InferencePort",
    "HITLPort",
    "IdentityPort",
    "StoragePort",
    "WorkflowPort",
]
