"""K·11 Explainability — domain models.

Explanations are derived solely from sealed LedgerEntry records — no model re-calls.
Every field in Explanation maps directly to what was recorded at decision time (F-09).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ExplainRequest:
    """Request an explanation for a governed action identified by action_id."""

    action_id: str
    tenant_id: str


@dataclass(frozen=True)
class Explanation:
    """A point-in-time explanation derived solely from a sealed LedgerEntry.

    ``derivable`` is True when all explanation fields could be populated from recorded data.
    If the entry lacks sufficient recorded data (e.g. recorded_result is empty), ``derivable``
    is False and the caller must NOT attempt a model re-call to fill the gap — it must
    surface "insufficient recorded data" to the requester.

    ``explanation_text`` is a human-readable summary of why the decision was made,
    composed from recorded fields only.
    """

    action_id: str
    tenant_id: str
    decision: str
    policy_versions: tuple[str, ...] = ()
    recorded_inputs: Mapping[str, Any] = field(default_factory=dict)
    recorded_outputs: Mapping[str, Any] = field(default_factory=dict)
    consent_state: Mapping[str, Any] = field(default_factory=dict)
    approver: str | None = None
    explanation_text: str = ""
    derivable: bool = True
    derived_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
