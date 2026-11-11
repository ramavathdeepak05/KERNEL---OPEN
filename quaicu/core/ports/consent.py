"""ConsentPort (K·04) — FROZEN. DPDP consent management for governed actions.

Per-tenant consent records are resolved through this port. Core NEVER imports any DB driver,
SDK, or concrete adapter — only this Protocol and the ConsentRecord dataclass (F-08).

Fail-closed contract:
  - Missing consent → raise ConsentDeniedError("missing")
  - Expired consent → raise ConsentDeniedError("expired")
  - Withdrawn consent → raise ConsentDeniedError("withdrawn")
  - Any adapter error → the ConsentEngine wraps it and raises ConsentDeniedError("error")
  - `get_consent` returns None (not found), never raises for absence — the engine interprets None as
    missing and raises ConsentDeniedError itself.

Source of truth: build spec §K·04 and DPDP Act 2023 §4 (purpose limitation).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


# ── ConsentRecord ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ConsentRecord:
    """An immutable snapshot of a DPDP consent grant at a point in time.

    Per F-09, the ConsentEngine records a dict representation of this into
    EvaluationResult.metadata["consent_state"] at evaluate time so the ledger can
    reconstruct the exact consent state that was in effect without re-querying.
    """

    consent_id: str
    tenant_id: str
    subject_id: str          # actor.id — the data principal
    purpose: str             # e.g. "ai_inference", "loan_evaluation"
    data_categories: tuple[str, ...]  # e.g. ("financial", "biometric")
    status: str              # "active" | "expired" | "withdrawn"
    granted_at: datetime
    expires_at: datetime | None      # None = perpetual (until withdrawn)
    withdrawn_at: datetime | None
    policy_ref: str | None           # DPDP policy identifier, e.g. "dpdp-2023-s4"

    def as_state_dict(self) -> dict[str, object]:
        """Return a JSON-safe dict for embedding in EvaluationResult.metadata["consent_state"].

        This snapshot is sealed to the ledger Merkle leaf (F-09 / replay-safe).
        """
        return {
            "consent_id": self.consent_id,
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "purpose": self.purpose,
            "data_categories": list(self.data_categories),
            "status": self.status,
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at is not None else None,
            "withdrawn_at": (
                self.withdrawn_at.isoformat() if self.withdrawn_at is not None else None
            ),
            "policy_ref": self.policy_ref,
        }


# ── ConsentPort Protocol ───────────────────────────────────────────────────────


@runtime_checkable
class ConsentPort(Protocol):
    """Resolves and persists DPDP consent records for a tenant + subject + purpose triple.

    This port is per-tenant schema isolated (F-07): each tenant's consent records live in
    `"tenant_{tenant_id}".consent_records` and are never mixed.

    Implementation note: adapters MUST scope all queries using the tenant_id parameter —
    they MUST NOT rely solely on RLS because the ConsentEngine never bypasses the parameter.
    """

    async def get_consent(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        purpose: str,
    ) -> ConsentRecord | None:
        """Return the most-recent consent record for (tenant_id, subject_id, purpose).

        Returns None if no record exists. Does NOT raise for absence — the ConsentEngine
        interprets None as missing and raises ConsentDeniedError.

        Raises:
            Any exception on adapter/infrastructure failure. The ConsentEngine wraps all
            exceptions and fails closed (DENY) — adapters need not translate errors.
        """
        ...

    async def record_consent(self, record: ConsentRecord) -> None:
        """Persist a new consent grant.

        Raises:
            Any exception on write failure. Callers must handle or propagate.
        """
        ...

    async def withdraw_consent(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        purpose: str,
        withdrawn_at: datetime,
    ) -> None:
        """Mark the active consent for (tenant_id, subject_id, purpose) as withdrawn.

        The record is updated in-place (status → "withdrawn", withdrawn_at set). The original
        grant timestamp is preserved for audit replay (F-09).

        Raises:
            Any exception on write failure. Callers must handle or propagate.
        """
        ...
