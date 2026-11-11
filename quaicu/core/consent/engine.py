"""K·04 DPDP Consent — ConsentEngine.

`ConsentEngine` wraps an inner `PolicyEvaluator` (K·01) and enforces DPDP consent BEFORE
delegating to the wrapped evaluator. It implements the `PolicyEvaluator` protocol so it can
be injected wherever a `PolicyEvaluator` is expected (e.g. `LifecycleEngine.policy`).

Architecture invariants enforced here:
  F-03 (fail-closed): any error, timeout, or ambiguity in consent resolution → DENY.
                       Never allow on uncertainty.
  F-04 (no bypass):   the ConsentEngine is always in the evaluator chain; it cannot be skipped.
  F-07 (tenant isolation): tenant_id is always passed explicitly to ConsentPort.get_consent.
  F-08 (hexagonal):   this module imports only core.* — no DB drivers, SDKs, or adapters.
  F-09 (replay-safe): consent_state is embedded in EvaluationResult.metadata["consent_state"]
                       so the ledger seals it into the Merkle leaf at evaluate time.

Consent check decision table:
  get_consent returns None        → ConsentDeniedError("missing")
  record.status == "withdrawn"    → ConsentDeniedError("withdrawn")
  record.expires_at <= now (UTC)  → ConsentDeniedError("expired")
  Any ConsentPort exception       → ConsentDeniedError("error") — fail-closed
  All checks pass                 → delegate to inner evaluator, inject consent_state

OTel instrumentation:
  Span:    "quaicu.consent.check"
  Attrs:   quaicu.tenant_id, quaicu.subject_id, quaicu.purpose, quaicu.consent_status
  Counter: quaicu.consent.checks_total (labels: tenant_id, outcome: granted/denied/error)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from opentelemetry import metrics, trace

from quaicu.core.consent.purpose import ConsentPurpose
from quaicu.core.errors import ConsentDeniedError
from quaicu.core.lifecycle.protocols import PolicyEvaluator
from quaicu.core.ports.consent import ConsentPort, ConsentRecord
from quaicu.core.types import Action, EvaluationResult

_log = logging.getLogger("quaicu.consent")

# ── OTel setup ────────────────────────────────────────────────────────────────

_tracer = trace.get_tracer("quaicu.consent", schema_url="https://opentelemetry.io/schemas/1.21.0")
_meter = metrics.get_meter("quaicu.consent", schema_url="https://opentelemetry.io/schemas/1.21.0")

_consent_checks_counter = _meter.create_counter(
    name="quaicu.consent.checks_total",
    description="Total consent checks performed by the ConsentEngine.",
    unit="1",
)

# ── Sentinel for unresolved record ────────────────────────────────────────────

_DEFAULT_PURPOSE = ConsentPurpose.AI_INFERENCE


def _resolve_purpose(action: Action) -> str:
    """Extract consent_purpose from action payload, defaulting to AI_INFERENCE."""
    purpose = action.payload.get("consent_purpose", _DEFAULT_PURPOSE)
    if not isinstance(purpose, str) or not purpose.strip():
        return _DEFAULT_PURPOSE
    return purpose.strip()


def _is_expired(record: ConsentRecord, now: datetime) -> bool:
    """Return True if the consent record has passed its expiry timestamp."""
    return record.expires_at is not None and record.expires_at <= now


# ── ConsentEngine ─────────────────────────────────────────────────────────────


class ConsentEngine:
    """Wraps an inner PolicyEvaluator and enforces DPDP consent FIRST.

    Implements the PolicyEvaluator protocol structurally — no explicit inheritance needed
    (hexagonal ports-and-adapters pattern). Wire this as the `policy` argument to
    LifecycleEngine:

        engine = LifecycleEngine(
            ...
            policy=ConsentEngine(
                consent_port=postgres_consent_adapter,
                inner=policy_engine,  # K·01
            ),
        )
    """

    def __init__(
        self,
        *,
        consent_port: ConsentPort,
        inner: PolicyEvaluator,
    ) -> None:
        self._consent_port = consent_port
        self._inner = inner

    async def evaluate(self, action: Action) -> EvaluationResult:
        """Check DPDP consent then delegate to the inner evaluator.

        On any consent failure this raises ConsentDeniedError, which the LifecycleEngine
        catches in its `_evaluate` step and transitions the action to DENIED (F-03/F-04).

        On consent granted, the inner evaluator is called and `consent_state` is injected
        into EvaluationResult.metadata (F-09).
        """
        tenant_id = str(action.tenant)
        subject_id = str(action.actor.id)
        purpose = _resolve_purpose(action)

        with _tracer.start_as_current_span(
            "quaicu.consent.check",
            attributes={
                "quaicu.tenant_id": tenant_id,
                "quaicu.subject_id": subject_id,
                "quaicu.purpose": purpose,
            },
        ) as span:
            record, deny_reason = await self._resolve_consent(
                tenant_id=tenant_id,
                subject_id=subject_id,
                purpose=purpose,
                span=span,
            )

            if deny_reason is not None:
                # Fail-closed: emit error attributes and metrics, then raise.
                span.set_attribute("quaicu.consent_status", deny_reason)
                span.set_status(trace.StatusCode.ERROR, f"consent {deny_reason}")
                _consent_checks_counter.add(
                    1,
                    attributes={"tenant_id": tenant_id, "outcome": "denied"},
                )
                _log.warning(
                    "consent denied: tenant=%s subject=%s purpose=%s reason=%s",
                    tenant_id,
                    subject_id,
                    purpose,
                    deny_reason,
                )
                raise ConsentDeniedError(
                    f"Consent {deny_reason} for subject={subject_id!r} "
                    f"purpose={purpose!r} tenant={tenant_id!r}",
                    detail={
                        "reason": deny_reason,
                        "tenant_id": tenant_id,
                        "subject_id": subject_id,
                        "purpose": purpose,
                    },
                )

            # Consent is granted — record the snapshot for ledger replay (F-09).
            assert record is not None  # deny_reason is None only when record is valid
            consent_state: dict[str, Any] = record.as_state_dict()

            span.set_attribute("quaicu.consent_status", "granted")
            span.set_status(trace.StatusCode.OK)
            _consent_checks_counter.add(
                1,
                attributes={"tenant_id": tenant_id, "outcome": "granted"},
            )
            _log.info(
                "consent granted: tenant=%s subject=%s purpose=%s consent_id=%s",
                tenant_id,
                subject_id,
                purpose,
                record.consent_id,
            )

        # Delegate to inner evaluator (K·01 PolicyEngine).
        inner_result = await self._inner.evaluate(action)

        # Inject consent_state into metadata — merge with any existing metadata so other
        # evaluators in the chain can also contribute (immutable dataclass replace pattern).
        merged_metadata: dict[str, Any] = dict(inner_result.metadata)
        merged_metadata["consent_state"] = consent_state

        return EvaluationResult(
            decision=inner_result.decision,
            policy_versions=inner_result.policy_versions,
            approvers=inner_result.approvers,
            reason=inner_result.reason,
            metadata=merged_metadata,
        )

    async def _resolve_consent(
        self,
        *,
        tenant_id: str,
        subject_id: str,
        purpose: str,
        span: trace.Span,
    ) -> tuple[ConsentRecord | None, str | None]:
        """Fetch and validate the consent record.

        Returns (record, None) on success, (None, reason) on denial.
        The reason string is one of: "missing" | "withdrawn" | "expired" | "error".

        Never raises — all exceptions are caught and converted to ("error") so the caller
        always fails closed.
        """
        try:
            record = await self._consent_port.get_consent(
                tenant_id=tenant_id,
                subject_id=subject_id,
                purpose=purpose,
            )
        except Exception as exc:  # noqa: BLE001 — any port failure → fail-closed deny
            _log.error(
                "consent port error — fail-closed deny: tenant=%s subject=%s purpose=%s: %s",
                tenant_id,
                subject_id,
                purpose,
                exc,
            )
            _consent_checks_counter.add(
                1,
                attributes={"tenant_id": tenant_id, "outcome": "error"},
            )
            span.record_exception(exc)
            return None, "error"

        if record is None:
            return None, "missing"

        # Fail-closed allowlist (F-03): grant ONLY for an explicitly active status. Any other
        # value — "withdrawn", "expired", "pending", a typo, or an unknown state — denies.
        if record.status != "active":
            reason = record.status if record.status in ("withdrawn", "expired") else "invalid"
            return None, reason

        now = datetime.now(tz=timezone.utc)
        if _is_expired(record, now):
            return None, "expired"

        # status == "active" and not expired: grant.
        return record, None
