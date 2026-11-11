"""LifecycleEngine — orchestrates `propose → evaluate → gate → execute → seal → emit`.

Invariants this module enforces by construction (see the `quaicu-governed-lifecycle` skill contract):
- **No bypass (F-04):** `execute` is reachable only after `evaluate` (and `gate`, when required) pass.
  There is no public method that executes without evaluating.
- **Fail-closed (F-03):** any error/timeout/ambiguity → DENY (governance) or HALT (infra). Never proceed.
- **Seal before complete:** an action that executed but failed to seal is HALTED, never COMPLETED.
- **Idempotency:** a duplicate `(tenant, idempotency_key)` returns the existing action; it never re-runs.
- **Determinism:** the engine introduces no wall-clock or randomness into the decision path (the HITL
  poll loop is bounded by a count, not a clock).

`core/` purity: this module imports only `core.*` (ports, types, errors, lifecycle) and the stdlib.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from quaicu.core.errors import StoragePortError
from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.lifecycle.protocols import ActionRepository, EventBus, Ledger, PolicyEvaluator
from quaicu.core.lifecycle.transitions import assert_transition
from quaicu.core.ports import HITLPort, IdentityPort
from quaicu.core.ports.consent import ConsentPort
from quaicu.core.types import (
    Action,
    ActionState,
    ApprovalDecision,
    ApprovalOutcome,
    ApproverRef,
    Decision,
    EvaluationResult,
    RequestContext,
)

log = logging.getLogger("quaicu.lifecycle")

# The execute step: the governed body, returning the result recorded to the ledger.
ExecuteFn = Callable[[], Awaitable[Any]]


class LifecycleEngine:
    """Runs the governed-action lifecycle. One instance per process; dependencies are injected
    (no globals in core)."""

    def __init__(
        self,
        *,
        repository: ActionRepository,
        policy: PolicyEvaluator,
        hitl: HITLPort,
        ledger: Ledger,
        events: EventBus,
        identity: IdentityPort | None = None,
        consent: ConsentPort | None = None,
        default_profile: GovernanceProfile | None = None,
        max_poll_attempts: int = 1,
        poll_wait: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._repo = repository
        self._policy = policy
        self._hitl = hitl
        self._ledger = ledger
        self._events = events
        self._identity = identity
        # Optional standalone consent collaborator (K·04). When wired and the active profile enforces
        # consent, it runs as its own step before policy — making consent independently toggleable.
        self._consent = consent
        # Default profile used when run() is called without an explicit one. all() = maximal governance.
        self._default_profile = default_profile or GovernanceProfile.all()
        # Bounded poll safety net. A real HITL adapter long-polls (blocks until a decision or its own
        # configured timeout); the count cap guarantees the loop terminates without a wall-clock.
        self._max_poll_attempts = max(1, max_poll_attempts)
        self._poll_wait = poll_wait

    @property
    def has_identity(self) -> bool:
        """True if an IdentityPort is wired. The standalone API requires this to be True so it
        never trusts a caller-supplied actor."""
        return self._identity is not None

    @property
    def identity(self) -> IdentityPort | None:
        """The wired IdentityPort, if any. Read-only access for control-plane surfaces (e.g. the
        policy management API) that must resolve the actor from a token outside the run lifecycle."""
        return self._identity

    # ── Public entry point ──────────────────────────────────────────────────────

    async def run(
        self,
        action: Action,
        execute_fn: ExecuteFn,
        *,
        context: RequestContext | None = None,
        profile: GovernanceProfile | None = None,
        defer_gate: bool = False,
    ) -> Action:
        """Drive `action` through the lifecycle, enforcing the layers the `profile` declares.

        `profile=None` uses the engine default (maximal governance). Returns the action in its final
        state (COMPLETED on success; DENIED/HALTED otherwise, or the pre-existing action on an
        idempotency hit). Never raises for an expected governance/infra outcome — the terminal state
        carries it. Each enabled layer remains fail-closed; a disabled layer is skipped by config.

        `defer_gate=True` (declarative `propose` path only): on `REQUIRE_APPROVAL`, create the approval
        request and **return the PENDING_APPROVAL action without polling/executing** — the action
        resumes (execute → seal → emit) via `resume_after_approval` when an authorized approver decides.
        The default `False` keeps the synchronous behavior (poll → fail-closed on timeout) for every
        existing caller (`guard`/`generate`/`check`).
        """
        prof = profile or self._default_profile

        # propose (identity + idempotency). proceed=False ⇒ stop and return (duplicate or denied).
        action, proceed = await self._propose(action, context, prof)
        if not proceed:
            return action

        # consent (independent layer, before policy) — only when enforced and a port is wired.
        consent_state: dict[str, Any] = {}
        if prof.enforce_consent and self._consent is not None:
            action, consent_state, ok = await self._consent_check(action)
            if not ok:
                return action  # consent denied (fail-closed)

        # evaluate
        action, evaluation = await self._evaluate(action, prof)
        if evaluation is None:  # denied at evaluate
            return action

        # annotate the evaluation with consent state + the enforced layers so they are sealed.
        evaluation = self._annotate(evaluation, consent_state, prof)

        # gate (only when a policy requires approval)
        approver: ApproverRef | None = None
        if evaluation.decision is Decision.REQUIRE_APPROVAL:
            if not prof.enforce_hitl_gate:
                # Approval was required but the gate layer is disabled — fail closed.
                return await self._deny(
                    action, "approval required but HITL gate disabled by profile"
                )
            if defer_gate:
                # Pause durably: register the approval request + return PENDING_APPROVAL. No poll,
                # no execute, no seal, no timeout→deny. The action resumes via resume_after_approval
                # once an approver decides (the durable HITL store survives across instances/restarts).
                return await self._request_pending(action, evaluation)
            action, approver = await self._gate(action, evaluation)
            if action.state is not ActionState.PENDING_APPROVAL and action.state in (
                ActionState.DENIED,
                ActionState.HALTED,
            ):
                return action

        # execute
        action, result = await self._execute(action, execute_fn)
        if action.state is ActionState.HALTED:
            return action

        # seal
        action, entry = await self._seal(action, evaluation, result, approver, prof)
        if action.state is ActionState.HALTED:
            return action

        # emit (best-effort, after seal — never changes the outcome)
        if prof.emit_events:
            await self._emit(action, entry)
        return action

    # ── Decision-only (PDP) path ─────────────────────────────────────────────────

    async def decide(
        self,
        action: Action,
        *,
        context: RequestContext | None = None,
        profile: GovernanceProfile | None = None,
        record: bool | None = None,
    ) -> AuthorizationResult:
        """Evaluate policy + consent + identity for ``action`` and return a verdict.

        **Side-effect-free**: no action row is inserted, no state-machine transitions happen, no
        events are emitted. The action object is never persisted. The caller is the enforcement
        point (PEP) — it decides what to do with the verdict.

        When ``record`` is True (or ``record`` is None and the active profile has
        ``seal_to_ledger=True``) a decision-only leaf is sealed into the transparency log so every
        authorization query becomes a tamper-evident monitoring record. A seal failure is
        best-effort: it is logged as a warning but does NOT change the returned verdict.
        """
        prof = profile or self._default_profile

        # Identity resolution (no insert, no persist — just enrich the action's actor).
        if prof.verify_identity and context is not None and self._identity is not None:
            try:
                actor = await self._identity.resolve_actor(context=context, tenant=action.tenant)
                action = dataclasses.replace(action, actor=actor)
            except Exception as exc:  # noqa: BLE001
                log.info("decide: identity unresolved — fail-closed: %s", exc)
                return AuthorizationResult(
                    decision=Decision.DENY,
                    allowed=False,
                    actor_id=action.actor.id,
                    reason="identity unresolved — fail-closed",
                    enforced_layers=prof.enabled_layers(),
                )

        # Consent check (pure — no state mutation).
        consent_state: dict[str, Any] = {}
        if prof.enforce_consent and self._consent is not None:
            ok, consent_state, consent_reason = await self._consent_verdict(action)
            if not ok:
                return AuthorizationResult(
                    decision=Decision.DENY,
                    allowed=False,
                    actor_id=action.actor.id,
                    reason=consent_reason,
                    enforced_layers=prof.enabled_layers(),
                    consent_state=consent_state,
                )

        # Policy evaluation (pure — no state mutation).
        if not prof.enforce_policy:
            eval_decision = Decision.ALLOW
            policy_versions: tuple[str, ...] = ("<policy-unenforced>",)
            approvers: tuple[ApproverRef, ...] = ()
            reason: str | None = None
        else:
            try:
                evaluation = await self._policy.evaluate(action)
            except Exception as exc:  # noqa: BLE001
                log.info("decide: policy evaluation failed — fail-closed: %s", exc)
                return AuthorizationResult(
                    decision=Decision.DENY,
                    allowed=False,
                    actor_id=action.actor.id,
                    reason="policy evaluation failed — fail-closed",
                    enforced_layers=prof.enabled_layers(),
                    consent_state=consent_state,
                )
            if evaluation is None:
                return AuthorizationResult(
                    decision=Decision.DENY,
                    allowed=False,
                    actor_id=action.actor.id,
                    reason="policy returned None — fail-closed",
                    enforced_layers=prof.enabled_layers(),
                    consent_state=consent_state,
                )
            eval_decision = evaluation.decision
            policy_versions = evaluation.policy_versions
            approvers = evaluation.approvers
            reason = evaluation.reason

        # Monitoring seal (best-effort — never changes the verdict).
        should_seal = record if record is not None else prof.seal_to_ledger
        sealed = False
        ledger_seq: int | None = None
        if should_seal:
            try:
                eval_result = EvaluationResult(
                    decision=eval_decision,
                    policy_versions=policy_versions,
                    approvers=approvers,
                    reason=reason,
                )
                annotated = self._annotate(eval_result, consent_state, prof)
                entry = await self._ledger.seal(
                    action=action,
                    evaluation=annotated,
                    recorded_result={"decision_only": True},
                    approver=None,
                )
                sealed = True
                ledger_seq = entry.ledger_seq
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "decide: monitoring seal failed for action %s (best-effort — verdict unchanged): %s",
                    action.id,
                    exc,
                )

        return AuthorizationResult(
            decision=eval_decision,
            allowed=(eval_decision is Decision.ALLOW),
            actor_id=action.actor.id,
            reason=reason,
            policy_versions=policy_versions,
            approvers=approvers,
            enforced_layers=prof.enabled_layers(),
            consent_state=consent_state,
            sealed=sealed,
            ledger_seq=ledger_seq,
        )

    # ── Steps ───────────────────────────────────────────────────────────────────

    async def _propose(
        self, action: Action, context: RequestContext | None, profile: GovernanceProfile
    ) -> tuple[Action, bool]:
        # Identity FIRST, before any insert (F-03/F-07). The kernel takes identity from the host
        # (IdentityPort); failure → DENY. Resolving before the idempotency insert means an
        # unauthenticated request never occupies the (tenant, idempotency_key) slot and so cannot
        # poison a legitimate retry. No row exists yet, so the denial is not persisted.
        if profile.verify_identity and context is not None and self._identity is not None:
            try:
                actor = await self._identity.resolve_actor(context=context, tenant=action.tenant)
            except Exception as exc:  # noqa: BLE001 — unresolved identity must fail closed
                denied = await self._deny(
                    action, "identity unresolved — fail-closed", exc, persist=False
                )
                return denied, False
            action = dataclasses.replace(action, actor=actor)

        # Idempotency: atomic insert. On conflict, return the existing action — never re-run it,
        # whatever state it is in. A storage failure here means the action was never recorded,
        # so there is no row to update → HALT in memory (fail-closed, never raise out of run()).
        try:
            existing = await self._repo.insert_if_absent(action)
        except StoragePortError as exc:
            halted = action.with_state(ActionState.HALTED)
            log.critical(
                "action %s HALTED before insert — storage failure: %s", action.id, exc
            )
            return halted, False
        if existing is not None:
            log.info(
                "idempotency hit — returning existing action %s (state=%s)",
                existing.id,
                existing.state.value,
            )
            return existing, False

        return action, True

    async def _consent_verdict(
        self, action: Action
    ) -> tuple[bool, dict[str, Any], str | None]:
        """Pure consent check — no state mutations, no action persistence.

        Returns ``(ok, consent_state, reason)``. Used by both ``decide`` (pure PDP path) and
        ``_consent_check`` (run path, which wraps failures in ``_deny``).
        """
        from quaicu.core.consent.engine import _is_expired, _resolve_purpose  # local import (core→core)
        from datetime import datetime, timezone

        tenant_id = str(action.tenant)
        subject_id = str(action.actor.id)
        purpose = _resolve_purpose(action)
        try:
            record = await self._consent.get_consent(
                tenant_id=tenant_id, subject_id=subject_id, purpose=purpose
            )
        except Exception as exc:  # noqa: BLE001
            return False, {}, f"consent port error — fail-closed ({exc})"

        if record is None:
            return False, {}, "consent missing — fail-closed"
        if record.status != "active":
            return False, {}, f"consent {record.status} — fail-closed"
        if _is_expired(record, datetime.now(tz=timezone.utc)):
            return False, {}, "consent expired — fail-closed"

        return True, record.as_state_dict(), None

    async def _consent_check(
        self, action: Action
    ) -> tuple[Action, dict[str, Any], bool]:
        """Standalone K·04 consent layer for the ``run`` path. Returns (action, consent_state, ok).

        Fail-closed: missing / withdrawn / expired / non-active / any port error → DENY. On success,
        returns the consent snapshot to be sealed into the ledger leaf (F-09). The action stays
        PROPOSED on success (the next layer advances it).
        """
        ok, consent_state, reason = await self._consent_verdict(action)
        if not ok:
            denied = await self._deny(action, reason or "consent denied — fail-closed")
            return denied, {}, False
        return action, consent_state, True

    def _annotate(
        self,
        evaluation: EvaluationResult,
        consent_state: dict[str, Any],
        profile: GovernanceProfile,
    ) -> EvaluationResult:
        """Attach consent_state (when resolved by the standalone layer) and the enforced-layer list
        to the evaluation metadata so both are sealed into the Merkle leaf."""
        metadata = dict(evaluation.metadata)
        if consent_state:
            metadata["consent_state"] = consent_state
        metadata["governance_profile"] = list(profile.enabled_layers())
        return dataclasses.replace(evaluation, metadata=metadata)

    async def _evaluate(
        self, action: Action, profile: GovernanceProfile
    ) -> tuple[Action, EvaluationResult | None]:
        action, ok = await self._transition(action, ActionState.EVALUATING)
        if not ok:
            return action, None  # storage failure → HALTED (run() returns it)
        if not profile.enforce_policy:
            # Policy layer disabled by profile → auto-ALLOW (explicit configuration decision).
            return action, EvaluationResult(
                decision=Decision.ALLOW, policy_versions=("<policy-unenforced>",)
            )
        try:
            evaluation = await self._policy.evaluate(action)
        except Exception as exc:  # noqa: BLE001 — any policy failure → DENY (fail-closed)
            return await self._deny(action, "policy evaluation failed — fail-closed", exc), None
        if evaluation is None:
            return await self._deny(action, "policy returned None — fail-closed"), None
        if evaluation.decision is Decision.DENY:
            return await self._deny(action, evaluation.reason or "policy denied"), None
        # allow or require_approval → continue (action stays EVALUATING; next step advances it)
        return action, evaluation

    async def _gate(
        self, action: Action, evaluation: EvaluationResult
    ) -> tuple[Action, ApproverRef | None]:
        action, ok = await self._transition(action, ActionState.PENDING_APPROVAL)
        if not ok:
            return action, None  # storage failure → HALTED (run() returns it)
        try:
            handle = await self._hitl.request_approval(
                action=action, approvers=list(evaluation.approvers), tenant=action.tenant
            )
            outcome = await self._poll_until_decided(handle)
        except Exception as exc:  # noqa: BLE001 — HITL infra failure → HALT (fail-closed)
            return await self._halt(action, "HITL port error — fail-closed halt", exc), None

        if outcome.decision is ApprovalDecision.APPROVED:
            # Capture WHO approved (ADR-0007): seal the decider as a `user:<id>` approver ref. A
            # backend that approves without reporting an identity seals approver=None.
            approver = (
                ApproverRef(f"user:{outcome.decided_by}") if outcome.decided_by else None
            )
            return action, approver
        # REJECTED or TIMED_OUT → fail-closed DENY (never auto-approve on timeout)
        return await self._deny(action, f"approval {outcome.decision.value.lower()}"), None

    async def _poll_until_decided(self, handle: Any) -> ApprovalOutcome:
        attempts = 0
        while attempts < self._max_poll_attempts:
            outcome = await self._hitl.poll(handle)
            if outcome.decision is not ApprovalDecision.PENDING:
                return outcome
            attempts += 1
            if self._poll_wait is not None:
                await self._poll_wait()
        return ApprovalOutcome(ApprovalDecision.TIMED_OUT)  # exhausted attempts → fail-closed

    # ── Deferred gate + resume (async approval) ──────────────────────────────────

    async def _request_pending(
        self, action: Action, evaluation: EvaluationResult
    ) -> Action:
        """Deferred gate: transition to PENDING_APPROVAL + register the approval request, then return
        without polling. Mirrors the first half of `_gate`; the action awaits `resume_after_approval`."""
        action, ok = await self._transition(action, ActionState.PENDING_APPROVAL)
        if not ok:
            return action  # storage failure → HALTED (caller returns it)
        try:
            await self._hitl.request_approval(
                action=action, approvers=list(evaluation.approvers), tenant=action.tenant
            )
        except Exception as exc:  # noqa: BLE001 — HITL infra failure → HALT (fail-closed)
            return await self._halt(action, "HITL request failed — fail-closed halt", exc)
        return action

    async def resume_after_approval(
        self,
        action: Action,
        *,
        approver: ApproverRef | None,
        execute_fn: ExecuteFn,
        profile: GovernanceProfile | None = None,
    ) -> Action:
        """Resume a PENDING_APPROVAL action after an authorized approval: consent → re-evaluate →
        execute → seal → emit. **Idempotent** — a no-op unless the action is still PENDING_APPROVAL,
        so a repeated approval can never double-execute or double-seal. **Fail-closed** — missing,
        withdrawn or expired consent, or a re-evaluation DENY, denies the action; a seal failure
        HALTs it (the existing `_execute`/`_seal` semantics)."""
        prof = profile or self._default_profile
        if action.state is not ActionState.PENDING_APPROVAL:
            return action  # already resolved (idempotency / double-approve guard)

        # Consent is checked again here, not carried over from the proposal: an action can wait a
        # long time for approval, and consent withdrawn (or expired) in the meantime must stop it.
        # The fresh snapshot is what gets sealed with the completed action.
        consent_state: dict[str, Any] = {}
        if prof.enforce_consent and self._consent is not None:
            ok, consent_state, consent_reason = await self._consent_verdict(action)
            if not ok:
                return await self._deny(action, consent_reason or "consent denied — fail-closed")

        # Re-evaluate to obtain the evaluation to seal (the seal records policy as of completion). Use
        # the policy directly — `_evaluate` transitions to EVALUATING, which is illegal from
        # PENDING_APPROVAL. The APPROVED HITL record (not this evaluation) authorizes passing the gate.
        if prof.enforce_policy:
            try:
                evaluation = await self._policy.evaluate(action)
            except Exception as exc:  # noqa: BLE001 — any policy failure → DENY (fail-closed)
                return await self._deny(action, "policy re-evaluation failed — fail-closed", exc)
            if evaluation is None:
                return await self._deny(action, "policy returned None — fail-closed")
            if evaluation.decision is Decision.DENY:
                return await self._deny(action, evaluation.reason or "policy denied on resume")
        else:
            evaluation = EvaluationResult(
                decision=Decision.ALLOW, policy_versions=("<policy-unenforced>",)
            )
        evaluation = self._annotate(evaluation, consent_state, prof)

        action, result = await self._execute(action, execute_fn)
        if action.state is ActionState.HALTED:
            return action
        action, entry = await self._seal(action, evaluation, result, approver, prof)
        if action.state is ActionState.HALTED:
            return action
        if prof.emit_events:
            await self._emit(action, entry)
        return action

    async def deny_pending(self, action: Action, reason: str) -> Action:
        """Fail-closed terminal for a rejected/expired deferred gate: PENDING_APPROVAL → DENIED.
        Idempotent — a no-op unless the action is still PENDING_APPROVAL."""
        if action.state is not ActionState.PENDING_APPROVAL:
            return action
        return await self._deny(action, reason)

    async def _execute(self, action: Action, execute_fn: ExecuteFn) -> tuple[Action, Any]:
        action, ok = await self._transition(action, ActionState.EXECUTING)
        if not ok:
            return action, None  # storage failure → HALTED (run() returns it)
        try:
            result = await execute_fn()
        except Exception as exc:  # noqa: BLE001 — execute body failure must HALT, never proceed
            return await self._halt(action, "execute failed", exc), None
        return action, result

    async def _seal(
        self,
        action: Action,
        evaluation: EvaluationResult,
        result: Any,
        approver: ApproverRef | None,
        profile: GovernanceProfile,
    ) -> tuple[Action, Any]:
        action, ok = await self._transition(action, ActionState.SEALING)
        if not ok:
            return action, None  # storage failure → HALTED (run() returns it)
        entry = None
        if not profile.seal_to_ledger:
            # Seal layer disabled by profile — the action will COMPLETE without an audit entry.
            log.warning(
                "action %s COMPLETED unsealed — ledger layer disabled by profile (no audit entry)",
                action.id,
            )
        else:
            try:
                entry = await self._ledger.seal(
                    action=action, evaluation=evaluation, recorded_result=result, approver=approver
                )
            except Exception as exc:  # noqa: BLE001
                # CRITICAL: the state change happened but the ledger has no record. Halt + alert; the
                # action is NOT completed. A reconcile path re-attempts sealing without re-executing.
                halted = await self._halt(action, "ledger seal failed — executed but unsealed", exc)
                log.critical(
                    "PARTIAL FAILURE: action %s executed but seal failed — manual reconcile required",
                    action.id,
                )
                return halted, None
        # The ledger record now exists. If persisting SEALED/COMPLETED fails we still HALT
        # (fail-closed) — the action is durably sealed and a reconcile path can mark it COMPLETED.
        action, ok = await self._transition(action, ActionState.SEALED)
        if not ok:
            return action, None
        action, ok = await self._transition(action, ActionState.COMPLETED)
        if not ok:
            return action, None
        return action, entry

    async def _emit(self, action: Action, entry: Any) -> None:
        try:
            await self._events.emit(action=action, entry=entry)
        except Exception as exc:  # noqa: BLE001 — emit is best-effort; outcome already sealed
            log.warning(
                "emit failed for action %s — outcome unchanged (already sealed): %s", action.id, exc
            )

    # ── Transition helpers ──────────────────────────────────────────────────────

    def _advance(self, action: Action, state: ActionState) -> Action:
        assert_transition(action.state, state)
        return action.with_state(state)

    async def _transition(
        self, action: Action, state: ActionState
    ) -> tuple[Action, bool]:
        """Advance to ``state`` and persist it. Returns ``(action, ok)``.

        On a ``StoragePortError`` the action is moved to HALTED (emergency stop — bypasses the
        normal transition guard because infrastructure can fail in any state) and ``ok=False`` is
        returned so the calling step returns immediately. Never raises — preserves run()'s contract.
        """
        advanced = self._advance(action, state)
        try:
            await self._repo.update_state(advanced)
        except StoragePortError as exc:
            return self._halt_on_storage(advanced, exc), False
        return advanced, True

    def _halt_on_storage(self, action: Action, exc: Exception) -> Action:
        """Emergency HALT on a storage failure, making a best-effort attempt to record it.

        Uses ``with_state`` directly (not ``_advance``) because HALTED is not a legal successor of
        every state in the transition table, yet a storage outage must stop the action from any
        state. The HALTED persist is best-effort: if storage is still down we swallow it and return
        HALTED anyway so run() resolves terminally.
        """
        halted = action.with_state(ActionState.HALTED)
        log.critical(
            "action %s HALTED on storage failure from state %s: %s",
            action.id,
            action.state.value,
            exc,
        )
        return halted

    async def _deny(
        self,
        action: Action,
        reason: str,
        cause: Exception | None = None,
        *,
        persist: bool = True,
    ) -> Action:
        denied = self._advance(action, ActionState.DENIED)
        if persist:
            try:
                await self._repo.update_state(denied)
            except StoragePortError as exc:
                # DENIED is terminal; if we cannot persist it we still return DENIED (fail-closed).
                log.error("failed to persist DENIED for action %s: %s", action.id, exc)
        log.info("action %s DENIED: %s%s", action.id, reason, f" ({cause})" if cause else "")
        return denied

    async def _halt(
        self,
        action: Action,
        reason: str,
        cause: Exception | None = None,
        *,
        persist: bool = True,
    ) -> Action:
        halted = self._advance(action, ActionState.HALTED)
        if persist:
            try:
                await self._repo.update_state(halted)
            except StoragePortError as exc:
                log.error("failed to persist HALTED for action %s: %s", action.id, exc)
        log.error("action %s HALTED: %s%s", action.id, reason, f" ({cause})" if cause else "")
        return halted
