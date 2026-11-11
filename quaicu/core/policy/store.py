"""K·01 Policy Engine — in-memory policy store.

Responsibilities:
- Compile CEL at `register` time so evaluation never silently uses a broken expression.
- Enforce the F-10 simulation gate at `activate` time: a policy moves REVIEW → ACTIVATED only
  with a matching, acknowledged `ImpactReport`.
- `lookup` returns only ACTIVATED policies that match (action_type, tenant_id), applying the
  specificity rule: both exact-tenant and wildcard policies are returned; conflict resolution
  happens in the evaluator, not here.

Thread-safety: a `threading.Lock` guards all mutations. The store is synchronous because no async
DB exists in Wave 1 (the storage adapter replaces this in Wave 2 without changing the evaluator).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

import celpy

from quaicu.core.errors import PolicyActivationError, PolicyCompileError, PolicyTransitionError
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.repository import PolicyRepository

log = logging.getLogger("quaicu.policy")


def _compile_cel(condition: str) -> tuple[Any, Any]:
    """Compile a CEL expression and return (env, program).

    Raises `PolicyCompileError` on any parse or type-check failure so the author gets immediate
    feedback at registration time rather than a runtime DENY on every evaluation.
    """
    try:
        env = celpy.Environment()
        ast = env.compile(condition)
        prog = env.program(ast)
        return env, prog
    except Exception as exc:
        raise PolicyCompileError(
            f"CEL compile failed for expression {condition!r}: {exc}",
            detail={"condition": condition, "cause": str(exc)},
        ) from exc


class PolicyStore:
    """Mutable (Wave 1) in-memory registry of all policy envelopes.

    Wave 2 will replace the storage layer with a Postgres-backed adapter implementing the same
    interface; this class becomes the in-process cache / write-through layer at that point.
    """

    def __init__(self, repository: PolicyRepository | None = None) -> None:
        # Primary index: (policy_id, version) → PolicyEnvelope
        self._policies: dict[tuple[str, int], PolicyEnvelope] = {}
        # Impact-report index: (policy_id, version) → ImpactReport
        self._impact_reports: dict[tuple[str, int], ImpactReport] = {}
        self._lock = threading.Lock()
        # Serialises `register_persisted` (check → durable write → cache) so two concurrent
        # registrations of the same (id, version) cannot both pass the guard and leave the durable
        # row and the cache holding different envelopes.
        self._persist_lock = asyncio.Lock()
        # Optional durable backend. When set, the write-through (`*_persisted`) methods persist to it
        # and `hydrate()` repopulates the in-memory cache from it on startup. The hot-path `lookup`
        # never touches it — this store remains the fast in-memory read cache (holding the compiled
        # CEL programs, which are not serialisable and are recompiled on hydrate).
        self._repository = repository

    # ── Authoring ───────────────────────────────────────────────────────────────

    def _assert_registrable(self, envelope: PolicyEnvelope) -> None:
        """Guard against mutating a finalised version, or another tenant's version.

        Overwriting a DRAFT or REVIEW envelope is legitimate draft iteration, but an ACTIVATED or
        DEPRECATED version is an immutable evidence artifact — re-registering it must raise. The
        caller MUST hold `self._lock`, or call this before any durable write (see
        `register_persisted`) so the cache check happens before the row is overwritten.

        The key is (id, version) with no tenant, and one store can serve many tenants, so an
        existing version may only be replaced by an envelope with the SAME tenant scope. Otherwise
        one tenant could overwrite another tenant's draft, or an operator seed.
        """
        policy_id, version = envelope.id, envelope.version
        existing = self._policies.get((policy_id, version))
        if existing is not None and existing.scope.get("tenant", "*") != envelope.scope.get(
            "tenant", "*"
        ):
            raise PolicyTransitionError(
                f"Policy {policy_id}@v{version} already exists under a different tenant scope; "
                "choose another policy id.",
                detail={"policy_id": policy_id, "version": version},
            )
        if existing is not None and existing.lifecycle in (
            PolicyLifecycle.ACTIVATED,
            PolicyLifecycle.DEPRECATED,
        ):
            raise PolicyTransitionError(
                f"Policy {policy_id}@v{version} is {existing.lifecycle.value} and immutable; "
                "create a new version instead.",
                detail={"policy_id": policy_id, "version": version, "lifecycle": existing.lifecycle.value},
            )

    def register(self, envelope: PolicyEnvelope) -> PolicyEnvelope:
        """Compile the CEL condition and store the envelope.

        Returns the stored envelope (with `compiled_condition` populated).
        Raises `PolicyCompileError` if the CEL expression is syntactically invalid.
        Raises `PolicyTransitionError` if the (id, version) is already ACTIVATED/DEPRECATED;
        create a new version instead.
        """
        _env, prog = _compile_cel(envelope.condition)
        # frozen=True prevents normal attribute assignment; use object.__setattr__ as sanctioned
        # by the dataclass docs for exactly this post-init population pattern.
        stored = object.__new__(PolicyEnvelope)
        object.__setattr__(stored, "id", envelope.id)
        object.__setattr__(stored, "version", envelope.version)
        object.__setattr__(stored, "governs", envelope.governs)
        object.__setattr__(stored, "scope", envelope.scope)
        object.__setattr__(stored, "condition", envelope.condition)
        object.__setattr__(stored, "decision", envelope.decision)
        object.__setattr__(stored, "approvers", envelope.approvers)
        object.__setattr__(stored, "regulatory_refs", envelope.regulatory_refs)
        object.__setattr__(stored, "lifecycle", envelope.lifecycle)
        object.__setattr__(stored, "compiled_condition", prog)

        with self._lock:
            self._assert_registrable(envelope)
            self._policies[(envelope.id, envelope.version)] = stored

        log.info("policy registered: %s@v%d (lifecycle=%s)", envelope.id, envelope.version, envelope.lifecycle.value)
        return stored

    def store_impact_report(self, report: ImpactReport) -> None:
        """Persist an impact report so `activate` can verify it."""
        with self._lock:
            self._impact_reports[(report.policy_id, report.policy_version)] = report

    def activate(self, policy_id: str, version: int, impact_report: ImpactReport) -> PolicyEnvelope:
        """Transition a REVIEW policy to ACTIVATED.

        F-10 gate: the `impact_report` must:
        - Match `policy_id` and `version`.
        - Have `acknowledged == True`.

        Raises `PolicyActivationError` if any precondition fails.
        """
        if not impact_report.acknowledged:
            raise PolicyActivationError(
                f"Impact report for {policy_id}@v{version} is not acknowledged — cannot activate.",
                detail={"policy_id": policy_id, "version": version},
            )

        if impact_report.policy_id != policy_id or impact_report.policy_version != version:
            raise PolicyActivationError(
                f"Impact report mismatch: report is for {impact_report.policy_id}@v{impact_report.policy_version}, "
                f"but activation requested for {policy_id}@v{version}.",
                detail={
                    "policy_id": policy_id,
                    "version": version,
                    "report_policy_id": impact_report.policy_id,
                    "report_version": impact_report.policy_version,
                },
            )

        with self._lock:
            key = (policy_id, version)
            envelope = self._policies.get(key)
            if envelope is None:
                raise PolicyActivationError(
                    f"Policy {policy_id}@v{version} not found in the store.",
                    detail={"policy_id": policy_id, "version": version},
                )

            if envelope.lifecycle not in (PolicyLifecycle.REVIEW, PolicyLifecycle.ACTIVATED):
                raise PolicyActivationError(
                    f"Policy {policy_id}@v{version} is in lifecycle state {envelope.lifecycle.value!r}; "
                    "only REVIEW policies may be activated.",
                    detail={"policy_id": policy_id, "version": version, "lifecycle": envelope.lifecycle.value},
                )

            # Build the activated envelope (same compiled_condition, new lifecycle value).
            activated = object.__new__(PolicyEnvelope)
            object.__setattr__(activated, "id", envelope.id)
            object.__setattr__(activated, "version", envelope.version)
            object.__setattr__(activated, "governs", envelope.governs)
            object.__setattr__(activated, "scope", envelope.scope)
            object.__setattr__(activated, "condition", envelope.condition)
            object.__setattr__(activated, "decision", envelope.decision)
            object.__setattr__(activated, "approvers", envelope.approvers)
            object.__setattr__(activated, "regulatory_refs", envelope.regulatory_refs)
            object.__setattr__(activated, "lifecycle", PolicyLifecycle.ACTIVATED)
            object.__setattr__(activated, "compiled_condition", envelope.compiled_condition)

            self._policies[key] = activated
            self._impact_reports[key] = impact_report

        log.info("policy activated: %s@v%d (reviewed_by=%s)", policy_id, version, impact_report.reviewed_by)
        return activated

    def deprecate(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Transition a policy to DEPRECATED (cache-only). It will no longer match in `lookup`."""
        with self._lock:
            key = (policy_id, version)
            envelope = self._policies.get(key)
            if envelope is None:
                raise PolicyActivationError(
                    f"Policy {policy_id}@v{version} not found in the store.",
                    detail={"policy_id": policy_id, "version": version},
                )
            deprecated = object.__new__(PolicyEnvelope)
            for attr in (
                "id", "version", "governs", "scope", "condition", "decision",
                "approvers", "regulatory_refs", "compiled_condition",
            ):
                object.__setattr__(deprecated, attr, getattr(envelope, attr))
            object.__setattr__(deprecated, "lifecycle", PolicyLifecycle.DEPRECATED)
            self._policies[key] = deprecated
        log.info("policy deprecated: %s@v%d", policy_id, version)
        return deprecated

    def submit_for_review(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Transition a DRAFT policy to REVIEW (cache-only).

        Raises `PolicyTransitionError` if the policy is missing or not in DRAFT.
        """
        with self._lock:
            key = (policy_id, version)
            envelope = self._policies.get(key)
            if envelope is None:
                raise PolicyTransitionError(
                    f"Policy {policy_id}@v{version} not found in the store.",
                    detail={"policy_id": policy_id, "version": version},
                )
            if envelope.lifecycle is not PolicyLifecycle.DRAFT:
                raise PolicyTransitionError(
                    f"Policy {policy_id}@v{version} is {envelope.lifecycle.value!r}; "
                    "only DRAFT policies may be submitted for review.",
                    detail={"policy_id": policy_id, "version": version, "lifecycle": envelope.lifecycle.value},
                )
            reviewing = object.__new__(PolicyEnvelope)
            for attr in (
                "id", "version", "governs", "scope", "condition", "decision",
                "approvers", "regulatory_refs", "compiled_condition",
            ):
                object.__setattr__(reviewing, attr, getattr(envelope, attr))
            object.__setattr__(reviewing, "lifecycle", PolicyLifecycle.REVIEW)
            self._policies[key] = reviewing
        log.info("policy submitted for review: %s@v%d", policy_id, version)
        return reviewing

    # ── Management reads (lock-guarded snapshots; never raise on absence) ─────────

    def get(self, policy_id: str, version: int) -> PolicyEnvelope | None:
        """Return the envelope for (id, version), or None if absent."""
        with self._lock:
            return self._policies.get((policy_id, version))

    def list_policies(self, lifecycle: PolicyLifecycle | None = None) -> list[PolicyEnvelope]:
        """Return all envelopes, optionally filtered by lifecycle, sorted by (id, version)."""
        with self._lock:
            envelopes = [
                env for env in self._policies.values()
                if lifecycle is None or env.lifecycle is lifecycle
            ]
        return sorted(envelopes, key=lambda e: (e.id, e.version))

    def list_versions(self, policy_id: str) -> list[PolicyEnvelope]:
        """Return all versions of a policy id, sorted ascending by version."""
        with self._lock:
            versions = [env for (pid, _), env in self._policies.items() if pid == policy_id]
        return sorted(versions, key=lambda e: e.version)

    def get_impact_report(self, policy_id: str, version: int) -> ImpactReport | None:
        """Return the stored impact report for (id, version), or None if absent."""
        with self._lock:
            return self._impact_reports.get((policy_id, version))

    # ── Durable write-through (async; not on the hot path) ───────────────────────

    async def hydrate(self) -> None:
        """Repopulate the in-memory cache from the durable repository, recompiling CEL.

        Called once at startup (`kernel.startup()`). No-op when no repository is wired. Every
        persisted envelope is re-`register`ed (which recompiles its CEL `condition`), and every
        persisted impact report is restored, so a restarted kernel enforces the same policies.
        """
        if self._repository is None:
            return
        envelopes = await self._repository.load_all()
        for envelope in envelopes:
            self.register(envelope)  # recompiles CEL; preserves the persisted lifecycle
        for report in await self._repository.load_impact_reports():
            self.store_impact_report(report)
        log.info(
            "policy store hydrated: %d envelope(s) from durable repository", len(envelopes)
        )

    async def register_persisted(self, envelope: PolicyEnvelope) -> PolicyEnvelope:
        """Persist an envelope to the durable store, then register it in the cache.

        Persist-first so the in-memory cache never gets ahead of the durable record on a write
        failure. The immutability guard runs BEFORE the durable write so a re-register of an
        ACTIVATED/DEPRECATED version cannot overwrite the persisted row. Returns the cached
        (compiled) envelope.
        """
        async with self._persist_lock:
            with self._lock:
                self._assert_registrable(envelope)
            if self._repository is not None:
                await self._repository.save_envelope(envelope)
            return self.register(envelope)

    async def activate_persisted(
        self, policy_id: str, version: int, impact_report: ImpactReport
    ) -> PolicyEnvelope:
        """Run the F-10 activation gate in-cache, then persist the report + ACTIVATED lifecycle."""
        activated = self.activate(policy_id, version, impact_report)  # validates F-10 + updates cache
        if self._repository is not None:
            await self._repository.save_impact_report(impact_report)
            await self._repository.set_lifecycle(policy_id, version, PolicyLifecycle.ACTIVATED)
        return activated

    async def deprecate_persisted(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Deprecate a policy in-cache, then persist the DEPRECATED lifecycle."""
        deprecated = self.deprecate(policy_id, version)
        if self._repository is not None:
            await self._repository.set_lifecycle(policy_id, version, PolicyLifecycle.DEPRECATED)
        return deprecated

    async def submit_for_review_persisted(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Transition DRAFT → REVIEW in-cache (validates), then persist the REVIEW lifecycle."""
        reviewing = self.submit_for_review(policy_id, version)
        if self._repository is not None:
            await self._repository.set_lifecycle(policy_id, version, PolicyLifecycle.REVIEW)
        return reviewing

    async def store_impact_report_persisted(self, report: ImpactReport) -> None:
        """Persist an impact report to the durable store, then cache it.

        Persist-first so the cache never gets ahead of the durable record on a write failure.
        """
        if self._repository is not None:
            await self._repository.save_impact_report(report)
        self.store_impact_report(report)

    # ── Query ───────────────────────────────────────────────────────────────────

    def lookup(self, action_type: str, tenant_id: str) -> list[PolicyEnvelope]:
        """Return all ACTIVATED policies that govern `action_type` for `tenant_id`.

        Scope matching rules:
        - `{"tenant": "exact-id"}` matches only that tenant.
        - `{"tenant": "*"}` matches any tenant.
        - Both are returned if they match — conflict resolution is the evaluator's job.
        - `governs: "*"` matches any action type.
        """
        with self._lock:
            candidates = list(self._policies.values())

        result: list[PolicyEnvelope] = []
        for env in candidates:
            if env.lifecycle is not PolicyLifecycle.ACTIVATED:
                continue

            # action-type filter
            if env.governs != "*" and env.governs != action_type:
                continue

            # tenant-scope filter
            scope_tenant = env.scope.get("tenant", "*")
            if scope_tenant != "*" and scope_tenant != tenant_id:
                continue

            result.append(env)

        return result
