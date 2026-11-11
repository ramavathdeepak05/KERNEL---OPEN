"""QUAICU Kernel — SDK entry point.

``Kernel`` holds injected collaborators and vends the governance decorators:
  - ``@kernel.governed(...)`` — wrap an action function.
  - ``@kernel.governed_tool(...)`` — wrap an agent tool (returns the tool's own result).
  - ``kernel.generate(...)`` — a governed model call through the AI Gateway.
  - ``kernel.for_agent(actor)`` — a handle that stamps every action with that agent's identity.

It is a thin composition root; all governance logic lives in ``core/``.

Composable enforcement (F-11): every governed action runs under a ``GovernanceProfile`` that
declares which layers are enforced (identity, consent, policy, HITL gate, gateway protections,
ledger seal, event emit). The profile is resolved per action type, overridable per call.
"""

from __future__ import annotations

import dataclasses
import functools
import importlib
import inspect
import logging
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from quaicu.core.errors import (  # noqa: F401 (re-exported)
    LifecycleDeniedError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
)
from quaicu.core.gateway.allowlist import InMemoryModelAllowlist
from quaicu.core.gateway.budget import InMemoryBudgetTracker
from quaicu.core.gateway.engine import AIGateway
from quaicu.core.gateway.masking import MaskingConfig
from quaicu.core.lifecycle.context import async_actor_scope, get_current_actor, set_actor
from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.lifecycle.engine import LifecycleEngine
from quaicu.core.ledger.repository import LedgerRepository
from quaicu.core.lifecycle.profile import GovernanceProfile, resolve_preset
from quaicu.core.lifecycle.protocols import ActionRepository, EventBus, Ledger, PolicyEvaluator
from quaicu.core.policy import (
    ImpactReport,
    PolicyEngine,
    PolicyEnvelope,
    PolicyRepository,
    PolicyStore,
)
from quaicu.core.ports import HITLPort, IdentityPort
from quaicu.core.ports.anchor import AnchorPort
from quaicu.core.ports.consent import ConsentPort
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    IdempotencyKey,
    ModelRef,
    ModelResponse,
    RequestContext,
    TenantId,
)
from quaicu.delivery.sdk.errors import SdkUsageError


def _normalize_roles(roles: Any) -> tuple[str, ...]:
    """Normalise role names to the ``role:<name>`` convention used across the kernel (cf. the HITL
    approver matching in quaicu/core/hitl). Bare names are prefixed; already-prefixed names pass through."""
    return tuple(r if str(r).startswith("role:") else f"role:{r}" for r in roles)


# ── In-process action repository (used when no storage adapter is provided) ────

class _InMemoryActionRepository:
    """Minimal in-process action store for SDK demos and tests."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], Action] = {}

    async def insert_if_absent(self, action: Action) -> Action | None:
        key = (str(action.tenant), str(action.idempotency_key))
        if key in self._store:
            return self._store[key]
        self._store[key] = action
        return None

    async def update_state(self, action: Action) -> None:
        key = (str(action.tenant), str(action.idempotency_key))
        self._store[key] = action

    async def get_by_idempotency_key(
        self, tenant: TenantId, key: IdempotencyKey
    ) -> Action | None:
        return self._store.get((str(tenant), str(key)))

    async def get_by_id(self, tenant: TenantId, action_id: ActionId) -> Action | None:
        return next(
            (
                a
                for a in self._store.values()
                if str(a.id) == str(action_id) and str(a.tenant) == str(tenant)
            ),
            None,
        )

    @property
    def by_key(self) -> dict[tuple[str, str], Action]:
        return self._store


# ── Adapter registry (F-11 config over code) ───────────────────────────────────

log = logging.getLogger(__name__)


# Maps config key → (module_path, class_name). Extended by plugins via register_adapter().
_ADAPTER_REGISTRY: dict[str, tuple[str, str]] = {
    # WorkflowPort
    "memory":                  ("quaicu.adapters.workflow.memory",          "InMemoryWorkflowAdapter"),
    "aws_sfn":                 ("quaicu.adapters.workflow.aws_sfn",         "StepFunctionsWorkflowAdapter"),
    # InferencePort
    "openai_compat":           ("quaicu.adapters.inference.openai_compat",  "OpenAICompatInferenceAdapter"),
    "vertex_inference":        ("quaicu.adapters.inference.vertex",         "VertexInferenceAdapter"),
    # HITLPort
    "webhook":                 ("quaicu.adapters.hitl.webhook",             "WebhookHITLAdapter"),
    "in_process":              ("quaicu.core.hitl.engine",                  "InProcessHITLPort"),
    # IdentityPort
    "local_token":             ("quaicu.adapters.identity.local_token",     "LocalTokenIdentityAdapter"),
    "jwt":                     ("quaicu.adapters.identity.jwt_adapter",     "JWTIdentityAdapter"),
    "oidc":                    ("quaicu.adapters.identity.oidc",            "OIDCIdentityAdapter"),
    # StoragePort
    "memory_storage":          ("quaicu.adapters.storage.memory",           "InMemoryStorageAdapter"),
    "postgres_storage":        ("quaicu.adapters.storage.postgres",         "PostgresStorageAdapter"),
    # PolicyEvaluator (dev/demo only)
    "always_allow":            ("quaicu.adapters.policy.always_allow",      "AlwaysAllowPolicyAdapter"),
    # PolicyRepository (durable policy store backends; CEL engine wired via _build_policy)
    "memory_policy":           ("quaicu.adapters.policy.memory",            "InMemoryPolicyRepository"),
    "postgres_policy":         ("quaicu.adapters.policy.postgres",          "PostgresPolicyRepository"),
    # Ledger
    "memory_ledger":           ("quaicu.adapters.ledger.memory",            "InMemoryLedgerAdapter"),
    "memory_signed_ledger":    ("quaicu.adapters.ledger.memory_signed",     "MemorySignedLedgerAdapter"),
    "openbao_ledger":          ("quaicu.adapters.ledger.openbao",           "OpenBaoLedgerAdapter"),
    "gcp_kms_ledger":          ("quaicu.adapters.ledger.gcp_kms",           "GcpKmsLedgerAdapter"),
    "aws_kms_ledger":          ("quaicu.adapters.ledger.aws_kms",           "AwsKmsLedgerAdapter"),
    # LedgerRepository (durable ledger backends; the TrustLedger writes through to these)
    "memory_ledger_repo":      ("quaicu.adapters.ledger.memory_repo",       "InMemoryLedgerRepository"),
    "postgres_ledger":         ("quaicu.adapters.ledger.postgres",          "PostgresLedgerRepository"),
    # EventBus
    "memory_events":           ("quaicu.adapters.events.memory",            "InMemoryEventBusAdapter"),
}


def _load_adapter(name: str, **kwargs: Any) -> Any:
    """Import and instantiate an adapter by registry name."""
    if name not in _ADAPTER_REGISTRY:
        raise ValueError(
            f"Unknown adapter {name!r}. Available: {sorted(_ADAPTER_REGISTRY)}"
        )
    module_path, class_name = _ADAPTER_REGISTRY[name]
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls(**kwargs) if kwargs else cls()


# ── Kernel ─────────────────────────────────────────────────────────────────────


@dataclasses.dataclass
class Kernel:
    """Composition root for the QUAICU governance kernel.

    Holds all port adapters, the optional AI Gateway, and the governance profiles. Create via
    ``Kernel.from_config(path)`` for production, or ``Kernel.from_parts(...)`` in tests.
    """

    engine: LifecycleEngine
    tenant: TenantId
    gateway: AIGateway | None = None
    default_profile: GovernanceProfile = dataclasses.field(default_factory=GovernanceProfile.all)
    action_profiles: dict[str, GovernanceProfile] = dataclasses.field(default_factory=dict)
    # Set only when the CEL policy engine is wired (policy = "cel_policy"). The store is the
    # in-memory read cache; the repository is its durable backend. Both are exposed so the policy
    # management API (and the SDK write-through primitives below) can author and persist policies.
    policy_store: PolicyStore | None = None
    policy_repository: PolicyRepository | None = None
    # Set when a durable ledger backend is wired ([adapters].ledger_store). Exposed so the kernel can
    # close its pool on shutdown; the TrustLedger writes through to it and hydrates from it on boot.
    ledger_repository: LedgerRepository | None = None
    # An independent witness (AnchorPort) that cosigns the tenant's STH on export (D3-2). None → the
    # ledger is not externally anchored (exports carry no cosignature).
    witness: "AnchorPort | None" = None
    # Control-plane roles permitted to author/manage policies via the management API. Normalised to
    # the ``role:<name>`` convention. An actor needs at least one of these to use ``/v1/policies``.
    policy_admin_roles: tuple[str, ...] = ("role:policy_admin",)

    @property
    def has_identity(self) -> bool:
        """True if an IdentityPort is wired. The standalone REST API requires this so it never
        trusts a caller-supplied actor."""
        return self.engine.has_identity

    @property
    def has_inference(self) -> bool:
        """True if an AI Gateway (inference adapter) is wired — i.e. ``generate`` is available."""
        return self.gateway is not None

    @property
    def has_policy_store(self) -> bool:
        """True if the CEL policy engine is wired — i.e. policies can be authored/persisted."""
        return self.policy_store is not None

    @property
    def hitl_queue_depth(self) -> int:
        """Number of HITL approvals still pending (dashboard read-model).

        Only the in-process HITL adapter exposes a queryable store; for any other adapter
        (e.g. a webhook adapter whose queue lives in an external system) this returns 0 — the
        dashboard should source that depth from the external system in that deployment.
        """
        from quaicu.core.hitl.engine import InProcessHITLPort

        hitl = self.engine._hitl  # type: ignore[attr-defined]
        if isinstance(hitl, InProcessHITLPort):
            return hitl._store.pending_count()
        return 0

    def _in_process_hitl(self) -> Any:
        """Return the wired HITL port if it is an in-process (queryable) one, else None.

        Only the in-process adapter exposes a listable approval store; a webhook/external adapter
        keeps its queue in another system, so the control-plane approvals surface is unavailable
        (the route maps None → 503).
        """
        from quaicu.core.hitl.engine import InProcessHITLPort

        hitl = self.engine._hitl  # type: ignore[attr-defined]
        return hitl if isinstance(hitl, InProcessHITLPort) else None

    def list_pending_approvals(self) -> list[Any]:
        """List pending HITL approval records (operator queue). Empty if no in-process port."""
        hitl = self._in_process_hitl()
        return hitl.list_pending() if hitl is not None else []

    async def approve(self, handle_id: str, *, actor: Actor) -> Any:
        """Approve a pending HITL request as ``actor`` and resume the action (execute → seal → emit).

        Ergonomic wrapper over ``decide_approval(handle_id, decision="approved", actor=actor)``. Use
        it with the ``handle_id`` carried on a caught ``LifecyclePendingApprovalError``::

            try:
                async with kernel.actor_context(maker):
                    await approve_loan(loan_id="L-1", amount=5000)
            except LifecyclePendingApprovalError as exc:
                await kernel.approve(exc.detail["handle_id"], actor=checker)

        The HITL port enforces approver eligibility and the self-approval guard (raises
        ``HITLPortError`` otherwise). Returns the updated ``ApprovalRecord``.
        """
        return await self.decide_approval(handle_id, decision="approved", actor=actor)

    async def reject(self, handle_id: str, *, actor: Actor) -> Any:
        """Reject a pending HITL request as ``actor`` (fail-closed DENY of the suspended action).

        Ergonomic wrapper over ``decide_approval(handle_id, decision="rejected", actor=actor)``.
        Returns the updated ``ApprovalRecord``.
        """
        return await self.decide_approval(handle_id, decision="rejected", actor=actor)

    async def decide_approval(self, handle_id: str, *, decision: str, actor: Actor) -> Any:
        """Approve or reject a pending HITL request as ``actor``.

        ``decision`` is ``"approved"`` or ``"rejected"``. Delegates to the HITL port, which enforces
        approver eligibility + the self-approval guard (raises ``HITLPortError`` otherwise). Returns
        the updated ``ApprovalRecord``. Raises ``RuntimeError`` if no in-process HITL port is wired.
        """
        hitl = self._in_process_hitl()
        if hitl is None:
            raise SdkUsageError("No in-process HITL port configured — approvals unavailable.")
        if decision == "approved":
            await hitl.approve(
                handle_id, approver_actor_id=actor.id, approver_roles=tuple(actor.roles)
            )
            # Resume the gated action (execute → seal → emit) now that it's approved. Best-effort:
            # a deferred (PENDING_APPROVAL) action completes here; a synchronous one is already
            # resolved and resume is a no-op. Never raises out — the approval is already recorded.
            await self.resume_approved(handle_id, approver=actor)
        elif decision == "rejected":
            await hitl.reject(
                handle_id, approver_actor_id=actor.id, approver_roles=tuple(actor.roles)
            )
            # A deferred (PENDING_APPROVAL) action must reach a terminal state on rejection — fail-closed
            # DENY (mirrors the synchronous gate). No-op if there's no such pending action.
            await self._deny_rejected(handle_id)
        else:
            raise ValueError(f"decision must be 'approved' or 'rejected', got {decision!r}")
        return hitl.get_record(handle_id)

    async def resume_approved(self, handle_id: str, *, approver: Actor) -> Any:
        """Resume a PENDING_APPROVAL action after its approval — execute → seal → emit.

        Returns the final ``Action`` (COMPLETED on success), or ``None`` if there is nothing to resume
        (no in-process HITL, the record isn't APPROVED, the action is absent, or it's already resolved —
        the resume is idempotent). Best-effort: a load/resume failure is logged and swallowed, leaving
        the approval recorded + the action PENDING for a reconcile (never raises out of the approve path).
        Scoped to declarative ``propose`` actions, whose execute step is recording the proposed payload.
        """
        from quaicu.core.types import ApprovalDecision, ApproverRef

        hitl = self._in_process_hitl()
        if hitl is None:
            return None
        record = hitl.get_record(handle_id)
        if record is None or record.decision is not ApprovalDecision.APPROVED:
            return None
        try:
            action = await self.engine._repo.get_by_id(record.tenant, record.action_id)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — load failure: leave PENDING for reconcile
            log.exception("resume: could not load action %s", record.action_id)
            return None
        if action is None or action.state is not ActionState.PENDING_APPROVAL:
            return None  # nothing to resume / already resolved (idempotent)

        payload = dict(action.payload)

        async def _execute_fn() -> dict[str, Any]:
            return {"payload": payload}

        approver_ref = ApproverRef(f"user:{record.decided_by}") if record.decided_by else None
        resolved = self.resolve_profile(action.type)
        try:
            return await self.engine.resume_after_approval(
                action, approver=approver_ref, execute_fn=_execute_fn, profile=resolved
            )
        except Exception:  # noqa: BLE001 — seal/execute failure already HALTs in-engine; never raise out
            log.exception("resume_after_approval failed for action %s", action.id)
            return None

    async def _deny_rejected(self, handle_id: str) -> Any:
        """Terminal-deny a PENDING_APPROVAL action whose approval was just rejected. Best-effort no-op
        if there's no in-process HITL / record / pending action (idempotent)."""
        hitl = self._in_process_hitl()
        if hitl is None:
            return None
        record = hitl.get_record(handle_id)
        if record is None:
            return None
        try:
            action = await self.engine._repo.get_by_id(record.tenant, record.action_id)  # type: ignore[attr-defined]
            if action is None:
                return None
            return await self.engine.deny_pending(action, "approval rejected")
        except Exception:  # noqa: BLE001 — leave PENDING for reconcile rather than raise out
            log.exception("deny-on-reject failed for action %s", record.action_id)
            return None

    # ── Lifecycle hooks (startup / shutdown) ─────────────────────────────────────

    async def startup(self) -> None:
        """Initialise async resources. Call once before serving (the API does this via lifespan).

        Hydrates the policy store and the durable ledger from their repositories so a restarted
        kernel enforces the same policies and serves the same transparency log. No-op for the
        in-memory backends.
        """
        if self.policy_store is not None:
            await self.policy_store.hydrate()
        ledger_hydrate = getattr(self.engine._ledger, "hydrate", None)  # type: ignore[attr-defined]
        if ledger_hydrate is not None:
            await ledger_hydrate()

    async def shutdown(self) -> None:
        """Release async resources (connection pools). Call once on shutdown."""
        for collaborator in (
            self.policy_repository,
            self.ledger_repository,
            self.engine._ledger,  # type: ignore[attr-defined]
            self.gateway,
        ):
            close = getattr(collaborator, "close", None)
            if close is not None:
                try:
                    await close()
                except Exception:  # noqa: BLE001 — shutdown is best-effort
                    pass

    # ── Identity (control-plane actor resolution) ────────────────────────────────

    async def resolve_actor(
        self, context: RequestContext, *, tenant: TenantId | None = None
    ) -> Actor:
        """Resolve the authenticated actor from a request context via the IdentityPort.

        Used by control-plane surfaces (the policy management API) that authenticate a caller
        outside the run lifecycle. ``tenant`` overrides the kernel's default tenant — required on a
        shared tier-kernel that serves many tenants, so identity is verified against the *request's*
        tenant (F-07), not the kernel's fixed one. Raises ``RuntimeError`` if no IdentityPort is
        wired; propagates ``IdentityPortError`` / ``TenantIsolationError`` fail-closed.
        """
        identity = self.engine.identity
        if identity is None:
            raise RuntimeError("No identity adapter configured.")
        return await identity.resolve_actor(context=context, tenant=tenant or self.tenant)

    # ── Regulator ledger-proof export (WS-F) ─────────────────────────────────────

    def export_ledger_proof(
        self,
        tenant: TenantId,
        *,
        window_start: "datetime | None" = None,
        window_end: "datetime | None" = None,
        regulation_refs: list[str] | None = None,
        policy_versions: list[str] | None = None,
    ):
        """Build a self-verifying `LedgerProofBundle` of a tenant's sealed actions in a time window.

        Reads only already-sealed K·02 entries (no model re-calls, F-09): collects the in-window
        entries, computes each one's RFC 6962 inclusion proof against the tenant's signed tree head,
        embeds the signing public key, and assembles the K·14 evidence pack with real proof refs. The
        regulator verifies it offline via `core.regmap.export.verify_ledger_proof_bundle`.
        """
        from datetime import datetime, timezone

        from quaicu.core.regmap.export import build_ledger_proof_bundle

        def _aware(dt: "datetime") -> "datetime":
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

        ledger = self.engine._ledger  # type: ignore[attr-defined]
        entries = ledger.get_entries(tenant)
        ws = _aware(window_start) if window_start else datetime(1970, 1, 1, tzinfo=timezone.utc)
        we = _aware(window_end) if window_end else datetime.now(tz=timezone.utc)

        def _in_window(e) -> bool:
            return ws <= _aware(e.sealed_at) <= we

        selected = [e for e in entries if _in_window(e)]
        entries_with_paths = [
            (e, ledger.get_inclusion_proof(tenant, e.ledger_seq)[1]) for e in selected
        ]
        sth = ledger.get_signed_tree_head(tenant)
        signer = getattr(ledger, "_signer", None)
        public_key_pem = getattr(signer, "public_key_pem", None)

        # Anchor the current STH with the independent witness (if wired) — a fork/rewind raises
        # LedgerTamperError here (fail-closed: no bundle for a tampered log).
        cosig = None
        if self.witness is not None:
            from quaicu.core.ledger.anchor import anchor_current_sth

            cosig = anchor_current_sth(ledger, self.witness, tenant)

        return build_ledger_proof_bundle(
            tenant_id=str(tenant),
            window_start=ws,
            window_end=we,
            entries_with_paths=entries_with_paths,
            sth=sth,
            public_key_pem=public_key_pem,
            regulation_refs=regulation_refs,
            policy_versions=policy_versions,
            witness_cosignature=cosig,
        )

    # ── Policy authoring (write-through primitives the management API wraps) ──────

    async def register_policy(self, envelope: PolicyEnvelope) -> PolicyEnvelope:
        """Persist a policy envelope and register it in the live store. Requires the CEL engine."""
        if self.policy_store is None:
            raise RuntimeError(
                "No policy store configured — set policy = \"cel_policy\" to author policies."
            )
        return await self.policy_store.register_persisted(envelope)

    async def activate_policy(
        self, policy_id: str, version: int, impact_report: ImpactReport
    ) -> PolicyEnvelope:
        """Run the F-10 activation gate and persist the ACTIVATED policy. Requires the CEL engine."""
        if self.policy_store is None:
            raise RuntimeError("No policy store configured.")
        return await self.policy_store.activate_persisted(policy_id, version, impact_report)

    async def deprecate_policy(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Deprecate a policy (stops matching in lookups) and persist it. Requires the CEL engine."""
        if self.policy_store is None:
            raise RuntimeError("No policy store configured.")
        return await self.policy_store.deprecate_persisted(policy_id, version)

    async def submit_policy_for_review(self, policy_id: str, version: int) -> PolicyEnvelope:
        """Transition a DRAFT policy to REVIEW and persist it. Requires the CEL engine."""
        if self.policy_store is None:
            raise RuntimeError("No policy store configured.")
        return await self.policy_store.submit_for_review_persisted(policy_id, version)

    async def store_policy_impact_report(self, report: ImpactReport) -> None:
        """Persist a policy's F-10 impact report so a later activation can reference it."""
        if self.policy_store is None:
            raise RuntimeError("No policy store configured.")
        await self.policy_store.store_impact_report_persisted(report)

    def resolve_profile(
        self, action_type: str, override: GovernanceProfile | None = None
    ) -> GovernanceProfile:
        """Resolve the governance profile for an action type.

        Precedence: explicit call override > per-action-type config > kernel default.
        """
        if override is not None:
            return override
        return self.action_profiles.get(action_type, self.default_profile)

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, path: str | Path) -> "Kernel":
        """Build a Kernel from a TOML config file.

        Selects concrete adapter classes by the names declared under ``[adapters]``. Optionally
        wires the AI Gateway (``[adapters].inference`` + ``[gateway]``) and the governance
        profiles (``[governance]``).
        """
        import os
        import tomllib

        def _expand(node: Any) -> Any:
            """Resolve ``${ENV_VAR}`` references in string values so configs can keep secrets
            (DSNs, signing keys) out of the file and inject them from the environment at load.
            Unset vars are left literal."""
            if isinstance(node, str):
                return os.path.expandvars(node)
            if isinstance(node, dict):
                return {k: _expand(v) for k, v in node.items()}
            if isinstance(node, list):
                return [_expand(v) for v in node]
            return node

        with open(path, "rb") as f:
            cfg = _expand(tomllib.load(f))

        tenant = TenantId(cfg.get("tenant", {}).get("id", "default"))
        adapter_cfg = cfg.get("adapters", {})

        repo: ActionRepository = _InMemoryActionRepository()
        policy: PolicyEvaluator | None = None
        policy_store: PolicyStore | None = None
        policy_repository: PolicyRepository | None = None
        ledger_repository: LedgerRepository | None = None
        hitl: HITLPort | None = None
        ledger: Ledger | None = None
        events: EventBus | None = None
        identity: IdentityPort | None = None
        consent: ConsentPort | None = None

        if "storage" in adapter_cfg:
            repo = _load_adapter(adapter_cfg["storage"], **cfg.get("storage", {}))
        if "policy" in adapter_cfg:
            if adapter_cfg["policy"] == "cel_policy":
                # The real K·01 CEL engine needs composition (PolicyEngine over a PolicyStore over an
                # optional durable repository), so it is built here rather than via the flat registry.
                policy, policy_store, policy_repository = cls._build_policy(adapter_cfg, cfg)
                cls._seed_policies(policy_store, cfg)
            else:
                policy = _load_adapter(adapter_cfg["policy"])
        if "hitl" in adapter_cfg:
            hitl = cls._build_hitl(adapter_cfg, cfg)
        if "ledger" in adapter_cfg:
            ledger, ledger_repository = cls._build_ledger(adapter_cfg, cfg)
        if "events" in adapter_cfg:
            events = _load_adapter(adapter_cfg["events"])
            cls._wire_event_sinks(events, cfg)
        if "identity" in adapter_cfg:
            identity = _load_adapter(adapter_cfg["identity"], **cfg.get("identity", {}))
        if "consent" in adapter_cfg:
            consent = _load_adapter(adapter_cfg["consent"], **cfg.get("consent", {}))

        if policy is None or hitl is None or ledger is None or events is None:
            raise ValueError(
                "kernel.toml must declare [adapters] for: policy, hitl, ledger, events"
            )

        # Governance profiles (composable enforcement).
        gov_cfg = cfg.get("governance", {})
        default_profile = resolve_preset(gov_cfg.get("default", "all"))
        action_profiles = {
            at: resolve_preset(name)
            for at, name in gov_cfg.get("action_profiles", {}).items()
        }
        policy_admin_roles = _normalize_roles(gov_cfg.get("policy_admin_roles", ["policy_admin"]))

        # Optional AI Gateway for governed inference.
        gateway = cls._build_gateway(tenant, adapter_cfg, cfg) if "inference" in adapter_cfg else None

        # Optional external anchor witness (D3-2) — cosigns the STH on export / periodic anchoring.
        witness = cls._build_witness(adapter_cfg, cfg) if "witness" in adapter_cfg else None

        engine = LifecycleEngine(
            repository=repo,
            policy=policy,
            hitl=hitl,
            ledger=ledger,
            events=events,
            identity=identity,
            consent=consent,
            default_profile=default_profile,
        )
        return cls(
            engine=engine,
            tenant=tenant,
            gateway=gateway,
            default_profile=default_profile,
            action_profiles=action_profiles,
            policy_store=policy_store,
            policy_repository=policy_repository,
            ledger_repository=ledger_repository,
            witness=witness,
            policy_admin_roles=policy_admin_roles,
        )

    @staticmethod
    def _build_witness(adapter_cfg: dict[str, Any], cfg: dict[str, Any]) -> "AnchorPort | None":
        """Build the anchor witness from ``[adapters].witness`` + ``[witness]``.

        Only ``http_witness`` is config-constructible (an out-of-process witness at ``base_url``, with
        a shared ``token``). An in-process ``SoftwareWitness`` is wired programmatically (tests / a
        sovereign single node), not from TOML.
        """
        name = adapter_cfg.get("witness")
        if name != "http_witness":
            raise ValueError(f"unknown witness adapter {name!r}; expected 'http_witness'")
        wcfg = cfg.get("witness", {})
        base_url = str(wcfg.get("base_url", "")).strip()
        if not base_url:
            raise ValueError("[witness] requires base_url for the http_witness adapter")
        from quaicu.adapters.ledger.http_witness import HttpWitness

        return HttpWitness(base_url, str(wcfg.get("token", "")).strip() or None)

    @staticmethod
    def _build_hitl(adapter_cfg: dict[str, Any], cfg: dict[str, Any]) -> HITLPort:
        """Assemble the HITL port.

        For ``hitl = "in_process"`` an optional ``[hitl].store = "postgres"`` (+ a ``dsn``) backs the
        approvals queue with a durable, cross-instance ``PostgresApprovalStore`` instead of per-process
        memory — so ``/v1/approvals`` is consistent on a horizontally-scaled plane. Omit ``store`` for
        the in-memory default. ``hitl = "email"`` builds an ``EmailHITLAdapter`` (in-process store +
        signed approve/reject links). Any other adapter (e.g. ``webhook``) is built from the flat registry.
        """
        name = adapter_cfg["hitl"]
        hitl_cfg = dict(cfg.get("hitl", {}))
        if name == "email":
            return Kernel._build_email_hitl(hitl_cfg)
        if name == "teams":
            return Kernel._build_teams_hitl(hitl_cfg)
        if name != "in_process":
            return _load_adapter(name, **hitl_cfg)

        from quaicu.core.hitl.engine import InProcessHITLPort

        store_kind = hitl_cfg.pop("store", None)
        dsn = hitl_cfg.pop("dsn", None)
        kwargs: dict[str, Any] = {}
        if "timeout_seconds" in hitl_cfg:
            kwargs["timeout_seconds"] = int(hitl_cfg["timeout_seconds"])
        if store_kind == "postgres":
            if not dsn:
                log.warning("hitl.store=postgres but no [hitl].dsn — falling back to in-memory queue")
            else:
                from quaicu.adapters.hitl.postgres_store import PostgresApprovalStore

                kwargs["store"] = PostgresApprovalStore(str(dsn))
        return InProcessHITLPort(**kwargs)

    @staticmethod
    def _build_email_hitl(hitl_cfg: dict[str, Any]) -> HITLPort:
        """Assemble the `EmailHITLAdapter` from ``[hitl]`` config (hitl = "email").

        Keys: ``approver_email`` (required — the compliance inbox), ``approver_id`` /
        ``approver_roles`` (the identity the link seals; roles must satisfy the policy's approver refs),
        ``link_base_url`` (public origin for the links), ``resend_api_key`` / ``from`` (Resend sender,
        else log-only), ``store = "postgres"`` + ``dsn`` (durable queue), ``timeout_seconds``,
        ``link_ttl_seconds``. The link secret is read from ``QUAICU_APPROVAL_LINK_SECRET`` (fail-closed).
        """
        import os

        from quaicu.adapters.hitl.email import EmailHITLAdapter
        from quaicu.core.hitl.links import ApprovalLinkSigner

        secret = os.getenv("QUAICU_APPROVAL_LINK_SECRET", "")
        if not secret:
            raise ValueError(
                "hitl = \"email\" requires QUAICU_APPROVAL_LINK_SECRET (signs the approve/reject links)."
            )

        api_key = (
            os.path.expandvars(str(hitl_cfg.get("resend_api_key", "")))
            or os.getenv("RESEND_API_KEY", "")
        ).strip()
        sender_from = (
            os.path.expandvars(str(hitl_cfg.get("from", ""))) or os.getenv("EMAIL_FROM", "")
        ).strip() or "onboarding@resend.dev"
        if api_key:
            from quaicu.adapters.email import ResendEmailAdapter

            sender: Any = ResendEmailAdapter(api_key=api_key, sender=sender_from)
        else:
            from quaicu.adapters.email import LogOnlyEmailSender

            sender = LogOnlyEmailSender()

        store = None
        if hitl_cfg.get("store") == "postgres" and hitl_cfg.get("dsn"):
            from quaicu.adapters.hitl.postgres_store import PostgresApprovalStore

            store = PostgresApprovalStore(str(hitl_cfg["dsn"]))

        roles = tuple(str(r) for r in hitl_cfg.get("approver_roles", ()))
        return EmailHITLAdapter(
            sender=sender,
            signer=ApprovalLinkSigner(secret),
            link_base_url=str(hitl_cfg.get("link_base_url", "")),
            approver_email=str(hitl_cfg.get("approver_email", "")),
            approver_id=str(hitl_cfg.get("approver_id", "compliance")),
            approver_roles=roles,
            link_ttl_seconds=int(hitl_cfg.get("link_ttl_seconds", 604800)),
            timeout_seconds=int(hitl_cfg.get("timeout_seconds", 86400)),
            store=store,
        )

    @staticmethod
    def _build_teams_hitl(hitl_cfg: dict[str, Any]) -> HITLPort:
        """Assemble the `MicrosoftTeamsHITLAdapter` from ``[hitl]`` config (hitl = "teams").

        Keys: ``webhook_url`` (required — a Teams incoming webhook), ``link_base_url`` (public origin for
        the approve/reject links), ``approver_id`` / ``approver_roles`` (identity the link seals; roles
        must satisfy the policy's approver refs), ``store = "postgres"`` + ``dsn`` (durable queue),
        ``timeout_seconds``, ``link_ttl_seconds``. The link secret is ``QUAICU_APPROVAL_LINK_SECRET``
        (fail-closed) — the same signed confirm-page flow as the email channel.
        """
        import os

        from quaicu.adapters.hitl.teams import MicrosoftTeamsHITLAdapter
        from quaicu.core.hitl.links import ApprovalLinkSigner

        secret = os.getenv("QUAICU_APPROVAL_LINK_SECRET", "")
        if not secret:
            raise ValueError(
                "hitl = \"teams\" requires QUAICU_APPROVAL_LINK_SECRET (signs the approve/reject links)."
            )

        store = None
        if hitl_cfg.get("store") == "postgres" and hitl_cfg.get("dsn"):
            from quaicu.adapters.hitl.postgres_store import PostgresApprovalStore

            store = PostgresApprovalStore(str(hitl_cfg["dsn"]))

        roles = tuple(str(r) for r in hitl_cfg.get("approver_roles", ()))
        return MicrosoftTeamsHITLAdapter(
            webhook_url=os.path.expandvars(str(hitl_cfg.get("webhook_url", ""))),
            signer=ApprovalLinkSigner(secret),
            link_base_url=str(hitl_cfg.get("link_base_url", "")),
            approver_id=str(hitl_cfg.get("approver_id", "compliance")),
            approver_roles=roles,
            link_ttl_seconds=int(hitl_cfg.get("link_ttl_seconds", 604800)),
            timeout_seconds=int(hitl_cfg.get("timeout_seconds", 86400)),
            store=store,
        )

    @staticmethod
    def _build_ledger(
        adapter_cfg: dict[str, Any], cfg: dict[str, Any]
    ) -> tuple[Ledger, LedgerRepository | None]:
        """Assemble the ledger adapter, optionally backed by a durable LedgerRepository.

        ``[adapters].ledger_store`` selects the durable backend (``"postgres_ledger"`` /
        ``"memory_ledger_repo"``); omit it for a non-durable in-memory ledger. Durability is wired
        through the TrustLedger-based signing adapters (``openbao_ledger``, ``gcp_kms_ledger``) — the
        dev ``memory_ledger`` adapter does not persist. The ledger hydrates from the repository at
        ``kernel.startup()``.
        """
        # TrustLedger-based signing adapters that accept a durable LedgerRepository kwarg.
        # memory_signed_ledger + a Postgres store = the real durable transparency log with a
        # software (per-process, ephemeral) signer — for load tests / dev multi-worker runs where
        # provisioning KMS/OpenBao is overkill. Production signing stays KMS/OpenBao (stable key).
        _DURABLE_LEDGERS = {
            "openbao_ledger",
            "gcp_kms_ledger",
            "aws_kms_ledger",
            "memory_signed_ledger",
        }
        name = adapter_cfg["ledger"]
        ledger_kwargs = cfg.get("ledger", {})
        repository: LedgerRepository | None = None
        if "ledger_store" in adapter_cfg:
            repository = _load_adapter(adapter_cfg["ledger_store"], **cfg.get("ledger_store", {}))
        if name in _DURABLE_LEDGERS and repository is not None:
            ledger = _load_adapter(name, **ledger_kwargs, repository=repository)
        else:
            ledger = _load_adapter(name, **ledger_kwargs)
            repository = None  # adapter does not support durability; don't expose an unused pool
        return ledger, repository

    @staticmethod
    def _seed_policies(store: Any, cfg: dict[str, Any]) -> None:
        """Register operator-provided ``[[policy.seed]]`` entries as ACTIVATED policies.

        These are *trusted, config-time* seeds — equivalent to hydrating already-activated policies
        from a durable store, so they do not go through (or bypass) the F-10 API activation gate. Used
        to ship demo/guardrail policies with the free tier so a CEL-engine deployment isn't an empty
        (fail-closed DENY) store. Each seed: ``id``, ``condition`` (CEL), ``decision``
        (allow|deny|require_approval); optional ``governs`` (default "*"), ``version``, ``approvers``,
        ``regulatory_refs``.
        """
        seeds = cfg.get("policy", {}).get("seed", [])
        if not seeds:
            return
        from quaicu.core.policy.model import PolicyEnvelope, PolicyLifecycle
        from quaicu.core.types import ApproverRef, Decision

        for s in seeds:
            envelope = PolicyEnvelope(
                id=str(s["id"]),
                version=int(s.get("version", 1)),
                governs=str(s.get("governs", "*")),
                scope={"tenant": str(s.get("tenant", "*"))},
                condition=str(s["condition"]),
                decision=Decision(str(s["decision"]).lower()),
                approvers=tuple(ApproverRef(str(a)) for a in s.get("approvers", [])),
                regulatory_refs=tuple(str(r) for r in s.get("regulatory_refs", [])),
                lifecycle=PolicyLifecycle.ACTIVATED,
            )
            store.register(envelope)

    @staticmethod
    def _wire_event_sinks(events: Any, cfg: dict[str, Any]) -> None:
        """Subscribe configured event sinks to the bus (no-op if the bus has no ``subscribe``).

        ``[events].log_sink = true`` records every sealed governed action to the ``quaicu.audit``
        logger (→ Cloud Logging) — a durable audit stream even when the ledger is in-memory (free
        tier). ``[events].pubsub_topic = "…"`` additionally fans out to GCP Pub/Sub. Sinks are
        best-effort; a sink failure never breaks the seal path.
        """
        if not hasattr(events, "subscribe"):
            return
        ev = cfg.get("events", {})
        if ev.get("log_sink"):
            from quaicu.adapters.events.sinks import LoggingEventSink

            events.subscribe(LoggingEventSink())
        topic = ev.get("pubsub_topic")
        if topic:
            from quaicu.adapters.events.sinks import PubSubEventSink

            events.subscribe(PubSubEventSink(str(topic)))
        bus = ev.get("eventbridge_bus")
        if bus:
            from quaicu.adapters.events.sinks import EventBridgeEventSink

            events.subscribe(
                EventBridgeEventSink(
                    str(bus),
                    source=str(ev.get("eventbridge_source", "quaicu.governance")),
                    detail_type=str(ev.get("eventbridge_detail_type", "GovernedAction")),
                )
            )
        webhook = ev.get("webhook_url")
        if webhook:
            import os

            from quaicu.adapters.events.sinks import WebhookEventSink

            headers = {
                str(k): os.path.expandvars(str(v))
                for k, v in (ev.get("webhook_headers", {}) or {}).items()
            }
            events.subscribe(WebhookEventSink(os.path.expandvars(str(webhook)), headers=headers))

    @staticmethod
    def _build_policy(
        adapter_cfg: dict[str, Any], cfg: dict[str, Any]
    ) -> tuple[PolicyEngine, PolicyStore, PolicyRepository | None]:
        """Assemble the K·01 CEL policy engine over a (optionally durable) PolicyStore.

        ``[adapters].policy_store`` selects the durable backend (``"postgres_policy"`` /
        ``"memory_policy"``); omit it for an in-process store with no persistence. The store is
        hydrated from the repository at ``kernel.startup()``, not here (hydration is async).
        """
        repository: PolicyRepository | None = None
        if "policy_store" in adapter_cfg:
            repository = _load_adapter(
                adapter_cfg["policy_store"], **cfg.get("policy_store", {})
            )
        store = PolicyStore(repository=repository)
        return PolicyEngine(store), store, repository

    @staticmethod
    def _build_gateway(
        tenant: TenantId, adapter_cfg: dict[str, Any], cfg: dict[str, Any]
    ) -> AIGateway:
        """Assemble the AI Gateway from the inference adapter + ``[gateway]`` config."""
        inference = _load_adapter(adapter_cfg["inference"], **cfg.get("inference", {}))
        gw_cfg = cfg.get("gateway", {})

        allowlist = InMemoryModelAllowlist()
        for model_id in gw_cfg.get("permitted_models", []):
            allowlist.permit(tenant, str(model_id))

        budget = InMemoryBudgetTracker()
        if gw_cfg.get("max_tokens"):
            budget.set_budget(tenant, max_tokens=int(gw_cfg["max_tokens"]))

        masking_configs = {
            str(tenant): MaskingConfig(
                sensitive_fields=frozenset(gw_cfg.get("sensitive_fields", [])),
                mask_patterns=bool(gw_cfg.get("mask_patterns", True)),
            )
        }
        return AIGateway(
            inference=inference,
            allowlist=allowlist,
            budget=budget,
            masking_configs=masking_configs,
        )

    @classmethod
    def from_parts(
        cls,
        *,
        tenant: TenantId | str,
        policy: PolicyEvaluator,
        hitl: HITLPort,
        ledger: Ledger,
        events: EventBus,
        identity: IdentityPort | None = None,
        consent: ConsentPort | None = None,
        repository: ActionRepository | None = None,
        gateway: AIGateway | None = None,
        default_profile: GovernanceProfile | None = None,
        action_profiles: dict[str, GovernanceProfile] | None = None,
        policy_store: PolicyStore | None = None,
        policy_repository: PolicyRepository | None = None,
        ledger_repository: LedgerRepository | None = None,
        policy_admin_roles: tuple[str, ...] | None = None,
        witness: "AnchorPort | None" = None,
        max_poll_attempts: int = 1,
    ) -> "Kernel":
        """Build a Kernel directly from collaborator instances (for tests and SDK demos)."""
        profile = default_profile or GovernanceProfile.all()
        engine = LifecycleEngine(
            repository=repository or _InMemoryActionRepository(),
            policy=policy,
            hitl=hitl,
            ledger=ledger,
            events=events,
            identity=identity,
            consent=consent,
            default_profile=profile,
            max_poll_attempts=max_poll_attempts,
        )
        return cls(
            engine=engine,
            tenant=TenantId(str(tenant)),
            gateway=gateway,
            default_profile=profile,
            action_profiles=action_profiles or {},
            policy_store=policy_store,
            policy_repository=policy_repository,
            ledger_repository=ledger_repository,
            witness=witness,
            policy_admin_roles=(
                _normalize_roles(policy_admin_roles)
                if policy_admin_roles is not None
                else ("role:policy_admin",)
            ),
        )

    @classmethod
    def local(
        cls,
        *,
        tenant: TenantId | str = "default",
        policies: "str | Path | Iterable[Mapping[str, Any]] | None" = None,
        allow_all: bool = False,
        profile: GovernanceProfile | None = None,
    ) -> "Kernel":
        """A complete kernel that runs inside your process, with no external services.

        It wires the real CEL policy engine, an in-process approvals queue, a signed in-memory
        Merkle ledger and an in-memory event bus. Nothing leaves the process and nothing is
        persisted: state is lost when the process exits (use ``Kernel.from_config`` with the
        Postgres adapters for durability).

        Args:
            tenant: The tenant id stamped on every action.
            policies: The policies to enforce, as ``[[policy.seed]]`` entries — either the path of
                a TOML file containing them, or a list of dicts. Each entry has ``id``,
                ``condition`` (CEL) and ``decision`` (``allow`` | ``deny`` | ``require_approval``),
                and optionally ``governs`` (action type, default ``"*"``), ``approvers``,
                ``version`` and ``regulatory_refs``. See ``docs/CEL_POLICY_GUIDE.md``.
            allow_all: Allow every action without evaluating any policy. For trying the SDK out
                only; cannot be combined with ``policies``.
            profile: The default governance profile. Defaults to ``standard`` (identity, policy,
                approvals, ledger and events; no consent layer, since no consent store is wired).

        With neither ``policies`` nor ``allow_all`` the kernel has no policies and therefore denies
        every action — the same fail-closed behaviour as an empty policy store anywhere else.

        Example::

            kernel = Kernel.local(policies=[
                {"id": "small-wires", "governs": "payments.wire",
                 "condition": "payload_amount < 10000", "decision": "allow"},
            ])

            @kernel.guard(policy="payments.wire")
            async def send_wire(*, amount: int) -> dict: ...

            async with kernel.actor_context("alice", roles=("analyst",)):
                await send_wire(amount=500)
        """
        import tomllib

        from quaicu.adapters.events.memory import InMemoryEventBusAdapter
        from quaicu.adapters.ledger.memory_signed import MemorySignedLedgerAdapter
        from quaicu.core.hitl.engine import InProcessHITLPort

        if allow_all and policies is not None:
            raise SdkUsageError("Kernel.local: pass either `policies` or `allow_all=True`, not both.")

        store: PolicyStore | None = None
        if allow_all:
            from quaicu.adapters.policy.always_allow import AlwaysAllowPolicyAdapter

            policy: PolicyEvaluator = AlwaysAllowPolicyAdapter()
        else:
            if policies is None:
                seeds: list[Mapping[str, Any]] = []
            elif isinstance(policies, (str, Path)):
                with open(policies, "rb") as f:
                    seeds = list(tomllib.load(f).get("policy", {}).get("seed", []))
            else:
                seeds = list(policies)
            store = PolicyStore()
            cls._seed_policies(store, {"policy": {"seed": seeds}})
            policy = PolicyEngine(store)

        return cls.from_parts(
            tenant=tenant,
            policy=policy,
            hitl=InProcessHITLPort(),
            ledger=MemorySignedLedgerAdapter(),
            events=InMemoryEventBusAdapter(),
            policy_store=store,
            default_profile=profile or GovernanceProfile.standard(),
        )

    # ── Agent binding ──────────────────────────────────────────────────────────

    def for_agent(
        self,
        actor: Actor | str,
        *,
        roles: tuple[str, ...] = (),
        profile: GovernanceProfile | None = None,
    ) -> "BoundAgent":
        """Return a handle whose tool/generate calls are stamped with this agent's identity.

        ``actor`` may be an ``Actor`` or a bare id string (e.g. ``"agent:researcher"``), in which
        case an ``Actor`` is built under this kernel's tenant. In a multi-agent system, give each
        agent its own handle so the ledger attributes every action to the right agent.
        """
        if isinstance(actor, str):
            actor = Actor(id=ActorId(actor), tenant=self.tenant, roles=tuple(roles))
        return BoundAgent(self, actor, profile)

    # ── Governed inference ──────────────────────────────────────────────────────

    async def generate(
        self,
        *,
        prompt_text: str,
        model_ref: ModelRef,
        actor: Actor,
        payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        profile: GovernanceProfile | None = None,
        context: Any | None = None,
        tenant: TenantId | None = None,
    ) -> ModelResponse:
        """Make a governed model call.

        The call becomes an ``inference.generate`` action: the active profile decides which layers
        run (policy/HITL/seal/emit + gateway allowlist/mask/log/budget). The AI Gateway is the
        execute step. Returns the ``ModelResponse`` on success; raises ``LifecycleDeniedError`` /
        ``LifecycleHaltedError`` otherwise.
        """
        if self.gateway is None:
            raise SdkUsageError(
                "No inference adapter configured — kernel.generate is unavailable. "
                "Set [adapters].inference and [gateway] in your config."
            )

        action_type = "inference.generate"
        tenant = tenant or self.tenant
        resolved = self.resolve_profile(action_type, profile)
        captured: dict[str, ModelResponse] = {}

        action = Action(
            id=ActionId(str(uuid.uuid4())),
            type=action_type,
            payload={
                "model_id": model_ref.id,
                "model_version": model_ref.version,
                **(payload or {}),
            },
            actor=actor,
            tenant=tenant,
            idempotency_key=IdempotencyKey(idempotency_key or str(uuid.uuid4())),
            proposed_at=datetime.now(tz=timezone.utc),
        )

        async def execute_fn() -> dict[str, Any]:
            resp = await self.gateway.generate(
                prompt_text=prompt_text,
                model_ref=model_ref,
                tenant=tenant,
                action_id=action.id,
                payload=payload,
                profile=resolved,
            )
            captured["response"] = resp
            return dict(resp.recorded_output)

        final = await self.engine.run(
            action, execute_fn, context=context, profile=resolved, defer_gate=True
        )
        self._raise_on_terminal_failure(final, action_type)
        # Surface the action id to the caller (the sealed leaf already covers action.id).
        resp = captured["response"]
        return dataclasses.replace(
            resp, recorded_output={**dict(resp.recorded_output), "action_id": str(final.id)}
        )

    # ── Decision-only (PDP) ─────────────────────────────────────────────────────

    async def check(
        self,
        *,
        action_type: str,
        actor: Actor,
        payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        profile: GovernanceProfile | None = None,
        context: Any | None = None,
        record: bool | None = None,
        tenant: TenantId | None = None,
    ) -> AuthorizationResult:
        """Ask the kernel: "is this action allowed?" without performing it.

        Returns an ``AuthorizationResult`` on all outcomes — never raises on DENY. The caller (the
        enforcement point, or PEP) decides what to do with the verdict.

        When ``record`` is None (the default), the monitoring seal follows the active profile's
        ``seal_to_ledger`` flag: the default ``all()`` profile seals every check into the
        tamper-evident ledger. Pass ``record=False`` to suppress sealing on the hot path.
        """
        resolved = self.resolve_profile(action_type, profile)
        action = self._build_action(action_type, payload or {}, actor, tenant)
        if idempotency_key is not None:
            action = dataclasses.replace(action, idempotency_key=IdempotencyKey(idempotency_key))
        return await self.engine.decide(action, context=context, profile=resolved, record=record)

    # ── Zero-friction integration ────────────────────────────────────────────────

    def actor_context(self, actor: Actor | str, *, roles: tuple[str, ...] = ()):
        """Context manager that binds ``actor`` for all ``guard``/``wrap`` calls inside the block.

        Works as both a sync (``with``) and async (``async with``) context manager so the same
        one-liner covers request handlers, background tasks, and sync code alike.

        Usage::

            async with kernel.actor_context(current_user_actor):
                result = await existing_function(arg1, arg2)  # unchanged call-site

            # String shorthand:
            async with kernel.actor_context("agent:planner"):
                ...

        The actor is task-local (ContextVar): concurrent async tasks each have their own actor and
        cannot see each other's.
        """
        if isinstance(actor, str):
            actor = Actor(id=ActorId(actor), tenant=self.tenant, roles=tuple(roles))
        # Return the async context manager; the sync one is also available via actor_scope.
        return async_actor_scope(actor)

    def set_actor(self, actor: Actor | str, *, roles: tuple[str, ...] = ()) -> None:
        """Imperatively set the governed actor for this async task / thread.

        Prefer ``actor_context`` (auto-cleanup). Use this only when a context manager scope is
        impractical (e.g. long-lived coroutine sessions).
        """
        if isinstance(actor, str):
            actor = Actor(id=ActorId(actor), tenant=self.tenant, roles=tuple(roles))
        set_actor(actor)

    def get_actor(self) -> Actor | None:
        """Return the actor currently bound in this async task / thread, or None."""
        return get_current_actor()

    def guard(
        self,
        *,
        policy: str,
        action_type: str | None = None,
        profile: GovernanceProfile | None = None,
    ) -> Callable:
        """Decorator that governs any existing function **without changing its signature**.

        The actor is resolved from the ContextVar set by ``kernel.actor_context()``.  The
        decorated function's signature, call-sites, and return type are **completely unchanged**.
        Zero codebase modification required.

        Usage::

            # BEFORE — existing function, untouched:
            async def approve_loan(loan_id: str, amount: float) -> dict:
                return await db.approve(loan_id, amount)

            # AFTER — add one decorator line:
            @kernel.guard(policy="loans.approve")
            async def approve_loan(loan_id: str, amount: float) -> dict:
                return await db.approve(loan_id, amount)

            # Caller — add actor_context once at the request boundary:
            async with kernel.actor_context(user_actor):
                result = await approve_loan(loan_id="L-1", amount=5000)  # unchanged

        On DENY the call raises ``LifecycleDeniedError``; on HALT it raises ``LifecycleHaltedError``.
        """
        effective_type = action_type or policy

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Pop actor= if the caller passed it as an escape-hatch override; otherwise use ctx.
                actor: Actor | None = kwargs.pop("actor", None)
                if actor is None:
                    actor = get_current_actor()
                if actor is None:
                    raise SdkUsageError(
                        f"@kernel.guard on {fn.__name__!r}: no actor in scope. "
                        "Call this function inside `async with kernel.actor_context(actor): ...` "
                        "or pass actor=<Actor> as a keyword argument."
                    )
                payload = dict(kwargs)
                action = self._build_action(effective_type, payload, actor)
                captured: dict[str, Any] = {}

                async def execute_fn() -> dict[str, Any]:
                    result = fn(*args, **kwargs)
                    if inspect.isawaitable(result):
                        result = await result
                    captured["result"] = result
                    return {"result": result}

                resolved = self.resolve_profile(effective_type, profile)
                final = await self.engine.run(
                    action, execute_fn, profile=resolved, defer_gate=True
                )
                self._raise_on_terminal_failure(final, effective_type)
                return captured.get("result")

            wrapper._governed_policy = policy  # type: ignore[attr-defined]
            wrapper._governed_action_type = effective_type  # type: ignore[attr-defined]
            wrapper._zero_friction = True  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def proxy(
        self,
        target: Any,
        *,
        policies: dict[str, str],
        actor: Actor | None = None,
    ) -> Any:
        """Wrap any existing object so that specified method calls are governed before execution.

        ``policies`` maps dotted method paths to policy names. Every listed method goes through
        ``kernel.check()`` before being called on the underlying object; unlisted methods pass
        through unchanged — the proxy is fully transparent to the rest of the codebase.

        Usage::

            client = kernel.proxy(
                openai.AsyncOpenAI(api_key="..."),
                policies={
                    "chat.completions.create": "ai.chat",
                    "embeddings.create":        "ai.embed",
                },
            )

            # Existing code completely unchanged:
            async with kernel.actor_context(user):
                response = await client.chat.completions.create(model="gpt-4", messages=[...])
        """
        from quaicu.delivery.sdk.proxy import GovernedProxy

        return GovernedProxy(target, policies=policies, kernel=self, actor=actor)

    async def govern_action(
        self,
        *,
        action_type: str,
        actor: Actor,
        payload: dict[str, Any],
        execute: Callable[[], Any],
        profile: GovernanceProfile | None = None,
        tenant: TenantId | None = None,
    ) -> Any:
        """Govern an action with an **explicit payload dict** + an ``execute`` closure (execute → seal
        → emit), returning the closure's result.

        Unlike ``guard``/``wrap`` (which build the payload from the wrapped function's kwargs), the
        payload is passed directly. Use this when the governed inputs aren't Python kwargs — e.g. an
        MCP tool call, whose ``arguments`` become top-level payload fields so a CEL policy can
        reference ``payload_<field>`` (and a tool argument named ``actor`` is just ``payload_actor``,
        never consumed as the governance actor).

        Raises ``LifecycleDeniedError`` / ``LifecycleHaltedError`` / ``LifecyclePendingApprovalError``
        on the terminal outcome (same fail-closed contract as ``wrap``).
        """
        resolved = self.resolve_profile(action_type, profile)
        action = self._build_action(action_type, dict(payload), actor, tenant)
        captured: dict[str, Any] = {}

        async def execute_fn() -> dict[str, Any]:
            result = execute()
            if inspect.isawaitable(result):
                result = await result
            captured["result"] = result
            return {"result": result}

        final = await self.engine.run(action, execute_fn, profile=resolved, defer_gate=True)
        self._raise_on_terminal_failure(final, action_type)
        return captured.get("result")

    def wrap(
        self,
        fn: Callable,
        *,
        policy: str,
        action_type: str | None = None,
        actor: Actor | None = None,
        profile: GovernanceProfile | None = None,
    ) -> Callable:
        """Govern any existing callable **without modifying it** — programmatic (non-decorator) form.

        Identical to ``guard`` but applied at call-time rather than definition-time. Use this to
        govern functions you don't own (third-party libraries, imported modules):

        Usage::

            # One line to govern an external function:
            governed_transfer = kernel.wrap(payments_lib.transfer, policy="payments.transfer")

            # Caller unchanged:
            async with kernel.actor_context(user_actor):
                result = await governed_transfer(amount=100, to="ACC-2")

        An explicit ``actor=`` bound at wrap-time takes priority over the ContextVar.
        """
        bound_actor = actor  # bound at wrap-time (optional override)
        effective_type = action_type or policy

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Priority: call-time actor= kwarg > wrap-time bound actor > context var
            act: Actor | None = kwargs.pop("actor", None) or bound_actor or get_current_actor()
            if act is None:
                raise SdkUsageError(
                    f"kernel.wrap({fn.__name__!r}): no actor in scope. "
                    "Call inside `async with kernel.actor_context(actor): ...` "
                    "or pass actor=<Actor> as a keyword argument."
                )
            payload = dict(kwargs)
            action = self._build_action(effective_type, payload, act)
            captured: dict[str, Any] = {}

            async def execute_fn() -> dict[str, Any]:
                result = fn(*args, **kwargs)
                if inspect.isawaitable(result):
                    result = await result
                captured["result"] = result
                return {"result": result}

            resolved = self.resolve_profile(effective_type, profile)
            final = await self.engine.run(
                action, execute_fn, profile=resolved, defer_gate=True
            )
            self._raise_on_terminal_failure(final, effective_type)
            return captured.get("result")

        wrapper._governed_policy = policy  # type: ignore[attr-defined]
        wrapper._governed_action_type = effective_type  # type: ignore[attr-defined]
        wrapper._zero_friction = True  # type: ignore[attr-defined]
        return wrapper

    # ── Decorator factories ─────────────────────────────────────────────────────

    def governed(
        self,
        *,
        policy: str,
        action_type: str | None = None,
        profile: GovernanceProfile | None = None,
    ) -> Callable:
        """Decorator factory. Wraps an async function as a governed action.

        The decorated function must accept ``actor: Actor`` as a keyword argument. On COMPLETED the
        final ``Action`` is returned; on DENIED/HALTED it raises. (For tools, prefer
        ``governed_tool``, which returns the function's own result.)
        """
        effective_type = action_type or policy

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                actor: Actor | None = kwargs.get("actor")
                if actor is None:
                    raise SdkUsageError(
                        f"@governed function {fn.__name__!r} must receive actor=<Actor> as a kwarg"
                    )
                payload = {k: v for k, v in kwargs.items() if k != "actor"}
                action = self._build_action(effective_type, payload, actor)

                async def execute_fn() -> Any:
                    return await fn(*args, **kwargs)

                resolved = self.resolve_profile(effective_type, profile)
                final = await self.engine.run(
                    action, execute_fn, profile=resolved, defer_gate=True
                )
                self._raise_on_terminal_failure(final, effective_type)
                return final

            wrapper._governed_policy = policy  # type: ignore[attr-defined]
            wrapper._governed_action_type = effective_type  # type: ignore[attr-defined]
            return wrapper

        return decorator

    def governed_tool(
        self,
        *,
        policy: str,
        name: str | None = None,
        actor: Actor | None = None,
        profile: GovernanceProfile | None = None,
    ) -> Callable:
        """Decorator factory for an agent tool. Governs the call and returns the tool's own result.

        Unlike ``governed``, this returns whatever the wrapped tool returns (not the Action) — which
        is what an agent framework expects. Works on sync or async tools. The actor may be bound (via
        ``for_agent``) or passed as ``actor=`` at call time. On DENIED/HALTED it raises.
        """
        effective_type = name or policy

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                act: Actor | None = kwargs.pop("actor", None) or actor
                if act is None:
                    raise SdkUsageError(
                        f"governed tool {fn.__name__!r} needs an actor — bind one with "
                        "kernel.for_agent(...) or pass actor=<Actor> at call time"
                    )
                payload = {k: v for k, v in kwargs.items()}
                action = self._build_action(effective_type, payload, act)
                captured: dict[str, Any] = {}

                async def execute_fn() -> dict[str, Any]:
                    result = fn(*args, **kwargs)
                    if inspect.isawaitable(result):
                        result = await result
                    captured["result"] = result
                    # Seal a dict (recorded_result is a Mapping); the leaf hash covers the value.
                    return {"result": result}

                resolved = self.resolve_profile(effective_type, profile)
                final = await self.engine.run(
                    action, execute_fn, profile=resolved, defer_gate=True
                )
                self._raise_on_terminal_failure(final, effective_type)
                return captured.get("result")

            wrapper._governed_policy = policy  # type: ignore[attr-defined]
            wrapper._governed_action_type = effective_type  # type: ignore[attr-defined]
            return wrapper

        return decorator

    # ── Internal helpers ─────────────────────────────────────────────────────────

    def _build_action(
        self,
        action_type: str,
        payload: dict[str, Any],
        actor: Actor,
        tenant: TenantId | None = None,
    ) -> Action:
        return Action(
            id=ActionId(str(uuid.uuid4())),
            type=action_type,
            payload=payload,
            actor=actor,
            tenant=tenant or self.tenant,
            idempotency_key=IdempotencyKey(str(uuid.uuid4())),
            proposed_at=datetime.now(tz=timezone.utc),
        )

    def _raise_on_terminal_failure(self, final: Action, action_type: str) -> None:
        if final.state is ActionState.DENIED:
            raise LifecycleDeniedError(
                f"Action {final.id} denied by governance",
                detail={"action_id": str(final.id), "type": action_type},
            )
        if final.state is ActionState.HALTED:
            raise LifecycleHaltedError(
                f"Action {final.id} halted by governance",
                detail={"action_id": str(final.id), "type": action_type},
            )
        if final.state is ActionState.PENDING_APPROVAL:
            # Not a failure: the require_approval action suspended durably (no false timeout→DENY).
            # Surface the handle so the caller can point an approver at /v1/approvals or decide_approval.
            raise LifecyclePendingApprovalError(
                f"Action {final.id} is pending human approval",
                detail={
                    "action_id": str(final.id),
                    "type": action_type,
                    "handle_id": self._pending_handle_for(final.id),
                },
            )

    def _pending_handle_for(self, action_id: Any) -> str | None:
        """The in-process HITL handle awaiting a decision for ``action_id``, or None (external queue)."""
        hitl = self._in_process_hitl()
        if hitl is None:
            return None
        return next(
            (r.handle_id for r in hitl.list_pending() if str(r.action_id) == str(action_id)),
            None,
        )


# ── Bound agent handle ──────────────────────────────────────────────────────────


class BoundAgent:
    """A kernel handle bound to one agent's ``Actor``.

    Every tool or model call made through it is attributed to that agent in the ledger, enabling
    per-agent audit trails in a multi-agent system.
    """

    def __init__(
        self, kernel: Kernel, actor: Actor, profile: GovernanceProfile | None = None
    ) -> None:
        self._kernel = kernel
        self._actor = actor
        self._profile = profile

    @property
    def actor(self) -> Actor:
        return self._actor

    def tool(
        self,
        *,
        policy: str,
        name: str | None = None,
        profile: GovernanceProfile | None = None,
    ) -> Callable:
        """Decorator: govern this agent's tool, attributed to this agent."""
        return self._kernel.governed_tool(
            policy=policy, name=name, actor=self._actor, profile=profile or self._profile
        )

    async def generate(
        self,
        *,
        prompt_text: str,
        model_ref: ModelRef,
        payload: dict[str, Any] | None = None,
        profile: GovernanceProfile | None = None,
    ) -> ModelResponse:
        """Make a governed model call attributed to this agent."""
        return await self._kernel.generate(
            prompt_text=prompt_text,
            model_ref=model_ref,
            actor=self._actor,
            payload=payload,
            profile=profile or self._profile,
        )

    async def check(
        self,
        *,
        action_type: str,
        payload: dict[str, Any] | None = None,
        profile: GovernanceProfile | None = None,
        record: bool | None = None,
    ) -> "AuthorizationResult":
        """Ask whether this agent is allowed to perform an action, without performing it."""
        return await self._kernel.check(
            action_type=action_type,
            actor=self._actor,
            payload=payload,
            profile=profile or self._profile,
            record=record,
        )
