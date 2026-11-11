"""K·01 Policy Engine — durable persistence port.

`PolicyRepository` is the structural async Protocol a durable policy backend implements (in-memory
for dev/single-process, Postgres for production). The `PolicyStore` uses it as a write-through
collaborator: the store stays the fast in-memory read cache (holding the compiled CEL programs,
which are not serialisable), and the repository persists the policy *rows* so they survive a
restart and can be re-hydrated (recompiling CEL on load).

This is a port (core depends only on this Protocol) — concrete adapters live under `quaicu/adapters/policy/`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle


@runtime_checkable
class PolicyRepository(Protocol):
    """Durable store for policy envelopes and their F-10 impact reports.

    Implementations MUST wrap backend faults in `core.errors.PolicyPersistenceError`. The hot-path
    evaluation never calls this — only hydrate (startup) and the write-through management path do.
    """

    async def load_all(self) -> list[PolicyEnvelope]:
        """Return every persisted envelope (any lifecycle), with `compiled_condition=None`.

        The `PolicyStore` recompiles each CEL condition when it registers the envelope on hydrate.
        """
        ...

    async def load_impact_reports(self) -> list[ImpactReport]:
        """Return every persisted impact report (so the store can re-link activations on hydrate)."""
        ...

    async def save_envelope(self, envelope: PolicyEnvelope) -> None:
        """Upsert one policy envelope keyed by (id, version). Idempotent."""
        ...

    async def save_impact_report(self, report: ImpactReport) -> None:
        """Upsert one impact report keyed by (policy_id, version). Idempotent."""
        ...

    async def set_lifecycle(
        self, policy_id: str, version: int, lifecycle: PolicyLifecycle
    ) -> None:
        """Persist a lifecycle transition (e.g. REVIEW → ACTIVATED, * → DEPRECATED)."""
        ...

    async def close(self) -> None:
        """Release any backend resources (connection pools). No-op for in-memory."""
        ...
