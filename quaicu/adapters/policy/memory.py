"""InMemoryPolicyRepository — dict-backed durable-store stand-in.

Satisfies the `PolicyRepository` Protocol structurally. The default when the CEL policy engine is
wired without a `policy_store` adapter, and the backend used in tests. State lives in process
memory, so it is "durable" only for the lifetime of the process — production uses
`PostgresPolicyRepository`. Useful because it lets the full write-through + hydrate path
(register → persist → new store → hydrate → lookup) be exercised without a database.
"""

from __future__ import annotations

import threading

from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle


class InMemoryPolicyRepository:
    """Thread-safe in-process policy persistence."""

    def __init__(self) -> None:
        self._envelopes: dict[tuple[str, int], PolicyEnvelope] = {}
        self._impact_reports: dict[tuple[str, int], ImpactReport] = {}
        self._lock = threading.Lock()

    async def load_all(self) -> list[PolicyEnvelope]:
        with self._lock:
            # Strip the (non-serialisable) compiled program — the store recompiles on register.
            import dataclasses

            return [
                dataclasses.replace(env, compiled_condition=None)
                for env in self._envelopes.values()
            ]

    async def load_impact_reports(self) -> list[ImpactReport]:
        with self._lock:
            return list(self._impact_reports.values())

    async def save_envelope(self, envelope: PolicyEnvelope) -> None:
        import dataclasses

        with self._lock:
            self._envelopes[(envelope.id, envelope.version)] = dataclasses.replace(
                envelope, compiled_condition=None
            )

    async def save_impact_report(self, report: ImpactReport) -> None:
        with self._lock:
            self._impact_reports[(report.policy_id, report.policy_version)] = report

    async def set_lifecycle(
        self, policy_id: str, version: int, lifecycle: PolicyLifecycle
    ) -> None:
        import dataclasses

        with self._lock:
            key = (policy_id, version)
            existing = self._envelopes.get(key)
            if existing is not None:
                self._envelopes[key] = dataclasses.replace(existing, lifecycle=lifecycle)

    async def close(self) -> None:
        return None
