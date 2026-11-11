"""PostgresPolicyRepository — durable, asyncpg-backed policy persistence.

Implements the `PolicyRepository` Protocol structurally on a single asyncpg connection pool (one
pool per adapter instance, created lazily on first use). Mirrors `quaicu/adapters/storage/postgres.py`.

Tables (see migration 002_create_policy_tables.py):
  quaicu_policies               — one row per (id, version); the policy envelope.
  quaicu_policy_impact_reports  — one row per (policy_id, version); the F-10 impact report.

Fail-closed contract:
  All asyncpg exceptions are caught and re-raised as `PolicyPersistenceError`. Writes use
  INSERT … ON CONFLICT DO UPDATE so re-persisting the same (id, version) is idempotent.

Note: the compiled CEL program is never persisted (it is not serialisable). `load_all` returns
envelopes with `compiled_condition=None`; the PolicyStore recompiles from `condition` on hydrate.
"""

from __future__ import annotations

import asyncio
import json

import asyncpg

from quaicu.core.errors import PolicyPersistenceError
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.types import ApproverRef, Decision

# ── SQL ─────────────────────────────────────────────────────────────────────

_UPSERT_ENVELOPE_SQL = """
INSERT INTO quaicu_policies
    (id, version, governs, scope, condition, decision,
     approvers, regulatory_refs, lifecycle, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
ON CONFLICT (id, version) DO UPDATE SET
    governs         = EXCLUDED.governs,
    scope           = EXCLUDED.scope,
    condition       = EXCLUDED.condition,
    decision        = EXCLUDED.decision,
    approvers       = EXCLUDED.approvers,
    regulatory_refs = EXCLUDED.regulatory_refs,
    lifecycle       = EXCLUDED.lifecycle,
    updated_at      = now()
"""

_SELECT_ALL_ENVELOPES_SQL = """
SELECT id, version, governs, scope, condition, decision,
       approvers, regulatory_refs, lifecycle
FROM   quaicu_policies
"""

_SET_LIFECYCLE_SQL = """
UPDATE quaicu_policies
SET    lifecycle = $3, updated_at = now()
WHERE  id = $1 AND version = $2
"""

_UPSERT_IMPACT_SQL = """
INSERT INTO quaicu_policy_impact_reports
    (policy_id, version, reviewed_by, reviewed_at,
     decision_distribution, flip_count, fairness_delta, acknowledged)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (policy_id, version) DO UPDATE SET
    reviewed_by           = EXCLUDED.reviewed_by,
    reviewed_at           = EXCLUDED.reviewed_at,
    decision_distribution = EXCLUDED.decision_distribution,
    flip_count            = EXCLUDED.flip_count,
    fairness_delta        = EXCLUDED.fairness_delta,
    acknowledged          = EXCLUDED.acknowledged
"""

_SELECT_ALL_IMPACT_SQL = """
SELECT policy_id, version, reviewed_by, reviewed_at,
       decision_distribution, flip_count, fairness_delta, acknowledged
FROM   quaicu_policy_impact_reports
"""


# ── Row mappers ───────────────────────────────────────────────────────────────


def _row_to_envelope(row: asyncpg.Record) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=row["id"],
        version=int(row["version"]),
        governs=row["governs"],
        scope=json.loads(row["scope"]) if row["scope"] else {},
        condition=row["condition"],
        decision=Decision(row["decision"]),
        approvers=tuple(ApproverRef(a) for a in (row["approvers"] or [])),
        regulatory_refs=tuple(row["regulatory_refs"] or []),
        lifecycle=PolicyLifecycle(row["lifecycle"]),
        compiled_condition=None,  # recompiled by the store on register
    )


def _row_to_impact_report(row: asyncpg.Record) -> ImpactReport:
    dist = row["decision_distribution"]
    return ImpactReport(
        policy_id=row["policy_id"],
        policy_version=int(row["version"]),
        reviewed_by=row["reviewed_by"],
        reviewed_at=row["reviewed_at"],
        decision_distribution=json.loads(dist) if isinstance(dist, str) else dict(dist or {}),
        flip_count=int(row["flip_count"]),
        fairness_delta=float(row["fairness_delta"]),
        acknowledged=bool(row["acknowledged"]),
    )


# ── Adapter ───────────────────────────────────────────────────────────────────


class PostgresPolicyRepository:
    """Asyncpg-backed `PolicyRepository`. Pass a libpq/asyncpg DSN; pool is created lazily."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._pool_lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                try:
                    # Bounded pool — the kernel opens several pools against one database (actions,
                    # policies, ledger). asyncpg's default (10 each) exhausts a small instance.
                    self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
                except Exception as exc:
                    raise PolicyPersistenceError(
                        f"Failed to create Postgres pool: {exc}",
                        detail={"dsn_prefix": self._dsn[:30]},
                    ) from exc
        return self._pool  # type: ignore[return-value]

    # ── PolicyRepository ──────────────────────────────────────────────────────

    async def load_all(self) -> list[PolicyEnvelope]:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(_SELECT_ALL_ENVELOPES_SQL)
            return [_row_to_envelope(r) for r in rows]
        except PolicyPersistenceError:
            raise
        except Exception as exc:
            raise PolicyPersistenceError(f"load_all failed: {exc}") from exc

    async def load_impact_reports(self) -> list[ImpactReport]:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                rows = await conn.fetch(_SELECT_ALL_IMPACT_SQL)
            return [_row_to_impact_report(r) for r in rows]
        except PolicyPersistenceError:
            raise
        except Exception as exc:
            raise PolicyPersistenceError(f"load_impact_reports failed: {exc}") from exc

    async def save_envelope(self, envelope: PolicyEnvelope) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    _UPSERT_ENVELOPE_SQL,
                    envelope.id,
                    envelope.version,
                    envelope.governs,
                    json.dumps(dict(envelope.scope)),
                    envelope.condition,
                    envelope.decision.value,
                    [str(a) for a in envelope.approvers],
                    list(envelope.regulatory_refs),
                    envelope.lifecycle.value,
                )
        except PolicyPersistenceError:
            raise
        except Exception as exc:
            raise PolicyPersistenceError(
                f"save_envelope failed for {envelope.id}@v{envelope.version}: {exc}",
                detail={"policy_id": envelope.id, "version": envelope.version},
            ) from exc

    async def save_impact_report(self, report: ImpactReport) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                await conn.execute(
                    _UPSERT_IMPACT_SQL,
                    report.policy_id,
                    report.policy_version,
                    report.reviewed_by,
                    report.reviewed_at,
                    json.dumps(dict(report.decision_distribution)),
                    report.flip_count,
                    report.fairness_delta,
                    report.acknowledged,
                )
        except PolicyPersistenceError:
            raise
        except Exception as exc:
            raise PolicyPersistenceError(
                f"save_impact_report failed for {report.policy_id}@v{report.policy_version}: {exc}",
                detail={"policy_id": report.policy_id, "version": report.policy_version},
            ) from exc

    async def set_lifecycle(
        self, policy_id: str, version: int, lifecycle: PolicyLifecycle
    ) -> None:
        try:
            pool = await self._get_pool()
            async with pool.acquire() as conn:
                result = await conn.execute(
                    _SET_LIFECYCLE_SQL, policy_id, version, lifecycle.value
                )
            count = int(result.split()[-1])
            if count == 0:
                raise PolicyPersistenceError(
                    "set_lifecycle affected 0 rows — policy not found",
                    detail={"policy_id": policy_id, "version": version},
                )
        except PolicyPersistenceError:
            raise
        except Exception as exc:
            raise PolicyPersistenceError(
                f"set_lifecycle failed for {policy_id}@v{version}: {exc}",
                detail={"policy_id": policy_id, "version": version},
            ) from exc

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
