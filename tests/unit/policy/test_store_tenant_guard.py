"""PolicyStore: an existing (id, version) may only be replaced under the same tenant scope.

The store is keyed by (id, version) with no tenant. Whatever sits in front of it, one tenant scope
must not be able to overwrite another's draft — or an operator's shared ``"*"`` policy.
"""

from __future__ import annotations

import pytest

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.errors import PolicyTransitionError
from quaicu.core.policy.model import PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Decision


def _envelope(tenant: str, *, condition: str = "true") -> PolicyEnvelope:
    return PolicyEnvelope(
        id="p",
        version=1,
        governs="payments.wire",
        scope={"tenant": tenant},
        condition=condition,
        decision=Decision.ALLOW,
        approvers=(),
        regulatory_refs=(),
        lifecycle=PolicyLifecycle.DRAFT,
    )


def test_same_scope_can_iterate_on_a_draft_but_another_scope_cannot_replace_it():
    store = PolicyStore()
    store.register(_envelope("tenant-a", condition="1 == 1"))
    store.register(_envelope("tenant-a", condition="2 == 2"))  # normal draft iteration
    with pytest.raises(PolicyTransitionError):
        store.register(_envelope("tenant-b"))
    with pytest.raises(PolicyTransitionError):
        store.register(_envelope("*"))
    kept = store.get("p", 1)
    assert kept.scope["tenant"] == "tenant-a" and kept.condition == "2 == 2"


async def test_the_guard_runs_before_the_durable_write():
    repo = InMemoryPolicyRepository()
    store = PolicyStore(repository=repo)
    await store.register_persisted(_envelope("tenant-a", condition="1 == 1"))
    with pytest.raises(PolicyTransitionError):
        await store.register_persisted(_envelope("tenant-b", condition="false"))
    persisted = {(e.id, e.version): e for e in await repo.load_all()}
    assert persisted[("p", 1)].scope["tenant"] == "tenant-a"
    assert persisted[("p", 1)].condition == "1 == 1"
