"""The periodic anchor loop cosigns each tenant's tree head with the witness.

Regression: the loop passed the witness the ledger *adapter*, which does not expose `tenants()`,
so every pass raised and was only logged — the log was never anchored between exports.
"""

from __future__ import annotations

import asyncio

from quaicu import Kernel
from quaicu.adapters.events.memory import InMemoryEventBusAdapter
from quaicu.adapters.ledger.memory_signed import MemorySignedLedgerAdapter
from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.adapters.policy.always_allow import AlwaysAllowPolicyAdapter
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.delivery.api.app import create_app


async def test_anchor_loop_cosigns_the_current_tree_head(caplog):
    witness = SoftwareWitness()
    kernel = Kernel.from_parts(
        tenant="local",
        policy=AlwaysAllowPolicyAdapter(),
        hitl=InProcessHITLPort(),
        ledger=MemorySignedLedgerAdapter(),
        events=InMemoryEventBusAdapter(),
        witness=witness,
    )
    app = create_app(kernel, anchor_interval=0.01)

    @kernel.guard(policy="demo.act")
    async def act() -> dict:
        return {"ok": True}

    async with app.router.lifespan_context(app):
        async with kernel.actor_context("alice"):
            await act()
            await act()
        for _ in range(200):  # up to ~2s for a pass to run
            if witness.last_seen(kernel.tenant) is not None:
                break
            await asyncio.sleep(0.01)

    seen = witness.last_seen(kernel.tenant)
    assert seen is not None, "the anchor loop never cosigned the tree head"
    sth = kernel.engine._ledger.get_signed_tree_head(kernel.tenant)
    assert seen == (sth.tree_size, sth.root_hash) == (2, sth.root_hash)
    assert "periodic ledger anchor pass failed" not in caplog.text
