#!/usr/bin/env python3
"""QUAICU quickstart — govern a function inside your own process.

No services, no accounts, nothing leaves this process.

    pip install .
    python examples/quickstart.py

Three calls to one governed function show the three things a policy can decide:
allow, deny, and require a human's approval.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from quaicu import (
    Actor,
    ActorId,
    Kernel,
    LifecycleDeniedError,
    LifecyclePendingApprovalError,
)

# A complete kernel in one call: CEL policy engine, approvals queue, signed in-memory ledger.
kernel = Kernel.local(policies=Path(__file__).with_name("policies.toml"))

sent: list[int] = []


# Your existing function, unchanged apart from the decorator. Keyword arguments become the action
# payload the policies see (payload_amount, payload_to).
@kernel.guard(policy="payments.wire")
async def send_wire(*, amount: int, to: str) -> dict:
    sent.append(amount)
    return {"sent": amount, "to": to}


async def main() -> int:
    # Say who is acting, once, at your request boundary.
    async with kernel.actor_context("alice", roles=("analyst",)):
        # 1. Small wire: a policy allows it, so the function runs and the action is sealed.
        print("small wire  → allowed:", await send_wire(amount=500, to="ACME"))

        # 2. Over the hard limit: denied. The function body never runs.
        try:
            await send_wire(amount=5_000_000, to="ACME")
        except LifecycleDeniedError:
            print("huge wire   → denied by policy; nothing was sent")

        # 3. Large wire: a policy requires approval. The call stops here — nothing was sent — and
        #    the action waits in the approvals queue.
        try:
            await send_wire(amount=50_000, to="ACME")
        except LifecyclePendingApprovalError as pending:
            handle = pending.detail["handle_id"]
            print("large wire  → waiting for a manager's approval; nothing was sent yet")

    # Someone else, holding the approver role, approves it. (alice could not: the proposer may not
    # approve their own action.) Approval completes and seals the action; the kernel does not call
    # your function again, so your application performs the approved step once it sees this.
    bob = Actor(id=ActorId("bob"), tenant=kernel.tenant, roles=("manager",))
    record = await kernel.approve(handle, actor=bob)
    print(f"large wire  → {record.decision.value.lower()} by {record.decided_by}; action sealed")

    # Every completed action is in a signed, append-only ledger you can export and verify.
    bundle = kernel.export_ledger_proof(kernel.tenant).to_dict()
    print(f"ledger      → {len(bundle['inclusion_proofs'])} sealed actions, tree head signed by "
          f"key {bundle['signed_tree_head']['key_id']}")

    return 0 if sent == [500] and len(bundle["inclusion_proofs"]) == 2 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
