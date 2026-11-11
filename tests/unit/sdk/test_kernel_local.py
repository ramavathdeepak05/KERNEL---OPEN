"""Kernel.local — a complete in-process kernel in one call — and the public `quaicu` import surface."""

from __future__ import annotations

import pytest

import quaicu
from quaicu import (
    Actor,
    ActorId,
    Kernel,
    LifecycleDeniedError,
    LifecyclePendingApprovalError,
    SdkUsageError,
)
from quaicu.core.regmap.export import trusted_keys_from_signer, verify_ledger_proof_bundle

POLICIES = [
    {"id": "wire-small", "governs": "payments.wire", "condition": "payload_amount < 10000", "decision": "allow"},
    {
        "id": "wire-large",
        "governs": "payments.wire",
        "condition": "payload_amount >= 10000",
        "decision": "require_approval",
        "approvers": ["role:manager"],
    },
    {"id": "wire-limit", "governs": "payments.wire", "condition": "payload_amount > 1000000", "decision": "deny"},
]


def _wire(kernel: Kernel):
    calls: list[int] = []

    @kernel.guard(policy="payments.wire")
    async def send_wire(*, amount: int) -> dict:
        calls.append(amount)
        return {"sent": amount}

    return send_wire, calls


def test_public_api_is_importable_from_the_top_level():
    assert quaicu.__version__
    for name in quaicu.__all__:
        assert getattr(quaicu, name) is not None


async def test_allowed_action_runs_and_is_sealed():
    kernel = Kernel.local(tenant="acme", policies=POLICIES)
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice", roles=("analyst",)):
        assert await send_wire(amount=500) == {"sent": 500}
    assert calls == [500]
    entries = kernel.engine._ledger.get_entries(kernel.tenant)
    assert len(entries) == 1 and str(entries[0].actor_id) == "alice"


async def test_denied_action_never_runs():
    kernel = Kernel.local(policies=POLICIES)
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice"):
        with pytest.raises(LifecycleDeniedError):
            await send_wire(amount=5_000_000)
    assert calls == []


async def test_approval_suspends_then_a_different_person_completes_it():
    kernel = Kernel.local(policies=POLICIES)
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice", roles=("manager",)):
        with pytest.raises(LifecyclePendingApprovalError) as pending:
            await send_wire(amount=50_000)
    assert calls == []  # nothing ran while waiting for a human
    handle = pending.value.detail["handle_id"]

    # The proposer cannot approve their own action, even holding the approver role.
    with pytest.raises(Exception, match="separation of duties"):
        await kernel.approve(handle, actor=Actor(id=ActorId("alice"), tenant=kernel.tenant, roles=("manager",)))

    await kernel.approve(handle, actor=Actor(id=ActorId("bob"), tenant=kernel.tenant, roles=("manager",)))
    entries = kernel.engine._ledger.get_entries(kernel.tenant)
    assert len(entries) == 1 and str(entries[0].approver) == "user:bob"


async def test_no_policies_means_everything_is_denied():
    kernel = Kernel.local()
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice"):
        with pytest.raises(LifecycleDeniedError):
            await send_wire(amount=1)
    assert calls == []


async def test_action_type_without_a_policy_is_denied():
    kernel = Kernel.local(policies=POLICIES)

    @kernel.guard(policy="accounts.close")
    async def close_account() -> dict:
        return {"closed": True}

    async with kernel.actor_context("alice"):
        with pytest.raises(LifecycleDeniedError):
            await close_account()


async def test_allow_all_is_an_explicit_opt_in():
    kernel = Kernel.local(allow_all=True)
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice"):
        await send_wire(amount=5_000_000)
    assert calls == [5_000_000]
    with pytest.raises(SdkUsageError):
        Kernel.local(policies=POLICIES, allow_all=True)


async def test_policies_load_from_a_toml_file(tmp_path):
    path = tmp_path / "policies.toml"
    path.write_text(
        '[[policy.seed]]\nid = "wire-small"\ngoverns = "payments.wire"\n'
        'condition = "payload_amount < 10000"\ndecision = "allow"\n',
        encoding="utf-8",
    )
    kernel = Kernel.local(policies=path)
    send_wire, calls = _wire(kernel)
    async with kernel.actor_context("alice"):
        await send_wire(amount=10)
        with pytest.raises(LifecycleDeniedError):  # no policy matches a larger amount
            await send_wire(amount=20_000)
    assert calls == [10]


async def test_local_ledger_exports_a_bundle_that_verifies_against_a_pinned_key():
    kernel = Kernel.local(policies=POLICIES)
    send_wire, _ = _wire(kernel)
    async with kernel.actor_context("alice"):
        await send_wire(amount=1)
        await send_wire(amount=2)
    bundle = kernel.export_ledger_proof(kernel.tenant).to_dict()
    pinned = trusted_keys_from_signer(kernel.engine._ledger._signer)
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=pinned)
    assert ok, errors
    assert len(bundle["inclusion_proofs"]) == 2
