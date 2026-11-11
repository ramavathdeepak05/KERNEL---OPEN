"""OpenBao ledger adapter conformance tests.

Requires a live OpenBao instance with the Transit engine enabled and an
ed25519 key named ``quaicu-ledger`` (or whatever ``OPENBAO_KEY`` is set to).

Setup (dev / Docker):
    docker run --rm -e VAULT_DEV_ROOT_TOKEN_ID=root -p 8200:8200 openbao/openbao server -dev
    export OPENBAO_ADDR=http://localhost:8200
    export OPENBAO_TOKEN=root
    bao secrets enable transit
    bao write transit/keys/quaicu-ledger type=ed25519

Run:
    OPENBAO_ADDR=http://localhost:8200 OPENBAO_TOKEN=root \\
        pytest tests/conformance/ledger/ -m integration -v
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from quaicu.adapters.ledger.openbao import OpenBaoLedgerAdapter, OpenBaoTreeSigner
from quaicu.core.types import (
    Action, ActionId, ActionState, Actor, ActorId,
    Decision, EvaluationResult, IdempotencyKey, TenantId,
)

OPENBAO_ADDR = os.environ.get("OPENBAO_ADDR", "")
OPENBAO_TOKEN = os.environ.get("OPENBAO_TOKEN", "")
OPENBAO_KEY = os.environ.get("OPENBAO_KEY", "quaicu-ledger")

skip_no_openbao = pytest.mark.skipif(
    not (OPENBAO_ADDR and OPENBAO_TOKEN),
    reason="OPENBAO_ADDR / OPENBAO_TOKEN not set — skipping integration tests",
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _signer() -> OpenBaoTreeSigner:
    return OpenBaoTreeSigner(addr=OPENBAO_ADDR, token=OPENBAO_TOKEN, key_name=OPENBAO_KEY)


def _action(ikey: str = "ik-openbao-1") -> Action:
    return Action(
        id=ActionId(f"act-{ikey}"),
        type="loan.approve",
        payload={"amount": 5000},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("bank-a")),
        tenant=TenantId("bank-a"),
        idempotency_key=IdempotencyKey(ikey),
        state=ActionState.EXECUTING,
        proposed_at=NOW,
    )


@pytest.mark.integration
@skip_no_openbao
def test_sign_and_verify_round_trip():
    """sign() then verify() on the same signer must return True."""
    signer = _signer()
    root_hash = b"\xde\xad\xbe\xef" * 8
    sth = signer.sign(tree_size=1, root_hash=root_hash, timestamp=NOW)
    assert signer.verify(sth) is True
    signer.close()


@pytest.mark.integration
@skip_no_openbao
def test_restart_durability():
    """Two independent signer instances sharing the same key must cross-verify.

    This simulates a process restart: signer_a signs, signer_b (new process)
    verifies — both use the same OpenBao key so verification must succeed.
    """
    root_hash = b"\xca\xfe\xba\xbe" * 8
    signer_a = _signer()
    sth = signer_a.sign(tree_size=2, root_hash=root_hash, timestamp=NOW)
    signer_a.close()

    signer_b = _signer()
    assert signer_b.verify(sth) is True
    signer_b.close()


@pytest.mark.integration
@skip_no_openbao
def test_tampered_sth_fails_verification():
    signer = _signer()
    root_hash = b"\x11" * 32
    sth = signer.sign(tree_size=3, root_hash=root_hash, timestamp=NOW)

    from quaicu.core.ledger.signer import SignedTreeHead
    tampered = SignedTreeHead(
        tree_size=sth.tree_size,
        timestamp=sth.timestamp,
        root_hash=b"\x00" * 32,  # different root
        signature=sth.signature,
        key_id=sth.key_id,
    )
    assert signer.verify(tampered) is False
    signer.close()


@pytest.mark.integration
@skip_no_openbao
async def test_full_seal_through_adapter():
    """End-to-end: OpenBaoLedgerAdapter.seal() returns a LedgerEntry."""
    adapter = OpenBaoLedgerAdapter(
        addr=OPENBAO_ADDR, token=OPENBAO_TOKEN, key_name=OPENBAO_KEY
    )
    action = _action("ik-openbao-e2e")
    evaluation = EvaluationResult(decision=Decision.ALLOW, policy_versions=("pol:v1",))

    entry = await adapter.seal(action=action, evaluation=evaluation, recorded_result={})

    assert entry.action_id == action.id
    assert entry.tenant == TenantId("bank-a")
    assert entry.leaf_hash
    adapter.close()
