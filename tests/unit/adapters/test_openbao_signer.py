"""Unit tests for OpenBaoTreeSigner and OpenBaoLedgerAdapter.

All HTTP calls are mocked — no real OpenBao instance required.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from quaicu.adapters.ledger.openbao import OpenBaoLedgerAdapter, OpenBaoTreeSigner
from quaicu.core.errors import LedgerSealError
from quaicu.core.ledger.signer import SignedTreeHead, _signing_message

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)
TREE_SIZE = 5
ROOT_HASH = b"\xab" * 32
FAKE_SIG = "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _mock_response(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    if status_code >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
    else:
        resp.raise_for_status.return_value = None
    return resp


def _signer(client: MagicMock) -> OpenBaoTreeSigner:
    signer = OpenBaoTreeSigner(
        addr="http://localhost:8200",
        token="root",
        key_name="quaicu-ledger",
    )
    signer._client = client
    return signer


# ── key_id ────────────────────────────────────────────────────────────────────


def test_key_id_fetched_and_cached():
    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    signer = _signer(client)

    kid = signer.key_id
    assert kid == "quaicu-ledger:v1"
    # Second access must not re-fetch
    _ = signer.key_id
    assert client.get.call_count == 1


def test_key_id_raises_ledger_seal_error_on_404():
    client = MagicMock()
    resp = MagicMock()
    resp.status_code = 404
    resp.raise_for_status.return_value = None
    client.get.return_value = resp
    signer = _signer(client)

    with pytest.raises(LedgerSealError, match="not found"):
        _ = signer.key_id


# ── sign() ────────────────────────────────────────────────────────────────────


def test_sign_returns_signed_tree_head():
    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    client.post.return_value = _mock_response({"data": {"signature": FAKE_SIG}})
    signer = _signer(client)

    sth = signer.sign(TREE_SIZE, ROOT_HASH, NOW)

    assert isinstance(sth, SignedTreeHead)
    assert sth.tree_size == TREE_SIZE
    assert sth.root_hash == ROOT_HASH
    assert sth.signature == FAKE_SIG.encode("utf-8")
    assert sth.key_id == "quaicu-ledger:v1"


def test_sign_sends_correct_payload():
    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    client.post.return_value = _mock_response({"data": {"signature": FAKE_SIG}})
    signer = _signer(client)

    signer.sign(TREE_SIZE, ROOT_HASH, NOW)

    call_kwargs = client.post.call_args
    body = call_kwargs[1]["json"]
    expected_b64 = base64.b64encode(_signing_message(TREE_SIZE, ROOT_HASH)).decode("ascii")
    assert body["input"] == expected_b64
    # Ed25519 signs the raw message: no hash_algorithm (it trips OpenBao's
    # RSA-only prehash validation). See quaicu/adapters/ledger/openbao.py.
    assert "hash_algorithm" not in body


def test_sign_wraps_http_error_as_ledger_seal_error():
    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    client.post.return_value = _mock_response({}, status_code=500)
    signer = _signer(client)

    with pytest.raises(LedgerSealError, match="OpenBao sign failed"):
        signer.sign(TREE_SIZE, ROOT_HASH, NOW)


def test_sign_wraps_connection_error_as_ledger_seal_error():
    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    client.post.side_effect = Exception("connection refused")
    signer = _signer(client)

    with pytest.raises(LedgerSealError, match="connection refused"):
        signer.sign(TREE_SIZE, ROOT_HASH, NOW)


# ── verify() ─────────────────────────────────────────────────────────────────


def _sth(sig: str = FAKE_SIG) -> SignedTreeHead:
    return SignedTreeHead(
        tree_size=TREE_SIZE,
        timestamp=NOW,
        root_hash=ROOT_HASH,
        signature=sig.encode("utf-8"),
        key_id="quaicu-ledger:v1",
    )


def test_verify_returns_true_for_valid_signature():
    client = MagicMock()
    client.post.return_value = _mock_response({"data": {"valid": True}})
    signer = _signer(client)
    signer._cached_key_id = "quaicu-ledger:v1"

    assert signer.verify(_sth()) is True


def test_verify_returns_false_for_invalid_signature():
    client = MagicMock()
    client.post.return_value = _mock_response({"data": {"valid": False}})
    signer = _signer(client)
    signer._cached_key_id = "quaicu-ledger:v1"

    assert signer.verify(_sth()) is False


def test_verify_raises_ledger_seal_error_on_http_error():
    # An HTTP 5xx from OpenBao is an outage, not a verdict — verify() must surface it rather than
    # silently return False (which would mask the outage as a failed audit).
    client = MagicMock()
    client.post.return_value = _mock_response({}, status_code=500)
    signer = _signer(client)
    signer._cached_key_id = "quaicu-ledger:v1"

    with pytest.raises(LedgerSealError, match="OpenBao verify failed"):
        signer.verify(_sth())


def test_verify_raises_ledger_seal_error_on_connection_error():
    client = MagicMock()
    client.post.side_effect = Exception("timeout")
    signer = _signer(client)
    signer._cached_key_id = "quaicu-ledger:v1"

    with pytest.raises(LedgerSealError, match="timeout"):
        signer.verify(_sth())


# ── OpenBaoLedgerAdapter ──────────────────────────────────────────────────────


async def test_openbao_ledger_adapter_seal_returns_entry():
    from quaicu.core.types import (
        Action, ActionId, ActionState, Actor, ActorId,
        Decision, EvaluationResult, IdempotencyKey, TenantId,
    )

    client = MagicMock()
    client.get.return_value = _mock_response({"data": {"latest_version": 1}})
    client.post.return_value = _mock_response({"data": {"signature": FAKE_SIG}})

    adapter = OpenBaoLedgerAdapter(
        addr="http://localhost:8200",
        token="root",
        key_name="quaicu-ledger",
    )
    adapter._signer._client = client

    action = Action(
        id=ActionId("act-001"),
        type="loan.approve",
        payload={"amount": 1000},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("bank-a")),
        tenant=TenantId("bank-a"),
        idempotency_key=IdempotencyKey("ik-1"),
        state=ActionState.EXECUTING,
        proposed_at=NOW,
    )
    evaluation = EvaluationResult(decision=Decision.ALLOW, policy_versions=("pol:v1",))

    entry = await adapter.seal(action=action, evaluation=evaluation, recorded_result={})

    assert entry.action_id == action.id
    assert entry.tenant == action.tenant
    assert entry.leaf_hash  # non-empty
