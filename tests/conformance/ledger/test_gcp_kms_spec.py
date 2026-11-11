"""GCP Cloud KMS ledger adapter conformance tests (the managed-service replacement for OpenBao).

Requires a live Cloud KMS asymmetric-signing key (EC_SIGN_P256_SHA256) and Application Default
Credentials. Mirrors test_openbao_spec.py so the OpenBao→Cloud KMS signer swap has equivalent live
coverage. Install the gcp extra: ``pip install -e .[gcp]``.

Setup (one-time; a keyring `quaicu-ledger` / key `sth-signer` already exists in the integration project):
    gcloud auth application-default login
    gcloud kms keyrings create quaicu-ledger --location us-central1            # if absent
    gcloud kms keys create sth-signer --location us-central1 --keyring quaicu-ledger \\
        --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256 --protection-level hsm

Run:
    GCP_KMS_PROJECT=ordinal-quarter-499114-s2 \\
        pytest tests/conformance/ledger/test_gcp_kms_spec.py -m integration -v
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from quaicu.adapters.ledger.gcp_kms import GcpKmsLedgerAdapter, GcpKmsTreeSigner
from quaicu.core.types import (
    Action, ActionId, ActionState, Actor, ActorId,
    Decision, EvaluationResult, IdempotencyKey, TenantId,
)

GCP_KMS_PROJECT = os.environ.get("GCP_KMS_PROJECT", "")
GCP_KMS_LOCATION = os.environ.get("GCP_KMS_LOCATION", "us-central1")
GCP_KMS_KEYRING = os.environ.get("GCP_KMS_KEYRING", "quaicu-ledger")
GCP_KMS_KEY = os.environ.get("GCP_KMS_KEY", "sth-signer")
GCP_KMS_VERSION = os.environ.get("GCP_KMS_VERSION", "1")

skip_no_kms = pytest.mark.skipif(
    not GCP_KMS_PROJECT,
    reason="GCP_KMS_PROJECT not set — skipping Cloud KMS integration tests",
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=timezone.utc)


def _signer() -> GcpKmsTreeSigner:
    return GcpKmsTreeSigner(
        project=GCP_KMS_PROJECT,
        location=GCP_KMS_LOCATION,
        key_ring=GCP_KMS_KEYRING,
        key=GCP_KMS_KEY,
        version=GCP_KMS_VERSION,
    )


def _action(ikey: str = "ik-gcpkms-1") -> Action:
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
@skip_no_kms
def test_sign_and_verify_round_trip():
    """sign() then verify() against the live Cloud KMS key must return True."""
    signer = _signer()
    root_hash = b"\xde\xad\xbe\xef" * 8
    sth = signer.sign(tree_size=1, root_hash=root_hash, timestamp=NOW)
    assert signer.verify(sth) is True
    signer.close()


@pytest.mark.integration
@skip_no_kms
def test_restart_durability():
    """Two independent signer instances sharing the same KMS key must cross-verify (simulated restart)."""
    root_hash = b"\xca\xfe\xba\xbe" * 8
    signer_a = _signer()
    sth = signer_a.sign(tree_size=2, root_hash=root_hash, timestamp=NOW)
    signer_a.close()

    signer_b = _signer()
    assert signer_b.verify(sth) is True
    signer_b.close()


@pytest.mark.integration
@skip_no_kms
def test_tampered_sth_fails_verification():
    signer = _signer()
    root_hash = b"\x11" * 32
    sth = signer.sign(tree_size=3, root_hash=root_hash, timestamp=NOW)

    from quaicu.core.ledger.signer import SignedTreeHead
    tampered = SignedTreeHead(
        tree_size=sth.tree_size,
        timestamp=sth.timestamp,
        root_hash=b"\x00" * 32,  # different root → signature no longer matches
        signature=sth.signature,
        key_id=sth.key_id,
    )
    assert signer.verify(tampered) is False
    signer.close()


@pytest.mark.integration
@skip_no_kms
async def test_full_seal_through_adapter():
    """End-to-end: GcpKmsLedgerAdapter.seal() returns a LedgerEntry."""
    adapter = GcpKmsLedgerAdapter(
        project=GCP_KMS_PROJECT,
        location=GCP_KMS_LOCATION,
        key_ring=GCP_KMS_KEYRING,
        key=GCP_KMS_KEY,
        version=GCP_KMS_VERSION,
    )
    action = _action("ik-gcpkms-e2e")
    evaluation = EvaluationResult(decision=Decision.ALLOW, policy_versions=("pol:v1",))

    entry = await adapter.seal(action=action, evaluation=evaluation, recorded_result={})

    assert entry.action_id == action.id
    assert entry.tenant == TenantId("bank-a")
    assert entry.leaf_hash
    await adapter.close()
