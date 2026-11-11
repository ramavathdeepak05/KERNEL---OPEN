"""The shipped starter config, end to end over HTTP — what a new user does after `quaicu init`.

Builds the kernel from `quaicu/templates/kernel.toml` exactly as `quaicu serve` does (local token,
CEL policies, in-process approvals, signed in-memory ledger) and walks the documented flow:
decide, propose, wait for approval, approve as someone else, read the status and the audit trail.
"""

from __future__ import annotations

from importlib import resources

import pytest
from httpx import ASGITransport, AsyncClient

from quaicu import Kernel
from quaicu.delivery.api.app import create_app

TOKEN = "local-token-0123456789abcdef"


def _as(actor: str, *roles: str) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {TOKEN}", "X-Actor-Id": actor}
    if roles:
        headers["X-Actor-Roles"] = ",".join(roles)
    return headers


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("QUAICU_TOKEN", TOKEN)
    template = resources.files("quaicu").joinpath("templates/kernel.toml")
    with resources.as_file(template) as path:
        kernel = Kernel.from_config(path)
    return create_app(kernel)


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _wire(amount: int, key: str) -> dict:
    return {"type": "payments.wire", "payload": {"amount": amount}, "idempotency_key": key}


async def test_decision_only_endpoint_reports_each_verdict(app):
    async with _client(app) as client:
        verdicts = {}
        for amount in (500, 50_000, 5_000_000):
            resp = await client.post(
                "/v1/authorize",
                json={"type": "payments.wire", "payload": {"amount": amount}},
                headers=_as("alice", "analyst"),
            )
            assert resp.status_code == 200
            verdicts[amount] = (resp.json()["decision"], resp.json()["allowed"], resp.json()["actor_id"])
    assert verdicts[500] == ("allow", True, "alice")
    assert verdicts[50_000] == ("require_approval", False, "alice")
    assert verdicts[5_000_000] == ("deny", False, "alice")


async def test_small_wire_completes_and_is_in_the_audit_trail(app):
    async with _client(app) as client:
        proposed = await client.post("/v1/actions/propose", json=_wire(500, "ik-1"), headers=_as("alice"))
        assert proposed.status_code == 202 and proposed.json()["state"] == "COMPLETED"
        action_id = proposed.json()["action_id"]
        status = await client.get(f"/v1/actions/{action_id}", headers=_as("alice"))
        trail = await client.get("/v1/ledger/local/trail", headers=_as("auditor"))
        again = await client.post("/v1/actions/propose", json=_wire(500, "ik-1"), headers=_as("alice"))
    assert status.status_code == 200 and status.json()["state"] == "COMPLETED"
    entries = trail.json()["entries"]
    assert [(e["action_id"], e["actor_id"], e["decision"]) for e in entries] == [(action_id, "alice", "allow")]
    assert again.json()["action_id"] == action_id  # same idempotency key → the same action, not a rerun


async def test_large_wire_waits_for_a_different_person_to_approve(app):
    async with _client(app) as client:
        proposed = await client.post(
            "/v1/actions/propose", json=_wire(50_000, "ik-2"), headers=_as("alice", "manager")
        )
        assert proposed.status_code == 202 and proposed.json()["state"] == "PENDING_APPROVAL"
        action_id = proposed.json()["action_id"]

        queue = await client.get("/v1/approvals", headers=_as("bob", "manager"))
        (pending,) = queue.json()["approvals"]
        assert pending["action_id"] == action_id and pending["proposed_by"] == "alice"
        handle = pending["handle_id"]

        own = await client.post(f"/v1/approvals/{handle}/approve", headers=_as("alice", "manager"))
        wrong_role = await client.post(f"/v1/approvals/{handle}/approve", headers=_as("carol", "analyst"))
        waiting = await client.get(f"/v1/actions/{action_id}", headers=_as("alice"))
        approved = await client.post(f"/v1/approvals/{handle}/approve", headers=_as("bob", "manager"))
        done = await client.get(f"/v1/actions/{action_id}", headers=_as("alice"))
        trail = await client.get("/v1/ledger/local/trail", headers=_as("auditor"))

    assert own.status_code == 409  # the proposer cannot approve their own action
    assert wrong_role.status_code == 409  # nor can someone without the approver role
    assert waiting.json()["state"] == "PENDING_APPROVAL"
    assert approved.status_code == 200 and approved.json()["decided_by"] == "bob"
    assert done.json()["state"] == "COMPLETED"
    (entry,) = trail.json()["entries"]
    assert entry["action_id"] == action_id and entry["approver"] == "user:bob"


async def test_denied_and_ungoverned_actions_do_not_run(app):
    async with _client(app) as client:
        over_limit = await client.post("/v1/actions/propose", json=_wire(5_000_000, "ik-3"), headers=_as("alice"))
        no_policy = await client.post(
            "/v1/actions/propose",
            json={"type": "accounts.close", "payload": {}, "idempotency_key": "ik-4"},
            headers=_as("alice"),
        )
        trail = await client.get("/v1/ledger/local/trail", headers=_as("auditor"))
    assert over_limit.status_code == 403
    assert no_policy.status_code == 403  # no policy governs this action type → fail-closed deny
    assert trail.json()["count"] == 0


async def test_another_tenants_trail_is_refused(app):
    async with _client(app) as client:
        resp = await client.get("/v1/ledger/someone-else/trail", headers=_as("auditor"))
    assert resp.status_code == 403


async def test_policy_admin_can_import_a_pack_scoped_to_this_tenant(app):
    async with _client(app) as client:
        refused = await client.post("/v1/policy-packs/dpdp/import", headers=_as("alice", "analyst"))
        imported = await client.post("/v1/policy-packs/dpdp/import", headers=_as("root", "policy_admin"))
        assert refused.status_code == 403 and imported.status_code == 200
        policy_id = imported.json()["imported"][0]
        one = await client.get(f"/v1/policies/{policy_id}/versions/1", headers=_as("root", "policy_admin"))
    assert one.json()["lifecycle"] == "DRAFT"
    assert one.json()["scope"] == {"tenant": "local", "pack": "dpdp"}


async def test_exported_bundle_verifies_against_the_published_signing_key(app):
    from quaicu.core.regmap.export import verify_ledger_proof_bundle

    async with _client(app) as client:
        await client.post("/v1/actions/propose", json=_wire(1, "ik-5"), headers=_as("alice"))
        await client.post("/v1/actions/propose", json=_wire(2, "ik-6"), headers=_as("alice"))
        key = (await client.get("/v1/ledger/signing-key", headers=_as("auditor"))).json()
        bundle = (await client.get("/v1/ledger/local/export", headers=_as("auditor"))).json()
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys={key["key_id"]: key["public_key_pem"]})
    assert ok, errors
    assert len(bundle["inclusion_proofs"]) == 2
