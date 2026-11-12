"""/v1/tools: people view and change the gateway's guardrails live; every change is sealed.
Approvals reach the running gateway, and the agent's retry then runs the approved call once."""

from __future__ import annotations

import tomllib

import pytest

pytest.importorskip("mcp")

from httpx import ASGITransport, AsyncClient  # noqa: E402

from quaicu.core.toolgate import parse_rule  # noqa: E402
from quaicu.delivery.api.app import create_app  # noqa: E402
from tests.unit.toolgate.helpers import build, headers  # noqa: E402

ADMIN = headers("carol", "policy_admin")
REVIEWER = headers("alice", "security")
AUDITOR = headers("auditor")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    kernel, gateway, servers = build(tmp_path, monkeypatch)
    client = AsyncClient(transport=ASGITransport(app=create_app(kernel)), base_url="http://test")
    return client, gateway, servers


async def test_requires_authentication_and_admin_role(setup):
    client, _gw, _s = setup
    async with client:
        assert (await client.get("/v1/tools")).status_code == 401
        assert (await client.get("/v1/tools", headers=headers("bob", "agent"))).status_code == 403
        assert (await client.get("/v1/tools", headers=ADMIN)).status_code == 200


async def test_503_without_a_gateway(tmp_path, monkeypatch):
    kernel, _gw, _s = build(tmp_path, monkeypatch)
    kernel.toolgate = None
    async with AsyncClient(transport=ASGITransport(app=create_app(kernel)), base_url="http://test") as client:
        resp = await client.get("/v1/tools", headers=ADMIN)
    assert resp.status_code == 503 and resp.json()["detail"]["code"] == "TOOL_GATEWAY_NOT_RUNNING"


async def test_rule_changes_apply_to_the_next_call_and_are_sealed(setup):
    client, gateway, servers = setup
    async with client:
        assert (await gateway.handle_call("github__get_issue", {})).isError is False

        resp = await client.put(
            "/v1/tools/rules/github-read",
            json={"tools": ["github.get_*", "github.list_*"], "access": "read", "decision": "deny"},
            headers=ADMIN,
        )
        assert resp.status_code == 200
        assert (await gateway.handle_call("github__get_issue", {})).isError is True

        created = await client.post(
            "/v1/tools/rules",
            json={"id": "github-transfer", "tools": ["github.transfer_repo"], "access": "admin",
                  "decision": "require_approval"},
            headers=ADMIN,
        )
        assert created.status_code == 201 and created.json()["approvers"] == ["role:security"]
        names = [t["name"] for t in await gateway.list_tools()]
        assert "github__transfer_repo" in names and "github__get_issue" not in names

        assert (await client.delete("/v1/tools/rules/github-transfer", headers=ADMIN)).status_code == 204
        assert (await client.get("/v1/tools/rules/github-transfer", headers=ADMIN)).status_code == 404

        trail = await client.get("/v1/ledger/local/trail", headers=AUDITOR)
    configure = [e for e in trail.json()["entries"] if e["action_type"] == "kernel.tools.configure"]
    assert len(configure) == 3
    assert {e["actor_id"] for e in configure} == {"carol"}
    assert servers["github"].calls == [("get_issue", {})]


async def test_invalid_rules_are_refused(setup):
    client, _gw, _s = setup
    async with client:
        bad = await client.post("/v1/tools/rules", json={"id": "x", "tools": ["github.*"], "access": "read",
                                                          "decision": "perhaps"}, headers=ADMIN)
        unknown_server = await client.post("/v1/tools/rules", json={"id": "x", "tools": ["gitlab.*"],
                                                                     "access": "read", "decision": "allow"},
                                           headers=ADMIN)
        duplicate = await client.post("/v1/tools/rules", json={"id": "web-read", "tools": ["web.fetch"],
                                                                "access": "read", "decision": "allow"},
                                      headers=ADMIN)
    assert bad.status_code == 422
    assert unknown_server.status_code == 422
    assert duplicate.status_code == 409


async def test_disabling_a_server_takes_its_tools_away(setup):
    client, gateway, servers = setup
    async with client:
        assert (await client.post("/v1/tools/servers/github/disable", headers=ADMIN)).status_code == 200
        assert [t["name"] for t in await gateway.list_tools()] == ["web__fetch"]
        assert (await gateway.handle_call("github__get_issue", {})).isError is True
        assert (await client.post("/v1/tools/servers/github/enable", headers=ADMIN)).status_code == 200
        assert (await gateway.handle_call("github__get_issue", {})).isError is False
        assert (await client.post("/v1/tools/servers/gitlab/disable", headers=ADMIN)).status_code == 404
    assert servers["github"].calls == [("get_issue", {})]


async def test_approval_over_http_then_the_agents_retry_runs_once(setup):
    client, gateway, servers = setup
    args = {"owner": "acme", "title": "from the web page"}
    async with client:
        await gateway.handle_call("web__fetch", {"url": "https://example.com"})
        held = await gateway.handle_call("github__create_issue", args)
        handle = held.meta["handle_id"]
        assert held.isError is True and handle

        # The agent's own identity cannot approve, even with the right role.
        self_approve = await client.post(f"/v1/approvals/{handle}/approve", headers=headers("agent:assistant", "security"))
        assert self_approve.status_code in (403, 409, 422)

        approved = await client.post(f"/v1/approvals/{handle}/approve", headers=REVIEWER)
        assert approved.status_code == 200
        assert servers["github"].calls == []  # approval alone runs nothing

        done = await gateway.handle_call("github__create_issue", args)
        again = await gateway.handle_call("github__create_issue", args)
    assert done.isError is False
    assert servers["github"].calls == [("create_issue", args)]
    assert again.isError is True and again.meta["quaicu_status"] == "PENDING"  # a new call, a new approval


async def test_session_reset_and_catalogue(setup):
    client, gateway, _s = setup
    async with client:
        await gateway.handle_call("web__fetch", {"url": "x"})
        cat = (await client.get("/v1/tools", headers=ADMIN)).json()
        assert cat["session"] == {"tainted": True, "sources": ["web__fetch"]}
        assert (await client.post("/v1/tools/session/reset", headers=ADMIN)).status_code == 200
        cat = (await client.get("/v1/tools", headers=ADMIN)).json()
    assert cat["session"] == {"tainted": False, "sources": []}
    assert "ghp-secret" not in repr(cat)


async def test_toml_export(setup):
    client, gateway, _s = setup
    async with client:
        resp = await client.get("/v1/tools/rules?format=toml", headers=ADMIN)
    assert resp.status_code == 200
    rules = [parse_rule(r) for r in tomllib.loads(resp.text)["tools"]["rule"]]
    assert rules == gateway.rules.rules()
