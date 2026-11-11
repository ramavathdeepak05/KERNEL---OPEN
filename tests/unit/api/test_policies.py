"""Unit tests for the policy management API (/v1/policies).

Covers control-plane authz, the full register→submit→impact-report→activate→deprecate lifecycle
over HTTP, error mapping (400/403/404/409/503), role normalization, and hydrate-after-restart.
"""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.errors import PolicyPersistenceError
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}
ADMIN_ROLES = ("role:policy_admin",)


def _kernel(
    *,
    repo: InMemoryPolicyRepository | None = None,
    identity_roles: tuple[str, ...] = ADMIN_ROLES,
    with_identity: bool = True,
    with_store: bool = True,
    policy_admin_roles: tuple[str, ...] | None = None,
):
    repo = repo if repo is not None else InMemoryPolicyRepository()
    store = PolicyStore(repository=repo) if with_store else None
    # The management routes use kernel.policy_store directly; the `policy` evaluator collaborator is
    # only exercised by engine.run, which these tests do not call — a FakePolicy suffices.
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(roles=identity_roles) if with_identity else None,
        policy_store=store,
        policy_repository=repo if with_store else None,
        policy_admin_roles=policy_admin_roles,
    )


def _app(**kw):
    return create_app(_kernel(**kw))


def _register_body(pid: str = "p.wire", version: int = 1, **over) -> dict:
    body = {
        "id": pid,
        "version": version,
        "governs": "payments.wire",
        "scope": {"tenant": "*"},
        "condition": "true",
        "decision": "allow",
        "approvers": [],
        "regulatory_refs": [],
    }
    body.update(over)
    return body


def _report_body(acknowledged: bool = True) -> dict:
    return {
        "reviewed_by": "user:reviewer",
        "reviewed_at": "2026-06-05T00:00:00+00:00",
        "decision_distribution": {"allow": 1.0},
        "flip_count": 0,
        "fairness_delta": 0.0,
        "acknowledged": acknowledged,
    }


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── Authorization ───────────────────────────────────────────────────────────────


async def test_register_without_token_returns_401() -> None:
    async with _client(_app()) as c:
        resp = await c.post("/v1/policies", json=_register_body())
    assert resp.status_code == 401


async def test_register_without_identity_returns_503() -> None:
    async with _client(_app(with_identity=False)) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 503


async def test_register_without_store_returns_503() -> None:
    async with _client(_app(with_store=False)) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "POLICY_STORE_NOT_CONFIGURED"


async def test_unresolvable_identity_returns_401() -> None:
    """A token the IdentityPort rejects → 401 (not the global handler's 503)."""
    kernel = _kernel()
    kernel.engine._identity.raise_exc = True  # type: ignore[attr-defined]
    app = create_app(kernel)
    async with _client(app) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "PORT_IDENTITY_ERROR"


async def test_wrong_role_returns_403() -> None:
    async with _client(_app(identity_roles=("role:risk_analyst",))) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "POLICY_ADMIN_REQUIRED"


async def test_bare_config_role_matches_prefixed_actor_role() -> None:
    # config uses a bare name; actor presents the prefixed form
    app = _app(identity_roles=("role:governance_lead",), policy_admin_roles=("governance_lead",))
    async with _client(app) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 201


async def test_prefixed_config_role_matches_bare_actor_role() -> None:
    # actor presents a bare name; config uses the prefixed form
    app = _app(identity_roles=("policy_admin",), policy_admin_roles=("role:policy_admin",))
    async with _client(app) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 201


async def test_get_endpoints_are_role_gated() -> None:
    async with _client(_app(identity_roles=("role:risk_analyst",))) as c:
        resp = await c.get("/v1/policies", headers=AUTH)
    assert resp.status_code == 403


# ── Register ──────────────────────────────────────────────────────────────────


async def test_register_creates_draft() -> None:
    async with _client(_app()) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 201
    data = resp.json()
    assert data["lifecycle"] == "DRAFT"
    assert "compiled_condition" not in data


async def test_register_bad_cel_returns_400() -> None:
    async with _client(_app()) as c:
        resp = await c.post("/v1/policies", json=_register_body(condition="((("), headers=AUTH)
    assert resp.status_code == 400
    assert resp.json()["detail"]["code"] == "POLICY_COMPILE_ERROR"


async def test_register_require_approval_without_approvers_returns_422() -> None:
    async with _client(_app()) as c:
        resp = await c.post(
            "/v1/policies",
            json=_register_body(decision="require_approval", approvers=[]),
            headers=AUTH,
        )
    assert resp.status_code == 422


async def test_register_over_activated_returns_409() -> None:
    repo = InMemoryPolicyRepository()
    app = _app(repo=repo)
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        await c.put(
            "/v1/policies/p.wire/versions/1/impact-report", json=_report_body(), headers=AUTH
        )
        await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)
        # Re-register the now-ACTIVATED version
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "POLICY_TRANSITION_INVALID"


# ── Reads ──────────────────────────────────────────────────────────────────────


async def test_list_empty() -> None:
    async with _client(_app()) as c:
        resp = await c.get("/v1/policies", headers=AUTH)
    assert resp.status_code == 200
    assert resp.json() == {"policies": [], "count": 0}


async def test_list_with_lifecycle_filter() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body("p.a", 1), headers=AUTH)
        await c.post("/v1/policies", json=_register_body("p.b", 1), headers=AUTH)
        await c.post("/v1/policies/p.b/versions/1/submit", headers=AUTH)
        resp = await c.get("/v1/policies", params={"lifecycle": "REVIEW"}, headers=AUTH)
    data = resp.json()
    assert data["count"] == 1 and data["policies"][0]["id"] == "p.b"


async def test_list_bad_lifecycle_returns_422() -> None:
    async with _client(_app()) as c:
        resp = await c.get("/v1/policies", params={"lifecycle": "BOGUS"}, headers=AUTH)
    assert resp.status_code == 422


async def test_list_versions_sorted() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body("p.x", 2), headers=AUTH)
        await c.post("/v1/policies", json=_register_body("p.x", 1), headers=AUTH)
        resp = await c.get("/v1/policies/p.x", headers=AUTH)
    data = resp.json()
    assert [p["version"] for p in data["policies"]] == [1, 2]


async def test_list_versions_unknown_returns_404() -> None:
    async with _client(_app()) as c:
        resp = await c.get("/v1/policies/nope", headers=AUTH)
    assert resp.status_code == 404


async def test_get_version_unknown_returns_404() -> None:
    async with _client(_app()) as c:
        resp = await c.get("/v1/policies/p.wire/versions/9", headers=AUTH)
    assert resp.status_code == 404


# ── Submit ─────────────────────────────────────────────────────────────────────


async def test_submit_transitions_to_review() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        resp = await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
    assert resp.status_code == 200 and resp.json()["lifecycle"] == "REVIEW"


async def test_submit_non_draft_returns_409() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        resp = await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
    assert resp.status_code == 409


async def test_submit_unknown_returns_404() -> None:
    async with _client(_app()) as c:
        resp = await c.post("/v1/policies/nope/versions/1/submit", headers=AUTH)
    assert resp.status_code == 404


# ── Impact report + activate ───────────────────────────────────────────────────


async def test_impact_report_upload_then_activate_with_stored() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        put = await c.put(
            "/v1/policies/p.wire/versions/1/impact-report", json=_report_body(), headers=AUTH
        )
        assert put.status_code == 200 and put.json()["policy_id"] == "p.wire"
        resp = await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)
    assert resp.status_code == 200 and resp.json()["lifecycle"] == "ACTIVATED"


async def test_activate_with_inline_report() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/activate",
            json={"impact_report": _report_body()},
            headers=AUTH,
        )
    assert resp.status_code == 200 and resp.json()["lifecycle"] == "ACTIVATED"


async def test_activate_without_any_report_returns_409() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        resp = await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)
    assert resp.status_code == 409


async def test_activate_unacknowledged_report_returns_409() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/activate",
            json={"impact_report": _report_body(acknowledged=False)},
            headers=AUTH,
        )
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "POLICY_ACTIVATION_BLOCKED"


async def test_activate_unknown_returns_404() -> None:
    async with _client(_app()) as c:
        resp = await c.post(
            "/v1/policies/nope/versions/1/activate",
            json={"impact_report": _report_body()},
            headers=AUTH,
        )
    assert resp.status_code == 404


# ── Deprecate ──────────────────────────────────────────────────────────────────


async def test_deprecate() -> None:
    app = _app()
    async with _client(app) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        resp = await c.post("/v1/policies/p.wire/versions/1/deprecate", headers=AUTH)
    assert resp.status_code == 200 and resp.json()["lifecycle"] == "DEPRECATED"


async def test_deprecate_unknown_returns_404() -> None:
    async with _client(_app()) as c:
        resp = await c.post("/v1/policies/nope/versions/1/deprecate", headers=AUTH)
    assert resp.status_code == 404


# ── Persistence fault → 503 (fail-closed via global handler) ───────────────────


class _FaultyRepo(InMemoryPolicyRepository):
    async def save_envelope(self, envelope) -> None:  # type: ignore[override]
        raise PolicyPersistenceError("injected persistence fault")


async def test_persistence_fault_returns_503() -> None:
    kernel = _kernel()
    kernel.policy_store._repository = _FaultyRepo()  # type: ignore[attr-defined]
    app = create_app(kernel)
    async with _client(app) as c:
        resp = await c.post("/v1/policies", json=_register_body(), headers=AUTH)
    assert resp.status_code == 503
    assert resp.json()["code"] == "POLICY_PERSISTENCE_ERROR"


# ── Full HTTP lifecycle journey ────────────────────────────────────────────────


async def test_full_lifecycle_journey() -> None:
    app = _app()
    async with _client(app) as c:
        assert (await c.post("/v1/policies", json=_register_body(), headers=AUTH)).status_code == 201
        assert (await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)).json()[
            "lifecycle"
        ] == "REVIEW"
        assert (
            await c.put(
                "/v1/policies/p.wire/versions/1/impact-report", json=_report_body(), headers=AUTH
            )
        ).status_code == 200
        assert (
            await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)
        ).json()["lifecycle"] == "ACTIVATED"
        got = await c.get("/v1/policies/p.wire/versions/1", headers=AUTH)
        assert got.json()["lifecycle"] == "ACTIVATED"
        dep = await c.post("/v1/policies/p.wire/versions/1/deprecate", headers=AUTH)
        assert dep.json()["lifecycle"] == "DEPRECATED"


# ── Hydrate after restart ──────────────────────────────────────────────────────


async def test_hydrate_after_restart_surfaces_policy() -> None:
    repo = InMemoryPolicyRepository()
    app1 = _app(repo=repo)
    async with _client(app1) as c:
        await c.post("/v1/policies", json=_register_body(), headers=AUTH)
        await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)
        await c.put(
            "/v1/policies/p.wire/versions/1/impact-report", json=_report_body(), headers=AUTH
        )
        await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)

    # New kernel over the same durable repository — simulate a restart.
    kernel2 = _kernel(repo=repo)
    await kernel2.startup()  # ASGITransport does not run lifespan, so hydrate explicitly
    app2 = create_app(kernel2)
    async with _client(app2) as c:
        resp = await c.get("/v1/policies/p.wire/versions/1", headers=AUTH)
    assert resp.status_code == 200 and resp.json()["lifecycle"] == "ACTIVATED"
