"""FastAPI application factory for the QUAICU Kernel REST API.

Usage::

    from quaicu import Kernel
    from quaicu.delivery.api.app import create_app

    kernel = Kernel.from_config("kernel.toml")
    app = create_app(kernel)

The app stores the ``Kernel`` on ``app.state.kernel`` so routes reach it without global state.

Every ``/v1`` route is authenticated by the kernel's identity adapter (see ``delivery/api/deps.py``).
The only unauthenticated endpoints are the health probes, the OpenAPI pages, and the signed
approval links (which carry their own HMAC-signed token).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from contextlib import asynccontextmanager
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from quaicu.core.errors import (
    LifecycleDeniedError,
    LifecycleHaltedError,
    QUAICUError,
    SubjectErasedError,
    TenantIsolationError,
)
from quaicu.delivery.api.deps import authenticate
from quaicu.delivery.api.middleware import GovernanceMiddleware
from quaicu.delivery.api.observability import RequestLoggingMiddleware
from quaicu.delivery.api.routes.actions import router as actions_router
from quaicu.delivery.api.routes.approvals import link_router as approval_links_router
from quaicu.delivery.api.routes.approvals import router as approvals_router
from quaicu.delivery.api.routes.authorize import router as authorize_router
from quaicu.delivery.api.routes.dashboard import router as dashboard_router
from quaicu.delivery.api.routes.erasure import router as erasure_router
from quaicu.delivery.api.routes.inference import router as inference_router
from quaicu.delivery.api.routes.ledger import router as ledger_router
from quaicu.delivery.api.routes.policies import router as policies_router
from quaicu.delivery.api.routes.policy_packs import router as policy_packs_router
from quaicu.delivery.api.routes.tools import router as tools_router
from quaicu.delivery.sdk.kernel import Kernel

_log = logging.getLogger("quaicu.api.app")

# Routers whose every route requires an authenticated caller.
_PROTECTED_ROUTERS: tuple[APIRouter, ...] = (
    actions_router,
    authorize_router,
    inference_router,
    ledger_router,
    policies_router,
    policy_packs_router,
    dashboard_router,
    approvals_router,
    erasure_router,
    tools_router,
)


def create_app(
    kernel: Kernel,
    *,
    enforce_paths: list[tuple[str, str]] | None = None,
    cors_origins: list[str] | None = None,
    extra_routers: Sequence[APIRouter] = (),
    erasure_engine: Any | None = None,
    anchor_interval: float | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        kernel: A fully wired ``Kernel``.
        enforce_paths: Optional reference-PEP enforcement-point path globs (see
            ``delivery/api/middleware.py``).
        cors_origins: Browser origins allowed to call the API. None (the default) allows no
            cross-origin browser access.
        extra_routers: Additional routers a host mounts on the same app. They are included with
            the same authentication dependency as the built-in ``/v1`` routes.
        erasure_engine: An ``ErasureEngine`` to enable the right-to-erasure routes (503 without).
        anchor_interval: Seconds between periodic witness anchoring passes, when the kernel has an
            anchor witness wired. None disables the loop.

    Returns:
        A configured ``FastAPI`` app ready to serve.
    """

    async def _anchor_loop() -> None:
        from quaicu.core.ledger.anchor import anchor_all_tenants
        from quaicu.delivery.api.leader import ANCHOR_LOCK_NAME, ledger_dsn_of, try_advisory_gate

        while True:
            await asyncio.sleep(anchor_interval)  # type: ignore[arg-type]
            try:
                # Single-runner gate: with several workers every worker runs this loop; a Postgres
                # advisory lock elects one runner per pass.
                async with try_advisory_gate(ledger_dsn_of(kernel), ANCHOR_LOCK_NAME) as won:
                    if not won:
                        continue
                    # The ledger adapters wrap the core TrustLedger and do not forward
                    # `tenants()`, which the anchor pass needs; hand it the core ledger.
                    ledger = kernel.engine._ledger
                    ledger = getattr(ledger, "_ledger", ledger)
                    await asyncio.to_thread(anchor_all_tenants, ledger, kernel.witness)
            except Exception:  # noqa: BLE001 — a witness outage must not kill the loop
                _log.exception("periodic ledger anchor pass failed")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        # Initialise async resources (hydrate the durable policy store and ledger) before serving.
        await kernel.startup()
        # Startup hydration done → /readyz reports ready. Flipped back off during shutdown so a
        # draining instance fails readiness while still answering liveness.
        _app.state.ready = True
        anchor_task = None
        if anchor_interval and anchor_interval > 0 and getattr(kernel, "witness", None) is not None:
            anchor_task = asyncio.create_task(_anchor_loop())
        try:
            yield
        finally:
            _app.state.ready = False
            if anchor_task is not None:
                anchor_task.cancel()
                try:
                    await anchor_task
                except asyncio.CancelledError:
                    pass
            await kernel.shutdown()

    app = FastAPI(
        title="QUAICU Governance Kernel",
        version="0.1.0",
        description=(
            "AI governance kernel. "
            "All actions are governed: evaluate → gate → execute → seal → emit."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.state.kernel = kernel
    # Readiness gate: false until lifespan startup hydration completes. /readyz reads this;
    # /health (liveness) ignores it.
    app.state.ready = False
    # Crypto-shredding engine for the right-to-erasure routes (503 when None).
    app.state.erasure_engine = erasure_engine

    # ── Routers ───────────────────────────────────────────────────────────────
    # Authentication is attached HERE, not inside each route, so a route cannot forget it.
    protected = [Depends(authenticate)]
    for router in (*_PROTECTED_ROUTERS, *extra_routers):
        app.include_router(router, dependencies=protected)
    # Signed approval links authenticate with the HMAC-signed token in the URL, not a bearer.
    app.include_router(approval_links_router)

    # ── Middleware stack ──────────────────────────────────────────────────────
    # Starlette runs middleware in REVERSE order of registration (last added = outermost), so the
    # effective order is: CORS → RequestLogging → GovernancePEP → routes.
    if enforce_paths:
        app.add_middleware(GovernanceMiddleware, kernel=kernel, enforce_paths=enforce_paths)

    # Structured access logging + correlation ids (always on).
    app.add_middleware(RequestLoggingMiddleware)

    # CORS only when the operator names the browser origins allowed to call the API. The
    # Authorization header and the actor headers are listed explicitly: per the Fetch spec the
    # wildcard does not match Authorization.
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type", "X-Actor-Id", "X-Actor-Roles"],
        )

    # ── Exception handlers ────────────────────────────────────────────────────

    @app.exception_handler(LifecycleDeniedError)
    async def _denied_handler(request: Request, exc: LifecycleDeniedError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
        )

    @app.exception_handler(LifecycleHaltedError)
    async def _halted_handler(request: Request, exc: LifecycleHaltedError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
        )

    @app.exception_handler(TenantIsolationError)
    async def _tenant_handler(request: Request, exc: TenantIsolationError) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
        )

    @app.exception_handler(SubjectErasedError)
    async def _erased_handler(request: Request, exc: SubjectErasedError) -> JSONResponse:
        # 410 Gone: the data was crypto-shredded — its absence is the correct, intended state.
        return JSONResponse(
            status_code=410,
            content={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
        )

    @app.exception_handler(QUAICUError)
    async def _kernel_error_handler(request: Request, exc: QUAICUError) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
        )

    # ── Health endpoints ──────────────────────────────────────────────────────
    # /health = liveness (process up); /readyz = readiness (startup hydration done). Both are
    # unauthenticated, for orchestrator probes and uptime monitors.

    @app.get("/health", tags=["system"], summary="Liveness / health check")
    async def health() -> dict:
        return {"ok": True, "tenant": str(kernel.tenant)}

    @app.get("/readyz", tags=["system"], summary="Readiness check")
    async def readyz(response: Response) -> dict:
        if getattr(app.state, "ready", False):
            return {"ok": True, "status": "ready"}
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"ok": False, "status": "not-ready"}

    return app
