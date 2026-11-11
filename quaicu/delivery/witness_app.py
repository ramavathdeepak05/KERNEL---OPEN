"""Standalone ledger-witness service (D3-2 follow-up).

An independent process that cosigns Signed Tree Heads — the out-of-process anchor that makes the
split-view/rewind defence real (the kernel and the witness are different trust domains). Run it with
its **own** Ed25519 key and durable state, separate from the kernel; the kernel calls it via
`adapters/ledger/http_witness.HttpWitness`.

    POST /cosign            (auth) — cosign an STH iff it extends the last seen; 409 on fork/rewind
    GET  /witness-key       (public) — {witness_id, public_key_pem} to pin
    GET  /last-seen/{tenant}(auth) — the witness's last-seen (size, root) for a tenant
    GET  /health
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import TenantId


class CosignRequest(BaseModel):
    tenant: str
    tree_size: int = Field(..., ge=1)
    root_hash_hex: str
    consistency_proof_hex: list[str] = Field(default_factory=list)


def create_witness_app(witness: Any, *, auth_token: str | None = None) -> FastAPI:
    """Build the witness FastAPI app around an `AnchorPort` (a `SoftwareWitness`).

    ``auth_token`` protects the mutating/stateful routes; ``/witness-key`` + ``/health`` stay public.
    """
    app = FastAPI(title="QUAICU Ledger Witness", version="0.1.0")

    def _auth(request: Request) -> None:
        if not auth_token:
            return  # auth disabled (dev only)
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or token.strip() != auth_token:
            raise HTTPException(status_code=401, detail={"error": "witness auth required",
                                                         "code": "WITNESS_AUTH"})

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "witness_id": witness.witness_id}

    @app.get("/witness-key")
    async def witness_key() -> dict:
        return {"witness_id": witness.witness_id, "public_key_pem": witness.public_key_pem}

    @app.get("/last-seen/{tenant}")
    async def last_seen(tenant: str, request: Request) -> dict | None:
        _auth(request)
        seen = witness.last_seen(TenantId(tenant))
        if seen is None:
            return None
        return {"tree_size": seen[0], "root_hash_hex": seen[1].hex()}

    @app.post("/cosign")
    async def cosign(body: CosignRequest, request: Request) -> dict:
        _auth(request)
        sth = SignedTreeHead(
            tree_size=body.tree_size,
            timestamp=datetime.now(tz=timezone.utc),
            root_hash=bytes.fromhex(body.root_hash_hex),
            signature=b"",  # the witness attests size+root; the STH's own signature isn't needed here
            key_id="",
        )
        proof = [bytes.fromhex(h) for h in body.consistency_proof_hex]
        try:
            cosig = witness.cosign(TenantId(body.tenant), sth, proof)
        except LedgerTamperError as exc:
            # 409 Conflict: the log presented a non-extension (fork / rewind). Fail-closed.
            raise HTTPException(
                status_code=409,
                detail={"error": str(exc), "code": exc.code, "detail": exc.detail or {}},
            )
        return cosig.to_dict()

    return app
