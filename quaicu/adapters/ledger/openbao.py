"""OpenBao-backed TreeSigner + LedgerAdapter.

``OpenBaoTreeSigner`` implements the ``TreeSigner`` protocol using OpenBao's
(Vault-compatible) Transit secrets engine.  The signing key lives in OpenBao —
never in process memory — so it survives restarts and can be shared across
nodes in a horizontally-scaled deployment.

``OpenBaoLedgerAdapter`` wraps the full RFC 6962 ``TrustLedger`` (K·02) with
this signer, giving you Merkle inclusion/consistency proofs + durable Ed25519
Signed Tree Heads.  Use this adapter in production; replace ``memory_ledger``
in kernel.toml with ``openbao_ledger``.

OpenBao Transit API calls are synchronous (``httpx.Client``).  The ``TreeSigner``
protocol is FROZEN — its methods cannot be made async.  The brief event-loop
block on a ledger seal is acceptable: one HTTP round-trip per governed action,
not a per-request hot path.

Prerequisites (run once):
    bao secrets enable transit
    bao write transit/keys/quaicu-ledger type=ed25519
"""

from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

import httpx

from quaicu.core.errors import LedgerSealError
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.repository import LedgerRepository
from quaicu.core.ledger.signer import SignedTreeHead, _signing_message
from quaicu.core.types import Action, ApproverRef, EvaluationResult, LedgerEntry


# ── OpenBao TreeSigner ────────────────────────────────────────────────────────


class OpenBaoTreeSigner:
    """Ed25519 ``TreeSigner`` backed by OpenBao Transit secrets engine.

    The key is identified by ``key_name`` and must already exist in OpenBao
    as type ``ed25519`` before this adapter is used.
    """

    def __init__(
        self,
        addr: str,
        token: str,
        key_name: str,
        *,
        verify_tls: bool = True,
    ) -> None:
        self._key_name = key_name
        self._client = httpx.Client(
            base_url=addr.rstrip("/"),
            headers={"X-Vault-Token": token},
            verify=verify_tls,
            timeout=10.0,
        )
        self._cached_key_id: str | None = None

    # ── TreeSigner protocol ───────────────────────────────────────────────────

    @property
    def key_id(self) -> str:
        if self._cached_key_id is None:
            self._cached_key_id = self._fetch_key_id()
        return self._cached_key_id

    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
        msg = _signing_message(tree_size, root_hash)
        b64_input = base64.b64encode(msg).decode("ascii")
        try:
            # Ed25519 signs the raw message directly — do NOT send hash_algorithm.
            # (Passing hash_algorithm="none" trips OpenBao's RSA-only prehash
            # validation path: "requires prehashed=true and signature_algorithm".)
            resp = self._client.post(
                f"/v1/transit/sign/{self._key_name}",
                json={"input": b64_input},
            )
            resp.raise_for_status()
            signature_str: str = resp.json()["data"]["signature"]
        except Exception as exc:
            raise LedgerSealError(
                f"OpenBao sign failed for key {self._key_name!r}: {exc}",
                detail={"key_name": self._key_name},
            ) from exc

        return SignedTreeHead(
            tree_size=tree_size,
            timestamp=timestamp,
            root_hash=root_hash,
            signature=signature_str.encode("utf-8"),  # store vault:v1:<b64> as bytes
            key_id=self.key_id,
        )

    def verify(self, sth: SignedTreeHead) -> bool:
        # A successful response carries OpenBao's verdict: return it as-is (``valid=false`` means the
        # signature is genuinely invalid → ``False``). A transport/HTTP failure is NOT a verdict — it
        # is an outage, and silently returning False would turn an infrastructure problem into a
        # false-negative audit failure. Raise so the caller (and the API's 503 handler) can tell the
        # difference between "ledger is bad" and "we couldn't reach the ledger's signer".
        msg = _signing_message(sth.tree_size, sth.root_hash)
        b64_input = base64.b64encode(msg).decode("ascii")
        signature_str = sth.signature.decode("utf-8")
        try:
            resp = self._client.post(
                f"/v1/transit/verify/{self._key_name}",
                json={"input": b64_input, "signature": signature_str},
            )
            resp.raise_for_status()
            return bool(resp.json()["data"]["valid"])
        except Exception as exc:
            raise LedgerSealError(
                f"OpenBao verify failed for key {self._key_name!r}: {exc}",
                detail={"key_name": self._key_name},
            ) from exc

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fetch_key_id(self) -> str:
        try:
            resp = self._client.get(f"/v1/transit/keys/{self._key_name}")
            if resp.status_code == 404:
                raise LedgerSealError(
                    f"OpenBao key {self._key_name!r} not found. "
                    f"Create it with: bao write transit/keys/{self._key_name} type=ed25519",
                    detail={"key_name": self._key_name},
                )
            resp.raise_for_status()
            version: int = resp.json()["data"]["latest_version"]
            return f"{self._key_name}:v{version}"
        except LedgerSealError:
            raise
        except Exception as exc:
            raise LedgerSealError(
                f"OpenBao key fetch failed for {self._key_name!r}: {exc}",
                detail={"key_name": self._key_name},
            ) from exc

    def close(self) -> None:
        self._client.close()


# ── OpenBao Ledger Adapter ────────────────────────────────────────────────────


class OpenBaoLedgerAdapter:
    """Production ledger: RFC 6962 TrustLedger + OpenBao-backed Ed25519 signer.

    Satisfies the ``Ledger`` protocol structurally.  Use in kernel.toml::

        [adapters]
        ledger = "openbao_ledger"

        [ledger]
        addr     = "http://vault.internal:8200"
        token    = "s.xxxxxxxxxxxx"
        key_name = "quaicu-ledger"
    """

    def __init__(
        self,
        addr: str,
        token: str,
        key_name: str,
        *,
        verify_tls: bool = True,
        repository: LedgerRepository | None = None,
    ) -> None:
        self._signer = OpenBaoTreeSigner(
            addr=addr,
            token=token,
            key_name=key_name,
            verify_tls=verify_tls,
        )
        self._repository = repository
        self._ledger = TrustLedger(signer=self._signer, repository=repository)

    async def hydrate(self) -> None:
        """Rebuild the in-memory tree/entries/STHs from the durable repository (startup)."""
        await self._ledger.hydrate()

    # ── Ledger protocol ───────────────────────────────────────────────────────

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        return await self._ledger.seal(
            action=action,
            evaluation=evaluation,
            recorded_result=recorded_result,
            approver=approver,
        )

    # ── Read-side (pass-through to TrustLedger) ───────────────────────────────

    def get_entry(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_entry(tenant, seq)

    def get_entries(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_entries(tenant)

    def get_signed_tree_head(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_signed_tree_head(tenant)

    def get_inclusion_proof(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_inclusion_proof(tenant, seq)

    def verify_inclusion(self, tenant, seq, sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_inclusion(tenant, seq, sth)

    def get_consistency_proof(self, tenant, old_size):  # type: ignore[no-untyped-def]
        return self._ledger.get_consistency_proof(tenant, old_size)

    def verify_consistency(self, tenant, old_sth, new_sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_consistency(tenant, old_sth, new_sth)

    async def close(self) -> None:
        self._signer.close()
        if self._repository is not None:
            await self._repository.close()
