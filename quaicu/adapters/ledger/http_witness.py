"""HttpWitness — kernel-side client for the out-of-process ledger witness (D3-2 follow-up).

Implements `core.ports.anchor.AnchorPort` by calling a remote witness service (`delivery/witness_app`)
over HTTP, so the witness runs in a separate trust domain from the kernel. Synchronous `httpx` (like
`adapters/ledger/openbao.py`): cosign happens on export + on the periodic anchor loop, not the
per-action hot path. A `409` from the witness (a fork/rewind it refused) is surfaced as
`LedgerTamperError` — fail-closed.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.ports.anchor import WitnessCosignature
from quaicu.core.types import TenantId


class HttpWitness:
    """`AnchorPort` client for a remote witness service. ``client`` is injectable for tests."""

    def __init__(self, base_url: str, auth_token: str | None = None, *, client: Any | None = None) -> None:
        self._base = base_url.rstrip("/")
        if client is not None:
            self._client = client
        else:
            import httpx

            headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
            self._client = httpx.Client(base_url=self._base, headers=headers, timeout=10.0)
        self._witness_id: str | None = None
        self._public_key_pem: str | None = None

    def _load_key(self) -> None:
        if self._witness_id is None:
            resp = self._client.get("/witness-key")
            resp.raise_for_status()
            data = resp.json()
            self._witness_id = str(data["witness_id"])
            self._public_key_pem = str(data["public_key_pem"])

    @property
    def witness_id(self) -> str:
        self._load_key()
        assert self._witness_id is not None
        return self._witness_id

    @property
    def public_key_pem(self) -> str:
        self._load_key()
        assert self._public_key_pem is not None
        return self._public_key_pem

    def last_seen(self, tenant: TenantId) -> tuple[int, bytes] | None:
        resp = self._client.get(f"/last-seen/{tenant}")
        resp.raise_for_status()
        data = resp.json()
        if not data:
            return None
        return (int(data["tree_size"]), bytes.fromhex(data["root_hash_hex"]))

    def cosign(
        self, tenant: TenantId, sth: SignedTreeHead, consistency_proof: list[bytes]
    ) -> WitnessCosignature:
        body = {
            "tenant": str(tenant),
            "tree_size": sth.tree_size,
            "root_hash_hex": sth.root_hash.hex(),
            "consistency_proof_hex": [h.hex() for h in consistency_proof],
        }
        resp = self._client.post("/cosign", json=body)
        if resp.status_code == 409:
            detail = resp.json().get("detail", {})
            raise LedgerTamperError(
                str(detail.get("error", "witness refused to cosign (fork / rewind)")),
                detail=detail.get("detail", {}) if isinstance(detail, dict) else {},
            )
        resp.raise_for_status()
        return WitnessCosignature.from_dict(resp.json())

    def verify(self, cosig: WitnessCosignature, public_key_pem: str) -> bool:
        try:
            key = load_pem_public_key(public_key_pem.encode())
            if not isinstance(key, Ed25519PublicKey):
                return False
            key.verify(cosig.signature, cosig.signing_message())
            return True
        except Exception:  # noqa: BLE001 — any failure is a verification failure
            return False
