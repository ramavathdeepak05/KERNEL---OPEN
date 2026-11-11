"""K·14 / WS-F — regulator ledger-proof export.

Turns a tenant's K·02 transparency log (over a time window) into an independently verifiable proof
bundle a regulator can check offline, without contacting the kernel:

  - the signed tree head (RFC 6962 STH: size, root, Ed25519/ECDSA signature, key_id, public key);
  - one inclusion proof per governed action in the window (leaf hash + audit path);
  - the K·14 evidence narrative + manifest (which regulations/policy versions the window covers).

Trust model — two separable properties (D3-1):

  * **Integrity** is self-contained: `verify_ledger_proof_bundle` recomputes the Merkle root from
    each inclusion proof and checks it equals the *signed* root. This detects any tampering *within*
    the bundle using nothing but the bundle.
  * **Authenticity** requires an *out-of-band pinned key*: the STH signature is verified against a
    caller-supplied `trusted_keys` map (`key_id → public-key PEM`), NEVER the key embedded in the
    bundle. A forged bundle carrying its own keypair is self-consistent but its `key_id` is not in
    the pinned set (or its signature does not verify against the pinned key) → rejected. The
    embedded public key is advisory only; if present it is cross-checked against the pinned key.

The regulator obtains the trusted key once at onboarding (e.g. `GET /v1/ledger/signing-key`, or a
published key registry) and pins it; thereafter a kernel-side key swap cannot pass verification. The
build side performs zero model re-calls and only reads already-sealed entries (F-09).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from quaicu.core.ledger.merkle import _recompute_root_from_path
from quaicu.core.ledger.signer import SignedTreeHead, _signing_message
from quaicu.core.ports.anchor import WitnessCosignature
from quaicu.core.regmap.catalog import generate_evidence_pack
from quaicu.core.regmap.model import EvidencePack
from quaicu.core.types import LedgerEntry

FORMAT_VERSION = "quaicu.ledger-proof/1.0"


@dataclass(frozen=True)
class InclusionProofExport:
    """One action's inclusion proof, hex-encoded for JSON transport."""

    ledger_seq: int
    leaf_hash_hex: str
    audit_path_hex: tuple[str, ...]
    action_id: str
    action_type: str
    decision: str
    sealed_at: str


@dataclass(frozen=True)
class SignedTreeHeadExport:
    """The signed tree head, hex-encoded, with the signing public key so it verifies offline."""

    tree_size: int
    root_hash_hex: str
    signature_hex: str
    key_id: str
    timestamp: str
    public_key_pem: str | None  # Ed25519 SPKI PEM; None if the signer does not expose it


@dataclass(frozen=True)
class LedgerProofBundle:
    """A complete, self-verifying regulator export."""

    tenant_id: str
    window_start: str
    window_end: str
    sth: SignedTreeHeadExport
    inclusion_proofs: tuple[InclusionProofExport, ...]
    evidence: EvidencePack
    generated_at: str
    format_version: str = FORMAT_VERSION
    metadata: dict = field(default_factory=dict)
    # An independent witness cosignature over this STH (D3-2), or None if the log is not anchored.
    anchor: dict | None = None

    def to_dict(self) -> dict:
        """A fully JSON-serializable view (what the export route returns)."""
        return {
            "format_version": self.format_version,
            "tenant_id": self.tenant_id,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "generated_at": self.generated_at,
            "anchor": self.anchor,
            "signed_tree_head": {
                "tree_size": self.sth.tree_size,
                "root_hash_hex": self.sth.root_hash_hex,
                "signature_hex": self.sth.signature_hex,
                "key_id": self.sth.key_id,
                "timestamp": self.sth.timestamp,
                "public_key_pem": self.sth.public_key_pem,
            },
            "inclusion_proofs": [
                {
                    "ledger_seq": p.ledger_seq,
                    "leaf_hash_hex": p.leaf_hash_hex,
                    "audit_path_hex": list(p.audit_path_hex),
                    "action_id": p.action_id,
                    "action_type": p.action_type,
                    "decision": p.decision,
                    "sealed_at": p.sealed_at,
                }
                for p in self.inclusion_proofs
            ],
            "evidence": {
                "verifiable": self.evidence.verifiable,
                "narrative": self.evidence.narrative,
                "manifest": {
                    "regulation_refs": list(self.evidence.manifest.regulation_refs),
                    "policy_versions": list(self.evidence.manifest.policy_versions),
                    "action_count": self.evidence.manifest.action_count,
                    "ledger_proof_refs": list(self.evidence.manifest.ledger_proof_refs),
                },
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def build_ledger_proof_bundle(
    *,
    tenant_id: str,
    window_start: datetime,
    window_end: datetime,
    entries_with_paths: list[tuple[LedgerEntry, list[bytes]]],
    sth: SignedTreeHead,
    public_key_pem: str | None,
    regulation_refs: list[str] | None = None,
    policy_versions: list[str] | None = None,
    witness_cosignature: "WitnessCosignature | None" = None,
) -> LedgerProofBundle:
    """Assemble a `LedgerProofBundle` from sealed entries + their inclusion proofs.

    ``entries_with_paths`` pairs each in-window `LedgerEntry` with its K·02 audit path (from
    ``TrustLedger.get_inclusion_proof``). ``sth`` is the tenant's current signed tree head; the proofs
    are verified against its root by the receiving regulator.
    """
    proofs = tuple(
        InclusionProofExport(
            ledger_seq=entry.ledger_seq,
            leaf_hash_hex=entry.leaf_hash.hex(),
            audit_path_hex=tuple(node.hex() for node in path),
            action_id=str(entry.action_id),
            action_type=entry.action_type,
            decision=entry.decision.value,
            sealed_at=_iso(entry.sealed_at),
        )
        for entry, path in entries_with_paths
    )

    # Real K·02 proof refs (leaf hashes) make the evidence pack independently verifiable (not a stub).
    pack = generate_evidence_pack(
        tenant_id=tenant_id,
        regulation_refs=list(regulation_refs or []),
        policy_versions=list(policy_versions or []),
        ledger_entries=[e for e, _ in entries_with_paths],
        window_start=window_start,
        window_end=window_end,
        ledger_proof_refs=[p.leaf_hash_hex for p in proofs],
    )

    sth_export = SignedTreeHeadExport(
        tree_size=sth.tree_size,
        root_hash_hex=sth.root_hash.hex(),
        signature_hex=sth.signature.hex(),
        key_id=sth.key_id,
        timestamp=_iso(sth.timestamp),
        public_key_pem=public_key_pem,
    )

    return LedgerProofBundle(
        tenant_id=tenant_id,
        window_start=_iso(window_start),
        window_end=_iso(window_end),
        sth=sth_export,
        inclusion_proofs=proofs,
        evidence=pack,
        generated_at=_iso(datetime.now(tz=timezone.utc)),
        anchor=witness_cosignature.to_dict() if witness_cosignature is not None else None,
    )


def trusted_keys_from_signer(signer: object) -> dict[str, str]:
    """Build a one-entry ``{key_id: public_key_pem}`` trust anchor from a live signer.

    For in-process callers that already hold the tenant's ledger signer (the hosted verify endpoint,
    tests). An external regulator instead pins the key obtained out-of-band (see the module docstring).
    Raises ``ValueError`` if the signer does not expose both ``key_id`` and ``public_key_pem``.
    """
    key_id = getattr(signer, "key_id", None)
    pem = getattr(signer, "public_key_pem", None)
    if not key_id or not pem:
        raise ValueError("signer does not expose key_id + public_key_pem; cannot build a trust anchor")
    return {str(key_id): str(pem)}


def verify_ledger_proof_bundle(
    bundle_dict: dict,
    *,
    trusted_keys: "dict[str, str] | None" = None,
    trusted_witnesses: "dict[str, str] | None" = None,
) -> tuple[bool, list[str]]:
    """Independently verify an exported bundle (the code a regulator runs offline).

    Returns ``(ok, errors)``. ``ok`` is True only when all requested checks hold:

      1. **Integrity** — every inclusion proof recomputes the *signed* Merkle root (self-contained).
      2. **Authenticity** — the STH signature verifies against an *externally pinned* key selected by
         the bundle's ``key_id`` from ``trusted_keys`` (``key_id → public-key PEM``), NOT the key
         embedded in the bundle. Fail-closed: no ``trusted_keys`` → cannot attest authenticity → fail;
         a ``key_id`` absent from the pinned set (a forged/unknown key) → fail.
      3. **Anchoring** (optional, D3-2) — when ``trusted_witnesses`` (``witness_id → PEM``) is given,
         the bundle's independent witness cosignature must verify against the pinned witness key and
         attest the *same* (tree_size, root) as the STH. Omit ``trusted_witnesses`` to skip this check.

    Operates purely on the exported dict + the caller-pinned keys — no kernel state, no network.
    """
    errors: list[str] = []
    try:
        sth = bundle_dict["signed_tree_head"]
        tree_size = int(sth["tree_size"])
        root = bytes.fromhex(sth["root_hash_hex"])
        proofs = bundle_dict.get("inclusion_proofs", [])
    except (KeyError, ValueError, TypeError) as exc:
        return False, [f"malformed bundle: {exc}"]

    # (1) Integrity: every inclusion proof must reconstruct the signed root.
    for p in proofs:
        try:
            seq = int(p["ledger_seq"])
            leaf = bytes.fromhex(p["leaf_hash_hex"])
            path = [bytes.fromhex(h) for h in p["audit_path_hex"]]
        except (KeyError, ValueError, TypeError) as exc:
            errors.append(f"malformed inclusion proof: {exc}")
            continue
        recomputed = _recompute_root_from_path(seq, tree_size, leaf, path)
        if recomputed != root:
            errors.append(f"inclusion proof for seq {seq} does not match the signed root")

    # (2) Authenticity: verify the STH signature against the PINNED key for the bundle's key_id —
    # never the key embedded in the bundle (that would let a forged, self-signed bundle pass). The
    # algorithm (Ed25519 vs ECDSA P-256) is inferred from the pinned key, so a GCP/AWS KMS-signed
    # bundle pins the same way as the Ed25519 software/OpenBao signer.
    errors.extend(_verify_authenticity(sth, tree_size, root, trusted_keys))

    # (3) Anchoring: verify the independent witness cosignature against a pinned witness key.
    if trusted_witnesses is not None:
        errors.extend(_verify_anchor(bundle_dict.get("anchor"), tree_size, root, trusted_witnesses))

    return (not errors), errors


def _verify_anchor(
    anchor: dict | None, tree_size: int, root: bytes, trusted_witnesses: dict[str, str]
) -> list[str]:
    if not anchor:
        return ["no witness cosignature in bundle — anchoring cannot be verified"]
    try:
        cosig = WitnessCosignature.from_dict(anchor)
    except (KeyError, ValueError, TypeError) as exc:
        return [f"malformed anchor cosignature: {exc}"]
    if cosig.witness_id not in trusted_witnesses:
        return [
            f"anchor witness_id {cosig.witness_id!r} is not in the pinned witness set — "
            "refusing to trust a self-described witness"
        ]
    if cosig.tree_size != tree_size or cosig.root_hash != root:
        return ["anchor cosignature attests a different tree head than the STH (possible split-view)"]
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        witness_key = load_pem_public_key(trusted_witnesses[cosig.witness_id].encode())
        _verify_sth_signature(witness_key, cosig.signature, cosig.signing_message())
    except Exception as exc:  # noqa: BLE001 — any failure is a verification failure
        return [f"witness cosignature does not verify against the pinned witness key: {exc}"]
    return []


def _verify_authenticity(
    sth: dict, tree_size: int, root: bytes, trusted_keys: "dict[str, str] | None"
) -> list[str]:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key_id = str(sth.get("key_id") or "")
    if trusted_keys is None:
        return [
            "no pinned trust anchor supplied — STH authenticity cannot be verified "
            "(pass trusted_keys={key_id: public_key_pem})"
        ]
    if key_id not in trusted_keys:
        return [
            f"STH key_id {key_id!r} is not in the pinned trust anchor — "
            "refusing to trust a self-described signing key"
        ]

    try:
        pinned_key = load_pem_public_key(trusted_keys[key_id].encode())
    except Exception as exc:  # noqa: BLE001 — a bad pinned key is a caller error, surfaced as failure
        return [f"pinned key for key_id {key_id!r} could not be loaded: {exc}"]

    # Defence-in-depth: if the bundle embeds a public key, it must match the pinned one (tamper signal).
    embedded_pem = sth.get("public_key_pem")
    if embedded_pem:
        try:
            embedded_key = load_pem_public_key(embedded_pem.encode())
            if _public_bytes(embedded_key) != _public_bytes(pinned_key):
                return [
                    f"embedded public key does not match the pinned key for key_id {key_id!r} "
                    "(possible tampering)"
                ]
        except Exception as exc:  # noqa: BLE001
            return [f"embedded public key could not be parsed: {exc}"]

    try:
        _verify_sth_signature(
            pinned_key, bytes.fromhex(sth["signature_hex"]), _signing_message(tree_size, root)
        )
    except Exception as exc:  # noqa: BLE001 — any failure is a verification failure
        return [f"STH signature does not verify against the pinned key: {exc}"]
    return []


def _public_bytes(public_key: object) -> bytes:
    """Canonical SPKI DER bytes of a public key, for equality comparison across PEM formatting."""
    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(  # type: ignore[attr-defined]
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _verify_sth_signature(public_key: object, signature: bytes, message: bytes) -> None:
    """Verify an STH signature, dispatching on the public-key type. Raises on any failure.

    - Ed25519 (software / OpenBao transit): pure EdDSA over the raw message.
    - ECDSA P-256 (GCP Cloud KMS ``EC_SIGN_P256_SHA256`` / AWS KMS ``ECDSA_SHA_256``): DER signature
      over SHA-256 of the message (the hash is applied internally by ``verify``).
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if isinstance(public_key, Ed25519PublicKey):
        public_key.verify(signature, message)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"unsupported STH signing key type: {type(public_key).__name__}")
