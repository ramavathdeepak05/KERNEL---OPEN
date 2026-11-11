# ADR-0012: Cloud-native adapters (GCP-first)

- **Status:** Accepted
- **Date:** 2026-06-16
- **Decided by:** orchestrator
- **Affects:** `quaicu/adapters/ledger/`, `quaicu/adapters/inference/`, `quaicu/core/ledger/signer.py`, `quaicu/core/regmap/export.py`, `quaicu/delivery/sdk/kernel.py` (registry), `pyproject.toml`

## Context

Regulated institutions (banks, insurance, healthcare) often will not self-host OpenBao / Kafka /
Temporal — the operational burden and the SOC2 / ISO 27001 / FedRAMP audit surface are dealbreakers.
They want **managed services** (FIPS-certified KMS, private inference, serverless workflows) so the
infrastructure-compliance burden shifts to the cloud provider. The hexagonal architecture (F-08: core
depends only on ports) means this is satisfied by writing new **adapters** against existing ports,
with **no core changes** — except one unavoidable crypto detail below.

The blocking detail: the K·02 ledger signs Signed Tree Heads (STHs) with **Ed25519**
(`quaicu/core/ledger/signer.py`). **Google Cloud KMS does not support Ed25519** for asymmetric signing (only
RSA and ECDSA P-256/P-384, verified June 2026). AWS KMS added Ed25519 in Nov 2025, but a GCP-first
launch cannot rely on that. So a Cloud KMS signer must use a different signature scheme, and the
offline regulator verifier (`quaicu/core/regmap/export.py`) must accept it.

## Decision

1. **Cloud adapters are additive and optional.** New SDKs (`google-cloud-kms`, `google-genai`) are
   declared under `[project.optional-dependencies]` extras `gcp` / `aws`, imported **lazily inside
   adapter constructors**, and registered in `_ADAPTER_REGISTRY` (`quaicu/delivery/sdk/kernel.py`). The
   kernel core carries **no** cloud dependency, and the base `requirements.lock` is unchanged. An
   adapter's SDK is required only when its `[adapters]` key is wired.
2. **Auth is Application Default Credentials / Workload Identity** — no static keys in config.
3. **The Cloud KMS ledger signer uses ECDSA P-256 (`EC_SIGN_P256_SHA256`)**, not Ed25519. It signs
   SHA-256 of the RFC 6962 signing message and stores the DER ECDSA signature in
   `SignedTreeHead.signature`. ECDSA is itself RFC 6962-conformant.
4. **The STH verifier is algorithm-aware by public-key type, not by a wire tag.** `SignedTreeHead`
   gains **no** new field (no storage/serialization migration). The offline verifier in
   `quaicu/core/regmap/export.py` dispatches: `Ed25519PublicKey` → pure EdDSA; `EllipticCurvePublicKey` →
   `ECDSA(SHA256)`. Each `TreeSigner` adapter knows its own scheme. Existing Ed25519 signers
   (software, OpenBao) are unchanged.

## Consequences

- **Easier:** new managed-service adapters plug in by implementing a port + one registry line; the
  regulator-facing offline verifier now handles both Ed25519 and ECDSA-P256 bundles with one code path.
- **Required:** a GCP-KMS-backed deployment's STHs are ECDSA-P256. The pending **K·02 external
  cryptographic review must review the ECDSA-P256 STH path** (not only Ed25519).
- **Forbidden (unchanged):** importing a cloud SDK from `core/` (F-08). SDKs live in `adapters/` and
  are lazy + optional.
- **Notify / re-run:** the K·02 reviewers; CI runs the new adapter tests with **mocked** clients, so
  no cloud credentials are needed in CI.
- **Reference adapters delivered:** `quaicu/adapters/ledger/gcp_kms.py` (`GcpKmsTreeSigner` +
  `GcpKmsLedgerAdapter`, registry `gcp_kms_ledger`) and `quaicu/adapters/inference/vertex.py`
  (`VertexInferenceAdapter`, registry `vertex_inference`). Further cloud adapters (DLP masking,
  KMS-envelope erasure, Pub/Sub events, Cloud Workflows HITL) are not part of this decision.

## Alternatives considered

- **Keep Ed25519 everywhere; require AWS KMS for the signer.** Rejected for a GCP-first launch (forces
  the cloud choice and leaves GCP customers without an HSM-backed signer).
- **Software/OpenBao Ed25519 STH re-signed from a KMS-wrapped key.** Rejected: the private key would
  leave the HSM, defeating the FIPS 140-2 L3 "key never extractable" guarantee that is the entire
  regulator value of moving to KMS.
- **Carry an explicit `algorithm` tag on `SignedTreeHead`.** Rejected as redundant: the public key
  already determines the scheme, and adding a field forces a ledger storage + export serialization
  migration for no verifier benefit.
