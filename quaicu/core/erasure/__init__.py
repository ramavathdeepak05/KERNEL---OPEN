"""Crypto-shredding erasure (WS-G) — GDPR / DPDP right-to-erasure without breaking the ledger.

The K·02 transparency log is append-only and tamper-evident: you cannot delete or rewrite a sealed
entry without invalidating every downstream Merkle proof. So "delete the customer's data" is satisfied
**cryptographically**, not by deletion:

  - personal data is stored as ciphertext encrypted under a per-subject data-encryption key (DEK);
  - the Merkle leaves / hashes are computed over the *ciphertext* (or over non-PII), so they stay
    valid forever;
  - erasure = **destroy the subject's DEK** (crypto-shredding). The ciphertext that remains in the
    ledger / storage becomes permanently irrecoverable, while the log's integrity is untouched.

`ErasureEngine` is the surface: `encrypt(subject, plaintext)` → a portable cipher token,
`decrypt(token)` → plaintext (or `SubjectErasedError` once shredded), `erase(subject)` → an erasure
receipt. Single-process in-memory keyring by default; a durable HSM/KMS-backed keyring plugs in behind
the same interface.
"""

from quaicu.core.erasure.engine import ErasureEngine, ErasureReceipt
from quaicu.core.erasure.keyring import InMemoryShredKeyring, ShredKeyring

__all__ = ["ErasureEngine", "ErasureReceipt", "ShredKeyring", "InMemoryShredKeyring"]
