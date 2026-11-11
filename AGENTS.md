# AGENTS.md — working agreement for contributors

Rules for anyone changing this codebase, human or coding agent. Code comments refer to the
sections here by number.

## 1. Layout

- `quaicu/core/` — governance logic. It imports only the standard library, a small set of pure
  libraries (CEL, cryptography, the OpenTelemetry API) and other `quaicu.core` modules. It never
  imports an adapter, a web framework, a database driver or a model SDK.
- `quaicu/adapters/` — implementations of the ports in `quaicu/core/ports/` (storage, ledger
  signing, identity, approvals, inference, events). Chosen by configuration, never by code in core.
- `quaicu/delivery/` — how the kernel is used: the SDK (`delivery/sdk`), the REST API
  (`delivery/api`), the MCP server (`delivery/mcp`) and the witness service.
- `tests/` — `unit/` and `conformance/` (spec-derived cases; the Postgres ones need a database).

## 2. Invariants

- **Fail-closed.** Any error, timeout or ambiguity denies (governance) or halts (infrastructure).
  A test that passes while the kernel lets an action through on an error is itself a defect.
- **No bypass.** Nothing executes an action without evaluating it first.
- **Seal before complete.** An action that executed but could not be sealed is HALTED, never
  COMPLETED.
- **CEL only** for policy conditions. No `eval`, no `exec`.
- **Replay-safe.** Record non-deterministic results and reuse them; never recompute a model call.

## 3. The frozen contract surface

These are the interfaces everything else is built against:

- `quaicu/core/ports/` — the port `Protocol` interfaces.
- `quaicu/core/types.py` — the shared value types (`Action`, `LedgerEntry`, `ActionState`, …).
- `quaicu/core/errors.py` — the `QUAICUError` hierarchy and its error codes.

Implement and consume them freely. Do not change a signature, a field or an error code without an
architecture decision record in `docs/adr/` that explains the change and its effect on dependants.

The ledger is additionally frozen until its independent cryptographic review is complete:
`quaicu/core/ledger/`, `quaicu/core/ports/anchor.py`, `quaicu/core/regmap/export.py`,
`quaicu/adapters/ledger/` and `quaicu/delivery/witness_app.py`
(`docs/operations/K02_REVIEW_PACKAGE.md`). Changes there need the maintainers' sign-off.

## 4. Before you open a change

```bash
pip install -e ".[test,dev]"
python -m pytest -q
ruff check .
```

- New behaviour comes with tests; a bug fix comes with a test that fails without it.
- Every `/v1` route is authenticated where routers are included (`quaicu/delivery/api/app.py`).
  Do not add an unauthenticated route without a reason stated in the change.
- Keep secrets out of files: configuration reads them from the environment (`"${NAME}"`).
