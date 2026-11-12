# CLAUDE.md — shared notes for AI coding assistants

Working memory for AI assistants (Claude Code, Gemini CLI and others) that work on this
repository. Tools that load this file at the start of a session see everything written here.
The rules for changing the code are in `AGENTS.md`; read that first.

## How to use this file

- **Read** this whole file before starting work.
- **Append** durable facts, decisions and handoffs under the sections below.
- **Attribute + date** every entry: `- [YYYY-MM-DD] (claude|gemini|…) <fact>`.
- Keep entries short and factual. Link to files with paths, not pasted blobs.
- Don't delete another agent's entry; if it's wrong, add a correcting entry below it.
- This repository is public: no credentials, no deployment details, no personal data.

---

## Project facts
- [2026-11-11] (claude) QUAICU Kernel: a fail-closed AI governance kernel (hexagonal ports/adapters). One Python package, `quaicu`: `quaicu/core` (governance logic, no I/O dependencies), `quaicu/adapters` (port implementations, chosen by configuration), `quaicu/delivery` (SDK, REST API, MCP server, witness service). Entry points: `from quaicu import Kernel`, `Kernel.local(policies=…)`, and the `quaicu init|serve|version` command (`quaicu/cli.py`).
- [2026-11-11] (claude) Install shape: the base install is `cel-python` + `cryptography` + `opentelemetry-api`; everything else is an extra (`server`, `postgres`, `gcp`, `aws`, `mcp`). `tests/unit/sdk/test_base_install.py` guards that importing the package does not pull in a web framework or a database driver. The `mcp` extra is pinned `<2` because the code targets the 1.x SDK.
- [2026-11-11] (claude) Checks before a change: `pip install -e ".[test,dev]"`, `python -m pytest -q`, `ruff check .` (the rule set is pinned in `pyproject.toml`). The Postgres conformance tests need `DATABASE_URL` and must connect as a non-superuser role, because PostgreSQL does not apply row-level security to superusers; CI and `docker/postgres-init.sql` create such a role.
- [2026-11-11] (claude) `quaicu serve` and the Docker image run one worker process: with the starter configuration, policies, approvals and the ledger live in that process's memory.

## Decisions
- [2026-11-11] (claude) Every `/v1` route is authenticated where routers are included (`quaicu/delivery/api/app.py`, `deps.authenticate`); `tests/unit/api/test_authentication.py` walks the OpenAPI paths to enforce it. The default identity adapter is `local_token` (shared `QUAICU_TOKEN` plus `X-Actor-Id` / `X-Actor-Roles`).
- [2026-11-11] (claude) The ledger files are frozen until the independent cryptographic review is complete: `quaicu/core/ledger/`, `quaicu/core/ports/anchor.py`, `quaicu/core/regmap/export.py`, `quaicu/adapters/ledger/`, `quaicu/delivery/witness_app.py` (`docs/operations/K02_REVIEW_PACKAGE.md`). Changes there need the maintainers' sign-off.

- [2026-11-11] (claude) Prompt injection is contained, not detected: policies see session provenance (`session_tainted` etc., from `Actor.attributes["quaicu.session"]`) and structured payloads; MCP approvals execute on the agent's retry. See `docs/adr/0013-injection-aware-policy-inputs.md`.

- [2026-11-12] (claude) Tool gateway (`quaicu gateway`, ADR-0014): `[tools]` rules in kernel.toml compile into activated CEL policies on action type `tool.<server>.<tool>` (`quaicu/core/toolgate/`); runtime in `quaicu/delivery/toolgate/`; live admin at `/v1/tools` (served in the gateway's process with `--admin-port`). Default deny; the AI gets no approval/admin tools.

## Handoffs / open threads
- [2026-11-11] (claude) Initial open-source release (0.1.0, unreleased: no version tag, nothing on PyPI, no published Docker image). Verified before publishing: 996 passed / 36 skipped without a database; 1024 passed / 8 skipped against PostgreSQL 16 as a non-superuser role (the 8 need OpenBao or a cloud KMS).
- [2026-11-11] (claude) Known limitations are listed in `SECURITY.md` (what the ledger proof does and does not show; the default signing key does not survive a restart).

- [2026-11-11] (claude) Red-team cases live in `tests/adversarial/test_prompt_injection.py`; add a case there for each new injection path. Open: provenance and the MCP retry index are per-process memory (a restart means a clean session and a fresh approval); a multi-tenant proxy tracks provenance only if its `ProxySession` carries one.

- [2026-11-12] (claude) Tool gateway follow-ups not built: HTTP MCP transport for remote agents, plain REST tools, per-rule rate limits, persisting live rule changes (today they last until restart; `GET /v1/tools/rules?format=toml` exports them).

## Scratch
