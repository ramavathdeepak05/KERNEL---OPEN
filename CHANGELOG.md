# Changelog

All notable changes to the QUAICU Kernel are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); the project aims for [SemVer](https://semver.org/).

## [0.1.0] — unreleased

First open-source release: the governance kernel on its own, to run locally.

### Prompt-injection containment (ADR-0013)
- **Session provenance.** The MCP proxy and server record which untrusted tools a session has read;
  policies see `session_tracked`, `session_tainted` and `session_sources`. New `agent-egress` policy
  pack.
- **Structured policy inputs.** Lists and objects in a payload reach CEL as lists and maps (they were
  `repr` strings), the whole payload is the map `payload`, and a list macro applied to a payload
  string now denies instead of iterating its characters.
- **MCP approvals work.** After a human approves, the agent's retry of the same call runs it once and
  returns the result. Previously the tool never ran.
- **MCP proxy:** tool definitions are pinned when first listed (a changed tool is hidden and blocked),
  `allowed_tools` and `tool_policies` config, structured tool output is forwarded (tools with an
  `outputSchema` used to come back as errors although they had run), and downstream errors stay errors.
- **SDK:** `guard`, `wrap`, `governed` and `governed_tool` give policies positional arguments too;
  `kernel.proxy` gives policies the call's arguments.
- **Docs:** SECURITY.md describes what the kernel does and does not do against prompt injection.

### What is in it
- **`from quaicu import Kernel`** — one package, `quaicu`, with the public API at the top level.
- **`Kernel.local(policies=...)`** — a complete in-process kernel in one call: CEL policy engine,
  approvals queue, signed in-memory ledger. No external services.
- **`quaicu` command** — `quaicu init` writes a starter `kernel.toml`; `quaicu serve` runs the REST
  API on 127.0.0.1 and generates a token for the run if `QUAICU_TOKEN` is unset.
- **`local_token` identity adapter** — one shared token; the calling product names the acting user
  in `X-Actor-Id` / `X-Actor-Roles`. No accounts, no signup. JWT and OIDC adapters are included for
  products that already have an identity provider.
- **Every `/v1` route authenticates the caller** through the identity adapter, attached where
  routers are included.
- **Small base install** — `pip install .` needs only `cel-python`, `cryptography` and
  `opentelemetry-api`. The HTTP service is the `server` extra; PostgreSQL is the `postgres` extra.
- **Policy packs ship inside the package** (`quaicu/policy_packs/`) and are imported scoped to the
  kernel's tenant.
- **Docker** — `docker/docker-compose.yml` (no external services) and
  `docker/docker-compose.postgres.yml` (durable storage), both published on 127.0.0.1 only.
- **Examples** — `examples/quickstart.py`, `examples/http_walkthrough.py`, and three longer demos,
  all exercised by the test suite.
- Licensed under **Apache-2.0**.
