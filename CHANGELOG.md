# Changelog

All notable changes to the QUAICU Kernel are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); the project aims for [SemVer](https://semver.org/).

## [0.1.0] — unreleased

First open-source release: the governance kernel on its own, to run locally.

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
