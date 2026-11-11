# QUAICU Governance Kernel — local HTTP service image.
#
# Build from the repository root:
#   docker build -f docker/Dockerfile -t quaicu-kernel:local .
#
# or just use docker/docker-compose.yml.
#
# The image serves the REST API on port 7000 from /app/kernel.toml. The baked-in config is the
# starter one (`quaicu init`): in-memory, no external services. Mount your own over it to change
# policies or switch to the Postgres adapters.

# ── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Reproducible install: requirements.lock pins every runtime dependency with hashes. Copy only the
# lock first so this layer is cached until the lock changes.
COPY requirements.lock ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --require-hashes -r requirements.lock

# Then the package itself. --no-deps: dependencies are already pinned from the lock above.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY quaicu ./quaicu
RUN pip install --no-cache-dir --no-deps .

# ── Stage 2: runtime (non-root, minimal) ─────────────────────────────────────
FROM python:3.12-slim AS runtime

RUN groupadd -r kernel && useradd -r -g kernel kernel

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/quaicu /usr/local/bin/uvicorn /usr/local/bin/alembic /usr/local/bin/

WORKDIR /app
RUN quaicu init /app/kernel.toml

USER kernel

EXPOSE 7000

ENV KERNEL_CONFIG=/app/kernel.toml

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7000/health')"

# One worker: the starter config keeps actions, approvals and the ledger in this process's memory.
# Binds 0.0.0.0 inside the container; publish the port on 127.0.0.1 (as the compose file does) to
# keep it private to your machine.
CMD ["quaicu", "serve", "--host", "0.0.0.0", "--port", "7000"]
