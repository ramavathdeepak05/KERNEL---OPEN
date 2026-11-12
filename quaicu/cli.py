"""The ``quaicu`` command — run the kernel as a local HTTP service.

    quaicu init                 write a starter kernel.toml into the current directory
    quaicu serve                serve the REST API from kernel.toml on 127.0.0.1:7000
    quaicu gateway              serve the AI's tools over MCP (stdio), governed by [tools]
    quaicu version              print the installed version

``serve`` needs the ``server`` extra (from a checkout: ``pip install ".[server]"``).

The API authenticates every request. With the default ``local_token`` identity adapter the caller
presents one shared token, taken from ``QUAICU_TOKEN``. If that variable is unset, ``serve``
generates a token for this run and prints it, so the service is never reachable without one.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from importlib import resources
from pathlib import Path

from quaicu import __version__
from quaicu.adapters.identity.local_token import MIN_TOKEN_LENGTH, TOKEN_ENV

DEFAULT_CONFIG = "kernel.toml"
CONFIG_ENV = "KERNEL_CONFIG"


def _starter_config() -> str:
    return resources.files("quaicu").joinpath("templates/kernel.toml").read_text(encoding="utf-8")


def cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if target.exists() and not args.force:
        print(f"{target} already exists; leaving it untouched (use --force to overwrite).", file=sys.stderr)
        return 1
    target.write_text(_starter_config(), encoding="utf-8")
    print(f"Wrote {target}. Edit the policies in it, then run: quaicu serve")
    return 0


def _uses_local_token(config_path: Path) -> bool:
    import tomllib

    with open(config_path, "rb") as f:
        config = tomllib.load(f)
    return config.get("adapters", {}).get("identity") == "local_token"


def _ensure_token(config_path: Path, *, announce) -> bool:
    """With the local_token identity adapter, make sure QUAICU_TOKEN is set: generate one for this
    run when it is unset (printing it to ``announce``, or not at all when that is None). Returns
    False when the token is set but too short."""
    if not _uses_local_token(config_path):
        return True
    token = os.getenv(TOKEN_ENV, "").strip()
    if not token:
        token = secrets.token_urlsafe(32)
        os.environ[TOKEN_ENV] = token
        if announce is not None:
            print(
                f"{TOKEN_ENV} is not set, so a token was generated for this run:\n\n"
                f"    {token}\n\n"
                f"Callers must send it as `Authorization: Bearer <token>`. Set {TOKEN_ENV} yourself "
                "to keep the same token across restarts.",
                file=announce,
                flush=True,
            )
    elif len(token) < MIN_TOKEN_LENGTH:
        print(f"{TOKEN_ENV} must be at least {MIN_TOKEN_LENGTH} characters.", file=sys.stderr)
        return False
    return True


def cmd_gateway(args: argparse.Namespace) -> int:
    config_path = Path(args.config or os.getenv(CONFIG_ENV) or DEFAULT_CONFIG)
    if not config_path.is_file():
        print(f"No kernel config at {config_path}. Add a [tools] section to it (see README).", file=sys.stderr)
        return 2
    try:
        import mcp  # noqa: F401
    except ImportError:
        print('The tool gateway needs the "mcp" extra. From a checkout: pip install ".[mcp]"', file=sys.stderr)
        return 2
    if args.admin_port:
        try:
            import uvicorn  # noqa: F401
        except ImportError:
            print('The admin API needs the "server" extra: pip install ".[mcp,server]"', file=sys.stderr)
            return 2
    # stdout is the MCP channel: anything for a person goes to stderr.
    if not _ensure_token(config_path, announce=sys.stderr if args.admin_port else None):
        return 2
    from quaicu.delivery.toolgate.runner import main as run

    return run(str(config_path), admin_port=args.admin_port, admin_host=args.admin_host)


def cmd_serve(args: argparse.Namespace) -> int:
    config_path = Path(args.config or os.getenv(CONFIG_ENV) or DEFAULT_CONFIG)
    if not config_path.is_file():
        print(
            f"No kernel config at {config_path}. Create one with `quaicu init`, "
            f"or point --config (or {CONFIG_ENV}) at an existing file.",
            file=sys.stderr,
        )
        return 2
    try:
        import uvicorn
    except ImportError:
        print(
            'The HTTP server needs the "server" extra. From a checkout: pip install ".[server]"',
            file=sys.stderr,
        )
        return 2

    os.environ[CONFIG_ENV] = str(config_path)

    if not _ensure_token(config_path, announce=sys.stdout):
        return 2

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"Listening on {args.host}: the API is reachable from other machines unless your "
            "network or container setup restricts it. Anyone who holds the token can act as any user.",
            flush=True,
        )
    print(f"QUAICU kernel on http://{args.host}:{args.port}  (API docs at /docs)", flush=True)
    uvicorn.run("quaicu.delivery.entrypoint:app", host=args.host, port=args.port, workers=1)
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="quaicu", description="Run the QUAICU governance kernel locally.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="write a starter kernel.toml")
    init.add_argument("path", nargs="?", default=DEFAULT_CONFIG, help="where to write it (default: kernel.toml)")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    init.set_defaults(func=cmd_init)

    serve = sub.add_parser("serve", help="serve the REST API")
    serve.add_argument("--config", help=f"kernel config file (default: ${CONFIG_ENV} or ./kernel.toml)")
    serve.add_argument("--host", default=os.getenv("KERNEL_HOST", "127.0.0.1"), help="bind address (default: 127.0.0.1)")
    serve.add_argument("--port", type=int, default=int(os.getenv("KERNEL_PORT", "7000")), help="port (default: 7000)")
    serve.set_defaults(func=cmd_serve)

    gateway = sub.add_parser(
        "gateway",
        help="serve the AI's tools over MCP (stdio), every call governed by the [tools] rules",
    )
    gateway.add_argument("--config", help=f"kernel config file (default: ${CONFIG_ENV} or ./kernel.toml)")
    gateway.add_argument(
        "--admin-port", type=int, default=None,
        help="also serve the REST API (approvals, /v1/tools) on this port, for people",
    )
    gateway.add_argument("--admin-host", default="127.0.0.1", help="admin API bind address (default: 127.0.0.1)")
    gateway.set_defaults(func=cmd_gateway)

    version = sub.add_parser("version", help="print the version")
    version.set_defaults(func=cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
