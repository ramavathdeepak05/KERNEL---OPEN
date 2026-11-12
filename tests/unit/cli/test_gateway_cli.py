"""`quaicu gateway`: refuses to start on a missing or invalid config, and never writes to stdout
(stdout is the MCP channel)."""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from quaicu import cli  # noqa: E402
from quaicu.adapters.identity.local_token import TOKEN_ENV  # noqa: E402
from tests.unit.toolgate.helpers import CONFIG  # noqa: E402


def test_gateway_without_a_config_explains_what_to_do(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KERNEL_CONFIG", raising=False)
    assert cli.main(["gateway"]) == 2
    out = capsys.readouterr()
    assert out.out == "" and "No kernel config" in out.err


def test_gateway_refuses_an_invalid_tools_section(tmp_path, monkeypatch, capsys):
    path = tmp_path / "kernel.toml"
    path.write_text(CONFIG.replace('decision = "deny"', 'decision = "nope"'), encoding="utf-8")
    monkeypatch.setenv(TOKEN_ENV, "t" * 32)
    assert cli.main(["gateway", "--config", str(path)]) == 2
    out = capsys.readouterr()
    assert out.out == "" and "Invalid [tools] configuration" in out.err


def test_gateway_runs_with_a_valid_config(tmp_path, monkeypatch, capsys):
    path = tmp_path / "kernel.toml"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    seen: dict = {}

    def fake_run(config_path, *, admin_port, admin_host):
        import os

        seen.update(config=config_path, port=admin_port, host=admin_host, token=os.environ.get(TOKEN_ENV))
        return 0

    import quaicu.delivery.toolgate.runner as runner

    monkeypatch.setattr(runner, "main", fake_run)
    assert cli.main(["gateway", "--config", str(path), "--admin-port", "7071"]) == 0
    out = capsys.readouterr()
    assert seen["port"] == 7071 and seen["host"] == "127.0.0.1" and seen["token"]
    assert out.out == ""  # the generated admin token goes to stderr, never into the MCP stream
    assert seen["token"] in out.err
