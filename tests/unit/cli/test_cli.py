"""The `quaicu` command: init / serve / version."""

from __future__ import annotations

import pytest

from quaicu import __version__, cli
from quaicu.adapters.identity.local_token import TOKEN_ENV


@pytest.fixture
def served(monkeypatch):
    """Capture the uvicorn.run call instead of binding a port."""
    import uvicorn

    calls: list[dict] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append({"app": app, **kwargs}))
    return calls


def test_version(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == __version__


def test_init_writes_a_starter_config_that_loads(tmp_path, monkeypatch):
    from quaicu import Kernel

    target = tmp_path / "kernel.toml"
    assert cli.main(["init", str(target)]) == 0
    monkeypatch.setenv(TOKEN_ENV, "local-token-0123456789abcdef")
    kernel = Kernel.from_config(target)
    assert str(kernel.tenant) == "local" and kernel.has_identity and kernel.has_policy_store


def test_init_does_not_overwrite_without_force(tmp_path, capsys):
    target = tmp_path / "kernel.toml"
    target.write_text("# mine\n", encoding="utf-8")
    assert cli.main(["init", str(target)]) == 1
    assert target.read_text(encoding="utf-8") == "# mine\n"
    assert cli.main(["init", str(target), "--force"]) == 0
    assert "[adapters]" in target.read_text(encoding="utf-8")
    assert "already exists" in capsys.readouterr().err


def test_serve_without_a_config_explains_what_to_do(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KERNEL_CONFIG", raising=False)
    assert cli.main(["serve"]) == 2
    assert "quaicu init" in capsys.readouterr().err
    assert served == []


def test_serve_generates_a_token_when_none_is_set(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    monkeypatch.delenv("KERNEL_CONFIG", raising=False)
    cli.main(["init"])
    assert cli.main(["serve"]) == 0
    import os

    token = os.environ[TOKEN_ENV]
    out = capsys.readouterr().out
    assert len(token) >= 32 and token in out  # generated, and shown to the operator once
    assert served == [
        {"app": "quaicu.delivery.entrypoint:app", "host": "127.0.0.1", "port": 7000, "workers": 1}
    ]
    assert os.environ["KERNEL_CONFIG"].endswith("kernel.toml")


def test_serve_keeps_a_token_the_operator_set(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(TOKEN_ENV, "operator-chosen-token-0123456789")
    cli.main(["init"])
    assert cli.main(["serve", "--port", "7123"]) == 0
    import os

    assert os.environ[TOKEN_ENV] == "operator-chosen-token-0123456789"
    assert "operator-chosen-token" not in capsys.readouterr().out  # never echoed
    assert served[0]["port"] == 7123


def test_serve_refuses_a_token_that_is_too_short(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(TOKEN_ENV, "short")
    cli.main(["init"])
    assert cli.main(["serve"]) == 2
    assert served == []


def test_serve_warns_when_bound_beyond_localhost(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(TOKEN_ENV, "operator-chosen-token-0123456789")
    cli.main(["init"])
    assert cli.main(["serve", "--host", "0.0.0.0"]) == 0
    assert "reachable from other machines" in capsys.readouterr().out
    assert served[0]["host"] == "0.0.0.0"
