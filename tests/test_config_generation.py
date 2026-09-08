"""Contract tests joining generated launch argv to the CLI parser."""
from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp import cli
from ida_pro_mcp.installer import config
from ida_pro_mcp.runtime_args import build_serve_argv
from ida_pro_mcp.spawner import IdatNotFoundError


def test_stdio_config_uses_explicit_serve_subcommand(monkeypatch):
    monkeypatch.setattr(config, "get_python_executable", lambda: "/python")
    rendered = config.build_mcp_config(ida_home="/ida")
    assert rendered["args"] == [str(config.SERVER_ENTRY_PY), "serve"]


def test_unsafe_stdio_config_round_trips_through_cli_parser(monkeypatch):
    monkeypatch.setattr(config, "get_python_executable", lambda: "/python")
    rendered = config.build_mcp_config(unsafe=True, ida_home="/ida")
    argv = rendered["args"][1:]
    parsed = cli._build_arg_parser().parse_args(argv)
    assert parsed.cmd == "serve"
    assert parsed.transport == "stdio"
    assert parsed.unsafe is True


def test_http_service_argv_round_trips_through_cli_parser():
    argv = build_serve_argv(
        transport="streamable-http",
        host="127.0.0.1",
        port=13337,
        unsafe=True,
    )
    parsed = cli._build_arg_parser().parse_args(argv)
    assert parsed.cmd == "serve"
    assert parsed.transport == "streamable-http"
    assert parsed.host == "127.0.0.1"
    assert parsed.port == 13337
    assert parsed.unsafe is True


def test_explicit_ida_home_is_baked_into_stdio_config(monkeypatch):
    monkeypatch.setattr(config, "get_python_executable", lambda: "/python")
    rendered = config.build_mcp_config(ida_home="/opt/ida")
    assert rendered["env"]["IDA_PRO_HOME"] == "/opt/ida"


def test_print_config_validates_explicit_ida_home_before_rendering(monkeypatch, capsys):
    validated: list[str] = []
    monkeypatch.setattr(config, "collect_python_env", lambda: {})
    monkeypatch.setattr(config, "get_python_executable", lambda: "/python")
    monkeypatch.setattr(
        config,
        "locate_idat_in_home",
        lambda home: validated.append(home) or Path(home) / "idat",
    )

    config.print_mcp_config(ida_home="/opt/ida")

    assert validated == ["/opt/ida"]
    assert '"IDA_PRO_HOME": "/opt/ida"' in capsys.readouterr().out


def test_print_config_rejects_invalid_explicit_ida_home(monkeypatch, capsys):
    monkeypatch.setattr(config, "collect_python_env", lambda: {})

    def reject(_home: str):
        raise IdatNotFoundError("invalid IDA directory")

    monkeypatch.setattr(config, "locate_idat_in_home", reject)

    with pytest.raises(IdatNotFoundError, match="invalid IDA directory"):
        config.print_mcp_config(ida_home="/missing/ida")
    assert capsys.readouterr().out == ""


def test_print_config_validates_environment_ida_home(monkeypatch):
    validated: list[str] = []
    monkeypatch.setenv("IDA_PRO_HOME", "/env/ida")
    monkeypatch.setattr(config, "collect_python_env", lambda: {})
    monkeypatch.setattr(config, "get_python_executable", lambda: "/python")
    monkeypatch.setattr(
        config,
        "locate_idat_in_home",
        lambda home: validated.append(home) or Path(home) / "idat",
    )

    config.print_mcp_config()

    assert validated == ["/env/ida"]
