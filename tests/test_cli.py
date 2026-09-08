"""CLI subcommand tests for ``ida-pro-mcp-headless`` (cli.main).

The MCP loop is never exercised here: ``print_mcp_config`` and
``build_mcp_server`` are stubbed so each test asserts exactly which
side effect ``main`` triggered for a given argv.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ida_pro_mcp import cli
from ida_pro_mcp.session_control import CloseOutcome


@pytest.fixture()
def stub_actions(monkeypatch):
    """Replace ``main``'s side-effecting hooks with in-memory recorders.

    ``config`` is the only terminal subcommand that early-returns from
    ``main`` after talking to the installer; capturing it is sufficient.
    The server-loop code path never runs in these tests.
    """
    calls: dict[str, list[object]] = {"config": []}

    def _config(
        *,
        unsafe: bool = False,
        transport: str = "stdio",
        host: str = "127.0.0.1",
        port: int = 13337,
        ida_home: str | None = None,
    ):
        calls["config"].append({
            "unsafe": unsafe,
            "transport": transport,
            "host": host,
            "port": port,
            "ida_home": ida_home,
        })

    monkeypatch.setattr(cli, "print_mcp_config", _config)
    return calls


@pytest.fixture()
def stub_service(monkeypatch):
    """Capture ``service`` dispatcher calls without touching the OS service framework."""
    calls: dict[str, list[object]] = {
        "install": [],
        "uninstall": [],
        "status": [],
    }

    def _install(*, transport: str, host: str, port: int, unsafe: bool, ida_home):
        calls["install"].append({
            "transport": transport, "host": host, "port": port,
            "unsafe": unsafe, "ida_home": ida_home,
        })
        return {"task_name": "ida-pro-mcp-headless", "url": f"http://{host}:{port}/mcp"}

    def _uninstall():
        calls["uninstall"].append(True)
        return {"task_name": "ida-pro-mcp-headless"}

    def _status():
        calls["status"].append(True)
        return {"installed": True, "task_name": "ida-pro-mcp-headless", "status": "Running"}

    monkeypatch.setattr(cli, "install_service", _install)
    monkeypatch.setattr(cli, "uninstall_service", _uninstall)
    monkeypatch.setattr(cli, "service_status", _status)
    return calls


@pytest.fixture()
def stub_session(monkeypatch):
    """Capture ``session`` actions without touching real IDA processes."""
    calls: dict[str, list[object]] = {"close": [], "live": [], "resolve": []}

    class _FakeInfo:
        def __init__(self, session_id: str) -> None:
            self._session_id = session_id

        def to_dict(self) -> dict[str, object]:
            return {"session_id": self._session_id, "port": 12345}

    def _live_ids():
        calls["live"].append(True)
        return ["alpha", "beta"]

    def _live_sessions():
        calls["live"].append(True)
        return [_FakeInfo("alpha"), _FakeInfo("beta")]

    def _resolve(*, session_ids=(), paths=()):
        calls["resolve"].append({"ids": list(session_ids), "paths": list(paths)})
        return [*session_ids, *(f"id-of:{path}" for path in paths)]

    def _close(ids, *, timeout=None):
        calls["close"].append({"ids": list(ids), "timeout": timeout})
        return [CloseOutcome(item, closed=True, graceful=True) for item in ids]

    monkeypatch.setattr(cli, "live_session_ids", _live_ids)
    monkeypatch.setattr(cli, "live_sessions", _live_sessions)
    monkeypatch.setattr(cli, "resolve_targets", _resolve)
    monkeypatch.setattr(cli, "close_sessions", _close)
    return calls


@pytest.fixture()
def stub_runtime(monkeypatch):
    """Stub the long-lived components ``main`` constructs in non-config paths.

    Captures whatever ``--transport`` / ``--host`` / ``--port`` ended up
    flowing into FastMCP without actually starting an event loop.
    """
    captured: dict[str, object] = {}

    class _FakeMCP:
        def __init__(self):
            self.settings = SimpleNamespace(host=None, port=None)

        def run(self, *, transport: str) -> None:
            captured["transport"] = transport
            captured["settings_host"] = self.settings.host
            captured["settings_port"] = self.settings.port

    def _build(*_args, **_kwargs):
        captured["build_host"] = _kwargs["host"]
        captured["build_port"] = _kwargs["port"]
        return _FakeMCP()

    monkeypatch.setattr(cli, "SessionRegistry", lambda: object())
    monkeypatch.setattr(cli, "Spawner", lambda: object())
    monkeypatch.setattr(cli, "build_mcp_server", _build)
    return captured


class TestConfigSubcommand:
    def test_config_prints_config(self, stub_actions):
        cli.main(["config"])
        assert stub_actions["config"] == [{
            "unsafe": False, "transport": "stdio",
            "host": "127.0.0.1", "port": 13337, "ida_home": None,
        }]

    def test_config_unsafe_propagates(self, stub_actions):
        cli.main(["config", "--unsafe"])
        assert stub_actions["config"] == [{
            "unsafe": True, "transport": "stdio",
            "host": "127.0.0.1", "port": 13337, "ida_home": None,
        }]

    def test_config_with_remote_transport_propagates(self, stub_actions):
        cli.main([
            "config",
            "--transport", "streamable-http",
            "--host", "10.0.0.1",
            "--port", "1337",
        ])
        assert stub_actions["config"] == [{
            "unsafe": False,
            "transport": "streamable-http",
            "host": "10.0.0.1",
            "port": 1337,
            "ida_home": None,
        }]

    def test_config_ida_home_propagates(self, stub_actions):
        cli.main(["config", "--ida-home", r"C:\IDA"])
        assert stub_actions["config"][0]["ida_home"] == r"C:\IDA"

    def test_invalid_ida_home_is_reported_without_traceback(self, monkeypatch, capsys):
        from ida_pro_mcp.spawner import IdatNotFoundError

        def _fail(**_kwargs):
            raise IdatNotFoundError("missing idat.exe")

        monkeypatch.setattr(cli, "print_mcp_config", _fail)
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["config", "--ida-home", r"C:\missing-ida"])

        assert exc_info.value.code == 2
        assert capsys.readouterr().err == "error: missing idat.exe\n"


class TestServeSubcommand:
    """``serve`` (default) starts the proxy with the requested transport."""

    def test_default_is_stdio_no_host_port_applied(self, stub_runtime):
        cli.main(["serve"])
        assert stub_runtime["transport"] == "stdio"
        # HTTP-only flags are ignored under stdio, so construction uses the
        # canonical defaults even if the parser carries host/port attributes.
        assert stub_runtime["build_host"] == "127.0.0.1"
        assert stub_runtime["build_port"] == 13337

    def test_implicit_serve_when_no_subcommand(self, stub_runtime):
        # ``ida-pro-mcp-headless`` with no args must still spin up the proxy --
        # this is the historical default behaviour the README depends on.
        cli.main([])
        assert stub_runtime["transport"] == "stdio"

    def test_streamable_http_applies_host_and_port(self, stub_runtime):
        cli.main(["serve", "--transport", "streamable-http"])
        assert stub_runtime["transport"] == "streamable-http"
        assert stub_runtime["build_host"] == "127.0.0.1"
        assert stub_runtime["build_port"] == 13337

    def test_explicit_host_and_port_override_defaults(self, stub_runtime):
        cli.main([
            "serve",
            "--transport", "sse",
            "--host", "192.168.1.50",
            "--port", "9000",
        ])
        assert stub_runtime["transport"] == "sse"
        assert stub_runtime["build_host"] == "192.168.1.50"
        assert stub_runtime["build_port"] == 9000

    def test_invalid_transport_rejected(self, stub_runtime):
        with pytest.raises(SystemExit):
            cli.main(["serve", "--transport", "tcp"])

    @pytest.mark.parametrize("bad_port", ["0", "65536", "abc", "-1"])
    def test_invalid_port_rejected(self, stub_runtime, bad_port):
        with pytest.raises(SystemExit):
            cli.main(["serve", "--transport", "streamable-http", "--port", bad_port])


class TestRetiredFlagAliases:
    """Plugin-install paths are gone; argparse must reject the old subcommands and flags."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["install"],
            ["uninstall"],
            ["--install"],
            ["--uninstall"],
            ["--config"],
            ["--service"],
            ["--install-plugin"],
            ["--uninstall-plugin"],
        ],
    )
    def test_legacy_subcommand_rejected(self, stub_actions, capsys, argv):
        with pytest.raises(SystemExit):
            cli.main(argv)
        err = capsys.readouterr().err
        assert (
            "invalid choice" in err
            or "unrecognized arguments" in err
            or argv[0] in err
        )


class TestArgvDefault:
    def test_main_reads_sys_argv_when_argv_omitted(self, stub_actions, monkeypatch):
        """Calling ``main()`` with no argument must default to ``sys.argv[1:]``."""
        monkeypatch.setattr("sys.argv", ["ida-pro-mcp-headless", "config"])
        cli.main()
        assert len(stub_actions["config"]) == 1


class TestServiceSubcommand:
    """``service install/uninstall/status`` routes to the cross-platform installer."""

    def test_install_propagates_args(self, stub_service):
        cli.main([
            "service", "install",
            "--transport", "streamable-http",
            "--host", "127.0.0.1",
            "--port", "13337",
            "--unsafe",
            "--ida-home", r"C:\Program Files\IDA Professional 9.0",
        ])
        assert stub_service["install"] == [{
            "transport": "streamable-http",
            "host": "127.0.0.1",
            "port": 13337,
            "unsafe": True,
            "ida_home": r"C:\Program Files\IDA Professional 9.0",
        }]

    def test_install_defaults_to_streamable_http(self, stub_service):
        cli.main(["service", "install"])
        assert stub_service["install"][0]["transport"] == "streamable-http"

    def test_install_rejects_stdio_transport_at_parse_time(self, stub_service):
        with pytest.raises(SystemExit):
            cli.main(["service", "install", "--transport", "stdio"])
        assert stub_service["install"] == []

    def test_uninstall_invokes_uninstall(self, stub_service):
        cli.main(["service", "uninstall"])
        assert stub_service["uninstall"] == [True]

    def test_status_prints_json_to_stdout(self, stub_service, capsys):
        cli.main(["service", "status"])
        out = capsys.readouterr().out
        # The CLI must emit valid JSON so users can pipe it into ``jq``.
        import json as _json
        payload = _json.loads(out)
        assert payload["installed"] is True
        assert payload["task_name"] == "ida-pro-mcp-headless"

    def test_unsupported_platform_exits_with_code_2(self, stub_service, monkeypatch, capsys):
        from ida_pro_mcp.installer.service import ServiceUnsupportedError

        def _fail(**_kw):
            raise ServiceUnsupportedError("nice-explanation about systemd")

        monkeypatch.setattr(cli, "install_service", _fail)
        with pytest.raises(SystemExit) as exc_info:
            cli.main([
                "service", "install",
                "--transport", "streamable-http",
            ])
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "nice-explanation" in err

    def test_invalid_service_action_rejected_by_argparse(self, stub_service):
        with pytest.raises(SystemExit):
            cli.main(["service", "restart"])  # not in choices

    def test_missing_service_action_emits_helpful_error(self, stub_service):
        with pytest.raises(SystemExit, match="service install"):
            cli.main(["service"])

    def test_ida_home_default_is_none(self, stub_service):
        cli.main([
            "service", "install",
            "--transport", "streamable-http",
        ])
        assert stub_service["install"][0]["ida_home"] is None


class TestSessionSubcommand:
    """``session close`` lets a shell user reclaim IDAs the model left running."""

    def test_close_all_closes_every_live_session(self, stub_session, capsys):
        cli.main(["session", "close", "--all"])
        assert stub_session["close"] == [{"ids": ["alpha", "beta"], "timeout": None}]
        payload = json.loads(capsys.readouterr().out)
        assert [item["session_id"] for item in payload] == ["alpha", "beta"]
        assert all(item["closed"] for item in payload)

    def test_close_named_ids(self, stub_session, capsys):
        cli.main(["session", "close", "one", "two"])
        assert stub_session["resolve"] == [{"ids": ["one", "two"], "paths": []}]
        assert stub_session["close"] == [{"ids": ["one", "two"], "timeout": None}]
        assert stub_session["live"] == []

    def test_close_by_path_is_resolved_to_a_session_id(self, stub_session):
        cli.main(["session", "close", "--path", "/samples/crackme.exe"])
        assert stub_session["resolve"] == [
            {"ids": [], "paths": ["/samples/crackme.exe"]}
        ]
        assert stub_session["close"][0]["ids"] == ["id-of:/samples/crackme.exe"]

    def test_path_may_be_repeated(self, stub_session):
        cli.main(["session", "close", "--path", "a.bin", "--path", "b.bin"])
        assert stub_session["resolve"] == [
            {"ids": [], "paths": ["a.bin", "b.bin"]}
        ]

    def test_ids_and_paths_may_be_combined(self, stub_session):
        cli.main(["session", "close", "alpha", "--path", "b.bin"])
        assert stub_session["resolve"] == [{"ids": ["alpha"], "paths": ["b.bin"]}]

    def test_timeout_is_forwarded(self, stub_session):
        cli.main(["session", "close", "--all", "--timeout", "2.5"])
        assert stub_session["close"][0]["timeout"] == 2.5

    def test_force_maps_to_zero_timeout(self, stub_session):
        cli.main(["session", "close", "--all", "--force"])
        assert stub_session["close"][0]["timeout"] == 0.0

    def test_timeout_zero_is_accepted(self, stub_session):
        cli.main(["session", "close", "--all", "--timeout", "0"])
        assert stub_session["close"][0]["timeout"] == 0.0

    def test_force_and_timeout_are_mutually_exclusive(self, stub_session, capsys):
        with pytest.raises(SystemExit):
            cli.main(["session", "close", "--all", "--force", "--timeout", "5"])
        assert "not allowed with" in capsys.readouterr().err

    def test_close_all_without_sessions_prints_empty_list(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "live_session_ids", list)
        cli.main(["session", "close", "--all"])
        assert json.loads(capsys.readouterr().out) == []

    def test_no_targets_is_an_error(self, stub_session, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["session", "close"])
        assert exc_info.value.code == 2
        assert "specify at least one session id" in capsys.readouterr().err
        assert stub_session["close"] == []

    def test_all_with_ids_is_an_error(self, stub_session, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["session", "close", "--all", "alpha"])
        assert exc_info.value.code == 2
        assert "cannot be combined" in capsys.readouterr().err

    def test_all_with_path_is_an_error(self, stub_session, capsys):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["session", "close", "--all", "--path", "a.bin"])
        assert exc_info.value.code == 2
        assert "cannot be combined" in capsys.readouterr().err

    def test_partial_failure_exits_nonzero_but_reports_every_target(
        self, monkeypatch, capsys
    ):
        def _close(ids, *, timeout=None):
            return [
                CloseOutcome("alpha", closed=False, error="gone"),
                CloseOutcome("beta", closed=True, graceful=True),
            ]

        monkeypatch.setattr(cli, "close_sessions", _close)
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["session", "close", "alpha", "beta"])

        assert exc_info.value.code == 2
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert [item["closed"] for item in payload] == [False, True]
        assert "session alpha: gone" in captured.err

    def test_missing_action_is_an_error(self, stub_session):
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["session"])
        # ``SystemExit(str)`` carries the message on ``code``; the interpreter
        # would print it, but pytest intercepts the exit before that happens.
        assert "missing session action" in str(exc_info.value.code)

    @pytest.mark.parametrize("bad_timeout", ["-1", "abc"])
    def test_invalid_timeout_rejected(self, stub_session, bad_timeout):
        with pytest.raises(SystemExit):
            cli.main(["session", "close", "--all", "--timeout", bad_timeout])


class TestSessionListSubcommand:
    """``session list`` prints the live sessions for use with ``session close``."""

    def test_prints_every_live_session_as_json(self, stub_session, capsys):
        cli.main(["session", "list"])
        payload = json.loads(capsys.readouterr().out)
        assert payload == [
            {"session_id": "alpha", "port": 12345},
            {"session_id": "beta", "port": 12345},
        ]

    def test_empty_when_nothing_runs(self, monkeypatch, capsys):
        monkeypatch.setattr(cli, "live_sessions", list)
        cli.main(["session", "list"])
        assert json.loads(capsys.readouterr().out) == []


class TestHelp:
    def test_top_level_help_lists_subcommands(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        out = capsys.readouterr().out
        assert "config" in out
        assert "serve" in out
        assert "service" in out
        # The plugin-install subcommands are gone after the headless-only
        # refactor: argparse renders the choices as ``{serve,config,service}``
        # in the usage line. Assert the legacy entries are absent there.
        usage_section = "\n".join(out.splitlines()[:5])
        assert "install," not in usage_section
        assert "uninstall," not in usage_section

    def test_serve_help_shows_transport_flags(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["serve", "--help"])
        out = capsys.readouterr().out
        assert "--transport" in out
        assert "--host" in out
        assert "--port" in out
        assert "--unsafe" in out

    def test_service_install_help_shows_ida_home(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["service", "install", "--help"])
        out = capsys.readouterr().out
        normalized = " ".join(out.split())
        assert "--ida-home" in out
        assert "default: streamable-http" in normalized
        assert "'stdio' runs" not in out

    def test_help_does_not_mention_retired_aliases(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        out = capsys.readouterr().out
        assert "--install-plugin" not in out
        assert "--uninstall-plugin" not in out
        assert "--bootstrap-ida-python" not in out
