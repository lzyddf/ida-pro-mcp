"""End-to-end tests for the FastMCP bridge."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ida_pro_mcp._tool_bridge import (
    Backend,
    register_local_tools,
    register_remote_tools,
)
from ida_pro_mcp.plugin import session


def _build_bridged_mcp(*, include_unsafe: bool):
    mcp = FastMCP("test", log_level="ERROR")
    seen: list[tuple[str, dict, str | None]] = []

    def fake_dispatch(name: str, kwargs: dict, session_id: str | None):
        seen.append((name, kwargs, session_id))
        return f"called {name}"

    names = register_remote_tools(mcp, dispatch=fake_dispatch, include_unsafe=include_unsafe)
    return mcp, names, seen


def _list_tools(mcp: FastMCP):
    return asyncio.run(mcp.list_tools())


def test_safe_only_excludes_unsafe():
    _, names, _ = _build_bridged_mcp(include_unsafe=False)
    assert "patch_address_assembles" not in names
    assert "dbg_set_breakpoint" not in names
    assert "get_metadata" in names


def test_include_unsafe_registers_everything():
    _, names_safe, _ = _build_bridged_mcp(include_unsafe=False)
    _, names_all, _ = _build_bridged_mcp(include_unsafe=True)
    assert set(names_safe) <= set(names_all)
    assert len(names_all) > len(names_safe)


def test_descriptions_propagate_to_schema():
    mcp, _, _ = _build_bridged_mcp(include_unsafe=True)
    tools = {t.name: t for t in _list_tools(mcp)}
    schema = tools["read_value"].inputSchema
    # AddressParam description is shared via params.py; just sanity-check it
    # describes a hex address rather than asserting the exact text.
    address_desc = schema["properties"]["address"]["description"].lower()
    assert "hex" in address_desc and "address" in address_desc
    assert schema["properties"]["kind"]["enum"] == [
        "byte", "word", "dword", "qword", "string",
    ]


def test_simplified_remote_signatures_are_reflected_in_schema():
    mcp, names, _ = _build_bridged_mcp(include_unsafe=True)
    tools = {tool.name: tool for tool in _list_tools(mcp)}

    assert {
        "get_function_by_name",
        "get_function_by_address",
        "get_current_address",
        "get_current_function",
        "data_read",
    }.isdisjoint(names)
    assert tools["get_function"].inputSchema["required"] == ["function"]
    assert tools["list_functions"].inputSchema.get("required", []) == []
    assert tools["get_global_variable_value"].inputSchema["required"] == ["target"]
    assert tools["read_bytes"].inputSchema["required"] == ["address", "size"]


def test_session_param_present_on_every_remote_tool():
    """Every bridged remote tool must accept the routing ``session`` kwarg."""
    mcp, _, _ = _build_bridged_mcp(include_unsafe=True)
    tools = {t.name: t for t in _list_tools(mcp)}
    assert tools, "fixture should register at least one remote tool"
    for name, tool in tools.items():
        props = tool.inputSchema["properties"]
        assert "session" in props, f"{name} lacks session param"
        # ``session`` must be optional -- never end up in ``required``.
        assert "session" not in tool.inputSchema.get("required", [])


def _dummy_backend(*, spawner=None) -> Backend:
    return Backend(
        dispatch=lambda *_a, **_k: None,
        list_sessions=lambda: [],
        spawner=spawner,
    )


def test_dispatch_routes_through_bridge():
    """Calling a proxy directly must hit the dispatch hook with kwargs intact."""
    from ida_pro_mcp._tool_bridge import _build_proxy
    from ida_pro_mcp.plugin import load_tools, rpc_registry

    load_tools()

    seen: list[tuple[str, dict, str | None]] = []

    def fake_dispatch(name: str, kwargs: dict, session_id: str | None):
        seen.append((name, kwargs, session_id))
        return "ok"

    proxy = _build_proxy(
        "get_function", rpc_registry.methods["get_function"], fake_dispatch
    )
    assert proxy(function="main") == "ok"
    assert seen == [("get_function", {"function": "main"}, None)]


def test_dispatch_passes_session_id_through():
    """``session`` kwarg must reach the dispatch hook and be stripped from kwargs."""
    from ida_pro_mcp._tool_bridge import _build_proxy
    from ida_pro_mcp.plugin import load_tools, rpc_registry

    load_tools()

    seen: list[tuple[str, dict, str | None]] = []

    def fake_dispatch(name: str, kwargs: dict, session_id: str | None):
        seen.append((name, kwargs, session_id))
        return "ok"

    proxy = _build_proxy(
        "get_function", rpc_registry.methods["get_function"], fake_dispatch
    )
    assert proxy(function="main", session="crackme-abcdef01") == "ok"
    assert seen == [("get_function", {"function": "main"}, "crackme-abcdef01")]


def test_dispatch_result_is_returned_verbatim():
    """The bridge must not transform values returned by *dispatch*.

    Void-marker substitution (``None`` -> ``{"ok": True}``) lives in
    :meth:`RPCRegistry.dispatch`, not in this proxy layer, so any client of
    the registry sees the same wire contract regardless of transport.
    """
    from ida_pro_mcp._tool_bridge import _build_proxy
    from ida_pro_mcp.plugin import load_tools, rpc_registry

    load_tools()

    def fake_dispatch(name: str, kwargs: dict, session_id: str | None):
        return "success\n\nInfo: parsed 1 type"

    proxy = _build_proxy(
        "declare_c_type", rpc_registry.methods["declare_c_type"], fake_dispatch
    )
    assert proxy(c_declaration="typedef int x;") == "success\n\nInfo: parsed 1 type"


def test_no_duplicate_registration():
    """Repeated registration must not silently shadow methods."""
    _, names, _ = _build_bridged_mcp(include_unsafe=True)
    assert len(names) == len(set(names))


def test_proxy_rejects_positional_invocation():
    from ida_pro_mcp._tool_bridge import _build_proxy
    from ida_pro_mcp.plugin import load_tools, rpc_registry

    load_tools()

    proxy = _build_proxy(
        "get_function",
        rpc_registry.methods["get_function"],
        lambda *_a, **_kw: None,
    )
    with pytest.raises(TypeError, match="positional"):
        proxy("main")


def test_local_tools_registered_from_specs():
    """Local tool registration is driven by the declarative tool specs."""
    mcp = FastMCP("test", log_level="ERROR")
    names = register_local_tools(mcp, backend=_dummy_backend())
    assert "check_connection" in names
    assert "list_ida_sessions" in names
    assert "convert_number" in names
    # Without a spawner, the open/close tools opt out and must not appear.
    assert "open_file" not in names
    assert "close_file" not in names


def test_open_close_registered_with_spawner():
    """When a spawner is provided, the AI-launch tools become available."""

    class _StubSpawner:
        DEFAULT_CLOSE_TIMEOUT_S = 30.0

        def open(self, *_a, **_k):  # pragma: no cover -- exercised via call below
            raise NotImplementedError

        def close(self, *_a, **_k):  # pragma: no cover
            raise NotImplementedError

    mcp = FastMCP("test", log_level="ERROR")
    names = register_local_tools(mcp, backend=_dummy_backend(spawner=_StubSpawner()))
    assert {"check_connection", "list_ida_sessions", "open_file", "close_file"} <= set(names)
    assert "reanalyse_file" not in names
    tools = {tool.name: tool for tool in _list_tools(mcp)}
    assert list(tools["open_file"].inputSchema["properties"]) == ["path"]
    assert tools["close_file"].inputSchema.get("required", []) == []
    assert list(tools["close_file"].inputSchema["properties"]) == ["session"]
    assert "session" not in tools["convert_number"].inputSchema["properties"]


def test_reanalyse_file_requires_unsafe_mode():
    class _StubSpawner:
        def open(self, *_a, **_k):
            raise NotImplementedError

        def close(self, *_a, **_k):
            raise NotImplementedError

    mcp = FastMCP("test", log_level="ERROR")
    names = register_local_tools(
        mcp,
        backend=_dummy_backend(spawner=_StubSpawner()),
        include_unsafe=True,
    )
    assert "reanalyse_file" in names


# --- list_ida_sessions / check_connection live tools ----------------------------


@pytest.fixture()
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


def test_list_ida_sessions_empty(isolate_sessions_dir: Path):
    """Empty list -- not an error -- when no IDA is running."""
    from ida_pro_mcp._tool_bridge import build_list_ida_sessions

    backend = Backend(dispatch=lambda *_a, **_k: None, list_sessions=lambda: [])
    assert build_list_ida_sessions(backend)() == []


def test_list_ida_sessions_returns_dicts():
    from ida_pro_mcp._tool_bridge import build_list_ida_sessions

    info = session.make_info(
        session_id="probe-deadbeef",
        host="127.0.0.1",
        port=1234,
        pid=os.getpid(),
        idb_path="/tmp/probe.i64",
        input_file="/tmp/probe",
        created_at=42.0,
    )
    backend = Backend(dispatch=lambda *_a, **_k: None, list_sessions=lambda: [info])
    payload = build_list_ida_sessions(backend)()
    assert payload[0]["session_id"] == "probe-deadbeef"
    assert payload[0]["port"] == 1234
    assert payload[0]["input_file"] == "/tmp/probe"


def test_check_connection_reports_open_file():
    from ida_pro_mcp._tool_bridge import build_check_connection

    def dispatch(method: str, params: dict, session_id: str | None) -> Any:
        assert method == "get_metadata"
        return {"module": "crackme.exe"}

    backend = Backend(dispatch=dispatch, list_sessions=lambda: [])
    assert "crackme.exe" in build_check_connection(backend)()


def test_check_connection_surfaces_no_session():
    from ida_pro_mcp._tool_bridge import build_check_connection
    from ida_pro_mcp.session_registry import SessionNotFoundError

    def dispatch(method: str, params: dict, session_id: str | None) -> Any:
        raise SessionNotFoundError(None)

    backend = Backend(dispatch=dispatch, list_sessions=lambda: [])
    text = build_check_connection(backend)()
    assert "No IDA session is running" in text


# --- open_file / close_file builders ---------------------------------------


def test_open_file_returns_payload_with_log_and_reused_flag():
    from dataclasses import dataclass

    from ida_pro_mcp._tool_bridge import build_open_file

    info = session.make_info(
        session_id="probe-abcdef01",
        host="127.0.0.1",
        port=1234,
        pid=os.getpid(),
        idb_path="/tmp/probe.i64",
        input_file="/tmp/probe",
        created_at=42.0,
    )

    @dataclass
    class _StubResult:
        session: session.SessionInfo
        log_file: str
        reused: bool

    class _StubSpawner:
        DEFAULT_CLOSE_TIMEOUT_S = 30.0

        def __init__(self) -> None:
            self.seen: dict = {}

        def open(self, path, *, fresh=False, timeout=None):
            self.seen.update(path=path, fresh=fresh, timeout=timeout)
            return _StubResult(session=info, log_file="/tmp/probe.ida.log", reused=False)

    spawner = _StubSpawner()
    backend = Backend(dispatch=lambda *_a, **_k: None, list_sessions=lambda: [], spawner=spawner)
    func = build_open_file(backend)
    assert func is not None
    payload = func("/tmp/probe")
    assert payload["session_id"] == "probe-abcdef01"
    assert payload["log_file"] == "/tmp/probe.ida.log"
    assert payload["reused"] is False
    assert spawner.seen == {"path": "/tmp/probe", "fresh": False, "timeout": None}


def test_reanalyse_file_requests_fresh_analysis():
    from dataclasses import dataclass

    from ida_pro_mcp._tool_bridge import build_reanalyse_file

    info = session.make_info(
        session_id="probe-abcdef01",
        host="127.0.0.1",
        port=1234,
        pid=os.getpid(),
        idb_path="/tmp/probe.i64",
        input_file="/tmp/probe",
        created_at=42.0,
    )

    @dataclass
    class _StubResult:
        session: session.SessionInfo
        log_file: str
        reused: bool

    class _StubSpawner:
        def __init__(self) -> None:
            self.fresh = False

        def open(self, path, *, fresh=False):
            assert path == "/tmp/probe"
            self.fresh = fresh
            return _StubResult(session=info, log_file="/tmp/probe.ida.log", reused=False)

    spawner = _StubSpawner()
    backend = Backend(dispatch=lambda *_a, **_k: None, list_sessions=lambda: [], spawner=spawner)
    func = build_reanalyse_file(backend)
    assert func is not None
    assert func("/tmp/probe")["session_id"] == "probe-abcdef01"
    assert spawner.fresh is True


def test_close_file_returns_graceful_flag():
    from ida_pro_mcp._tool_bridge import build_close_file

    class _StubSpawner:
        DEFAULT_CLOSE_TIMEOUT_S = 30.0

        def close(self, session_id):
            return True

    backend = Backend(
        dispatch=lambda *_a, **_k: None,
        list_sessions=lambda: [],
        spawner=_StubSpawner(),
    )
    func = build_close_file(backend)
    assert func is not None
    payload = func("probe-abcdef01")
    assert payload == {"session": "probe-abcdef01", "graceful": True}


def test_close_file_auto_selects_the_only_session():
    from ida_pro_mcp._tool_bridge import build_close_file

    info = session.make_info(
        session_id="only-abcdef01",
        host="127.0.0.1",
        port=1234,
        pid=os.getpid(),
        idb_path="/tmp/only.i64",
        input_file="/tmp/only",
        created_at=42.0,
    )

    class _StubSpawner:
        def __init__(self) -> None:
            self.closed: str | None = None

        def close(self, session_id):
            self.closed = session_id
            return True

    spawner = _StubSpawner()
    backend = Backend(
        dispatch=lambda *_a, **_k: None,
        list_sessions=lambda: [info],
        spawner=spawner,
    )
    func = build_close_file(backend)
    assert func is not None
    assert func() == {"session": "only-abcdef01", "graceful": True}
    assert spawner.closed == "only-abcdef01"


@pytest.mark.parametrize("session_count", [0, 2])
def test_close_file_requires_an_unambiguous_session(session_count: int):
    from ida_pro_mcp._tool_bridge import build_close_file
    from ida_pro_mcp.session_registry import SessionResolutionError

    sessions = [
        session.make_info(
            session_id=f"probe-{index}",
            host="127.0.0.1",
            port=1234 + index,
            pid=os.getpid(),
            idb_path=f"/tmp/probe-{index}.i64",
            input_file=f"/tmp/probe-{index}",
            created_at=42.0,
        )
        for index in range(session_count)
    ]

    class _StubSpawner:
        def close(self, session_id):  # pragma: no cover - resolution fails first
            raise AssertionError(session_id)

    backend = Backend(
        dispatch=lambda *_a, **_k: None,
        list_sessions=lambda: sessions,
        spawner=_StubSpawner(),
    )
    func = build_close_file(backend)
    assert func is not None
    with pytest.raises(SessionResolutionError):
        func()


def test_open_close_disabled_without_spawner():
    from ida_pro_mcp._tool_bridge import (
        build_close_file,
        build_open_file,
        build_reanalyse_file,
    )

    backend = Backend(dispatch=lambda *_a, **_k: None, list_sessions=lambda: [])
    assert build_open_file(backend) is None
    assert build_close_file(backend) is None
    assert build_reanalyse_file(backend) is None
