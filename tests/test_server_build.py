"""Tests for ``server.build_mcp_server``: end-to-end MCP assembly."""
from __future__ import annotations

import asyncio
import contextlib
import os
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from ida_pro_mcp.plugin import session
from ida_pro_mcp.plugin.http_server import Server
from ida_pro_mcp.plugin.registry import RPCRegistry
from ida_pro_mcp.server import build_mcp_server
from ida_pro_mcp.session_registry import SessionRegistry


def _list_tools(mcp):
    return asyncio.run(mcp.list_tools())


@pytest.fixture()
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


@contextlib.contextmanager
def _running_inproc_server() -> Iterator[Server]:
    """Spin up :class:`Server` on a worker thread and tear it down cleanly.

    The headless server runs ``serve_forever`` on the *calling* thread by
    design (so ``@idaread`` handlers can short-circuit ``execute_sync``);
    tests that just want a TCP listener wrap that in a daemon thread.
    """
    registry = RPCRegistry()

    def get_metadata() -> dict:
        return {"module": "fake.exe"}

    registry.register(get_metadata)
    server = Server(host="127.0.0.1", port=0, registry=registry)
    server.bind()
    thread = threading.Thread(target=server.serve_in_current_thread, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stop()
        thread.join(timeout=3)


def _publish_session(server: Server, session_id: str = "fake-deadbeef") -> session.SessionInfo:
    assert server.bound_port is not None
    info = session.make_info(
        session_id=session_id,
        host="127.0.0.1",
        port=server.bound_port,
        pid=os.getpid(),
        idb_path=f"/tmp/{session_id}.i64",
        input_file=f"/tmp/{session_id}",
    )
    session.write(info)
    return info


def test_check_connection_registered_per_server(isolate_sessions_dir: Path):
    with _running_inproc_server() as server:
        _publish_session(server)
        mcp = build_mcp_server(SessionRegistry(timeout=5), include_unsafe=False)
        tool_names = {t.name for t in _list_tools(mcp)}
        assert "check_connection" in tool_names
        assert "list_ida_sessions" in tool_names
        assert "get_metadata" in tool_names
        assert "patch_address_assembles" not in tool_names


def test_unsafe_flag_includes_unsafe_tools(isolate_sessions_dir: Path):
    with _running_inproc_server() as server:
        _publish_session(server)
        mcp = build_mcp_server(SessionRegistry(timeout=5), include_unsafe=True)
        tool_names = {t.name for t in _list_tools(mcp)}
        assert "patch_address_assembles" in tool_names
        assert "reanalyse_file" not in tool_names  # no spawner supplied


def test_no_module_level_global_state(isolate_sessions_dir: Path):
    """build_mcp_server should be callable repeatedly without leaking state."""
    with _running_inproc_server() as server:
        _publish_session(server)
        mcp_a = build_mcp_server(SessionRegistry(timeout=5), include_unsafe=False)
        mcp_b = build_mcp_server(SessionRegistry(timeout=5), include_unsafe=True)
        assert mcp_a is not mcp_b
        names_a = {t.name for t in _list_tools(mcp_a)}
        names_b = {t.name for t in _list_tools(mcp_b)}
        assert names_a < names_b


def test_open_close_tools_appear_when_spawner_provided(isolate_sessions_dir: Path):
    """Passing a Spawner must surface ``open_file`` / ``close_file``."""
    from ida_pro_mcp.spawner import Spawner

    with _running_inproc_server() as server:
        _publish_session(server)
        mcp = build_mcp_server(
            SessionRegistry(timeout=5),
            include_unsafe=False,
            spawner=Spawner(),
        )
        tool_names = {t.name for t in _list_tools(mcp)}
        assert {"open_file", "close_file", "list_ida_sessions"} <= tool_names
        assert "reanalyse_file" not in tool_names


def test_reanalyse_tool_requires_spawner_and_unsafe_mode(isolate_sessions_dir: Path):
    from ida_pro_mcp.spawner import Spawner

    with _running_inproc_server() as server:
        _publish_session(server)
        mcp = build_mcp_server(
            SessionRegistry(timeout=5),
            include_unsafe=True,
            spawner=Spawner(),
        )
        tool_names = {t.name for t in _list_tools(mcp)}
        assert "reanalyse_file" in tool_names


def test_open_close_tools_omitted_without_spawner(isolate_sessions_dir: Path):
    with _running_inproc_server() as server:
        _publish_session(server)
        mcp = build_mcp_server(SessionRegistry(timeout=5), include_unsafe=False)
        tool_names = {t.name for t in _list_tools(mcp)}
        assert "open_file" not in tool_names
        assert "close_file" not in tool_names


def test_http_bind_settings_are_applied_during_construction(isolate_sessions_dir: Path):
    """A wildcard listener must not retain FastMCP's localhost-only policy."""
    mcp = build_mcp_server(
        SessionRegistry(timeout=5),
        include_unsafe=False,
        host="0.0.0.0",
        port=13337,
    )

    assert mcp.settings.host == "0.0.0.0"
    assert mcp.settings.port == 13337
    assert mcp.settings.transport_security is None
