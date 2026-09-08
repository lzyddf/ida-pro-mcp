"""Tests for the proxy-side :class:`SessionRegistry`."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp.client import IDARpcClient
from ida_pro_mcp.plugin import session
from ida_pro_mcp.session_registry import (
    SessionAmbiguousError,
    SessionNotFoundError,
    SessionRegistry,
)


@pytest.fixture(autouse=True)
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


def _publish(session_id: str, *, port: int) -> session.SessionInfo:
    info = session.make_info(
        session_id=session_id,
        host="127.0.0.1",
        port=port,
        pid=os.getpid(),
        idb_path=f"/tmp/{session_id}.i64",
        input_file=f"/tmp/{session_id}",
    )
    session.write(info)
    return info


class TestListSessions:
    def test_empty_when_no_sidecars(self):
        assert SessionRegistry().list_sessions() == []

    def test_returns_known_sessions(self):
        _publish("alpha-aaaaaaaa", port=1111)
        _publish("beta-bbbbbbbb", port=2222)
        ids = sorted(s.session_id for s in SessionRegistry().list_sessions())
        assert ids == ["alpha-aaaaaaaa", "beta-bbbbbbbb"]


class TestResolveExplicit:
    def test_returns_client_for_known_id(self):
        _publish("alpha-aaaaaaaa", port=4444)
        client = SessionRegistry().resolve("alpha-aaaaaaaa")
        assert isinstance(client, IDARpcClient)
        assert client.host == "127.0.0.1"
        assert client.port == 4444

    def test_unknown_id_raises_not_found(self):
        registry = SessionRegistry()
        with pytest.raises(SessionNotFoundError) as exc:
            registry.resolve("ghost-12345678")
        assert exc.value.session_id == "ghost-12345678"


class TestResolveAuto:
    def test_single_session_resolves_without_id(self):
        _publish("solo-deadbeef", port=5555)
        client = SessionRegistry().resolve(None)
        assert client.port == 5555

    def test_no_sessions_raises_not_found(self):
        registry = SessionRegistry()
        with pytest.raises(SessionNotFoundError) as exc:
            registry.resolve(None)
        assert exc.value.session_id is None

    def test_multiple_sessions_raise_ambiguous(self):
        _publish("alpha-aaaaaaaa", port=1)
        _publish("beta-bbbbbbbb", port=2)
        registry = SessionRegistry()
        with pytest.raises(SessionAmbiguousError) as exc:
            registry.resolve(None)
        assert sorted(exc.value.available_sessions) == ["alpha-aaaaaaaa", "beta-bbbbbbbb"]


class TestCacheBehavior:
    def test_same_session_returns_same_client(self):
        _publish("alpha-aaaaaaaa", port=1111)
        registry = SessionRegistry()
        a = registry.resolve("alpha-aaaaaaaa")
        b = registry.resolve("alpha-aaaaaaaa")
        assert a is b

    def test_port_change_replaces_cached_client(self):
        _publish("alpha-aaaaaaaa", port=1111)
        registry = SessionRegistry()
        first = registry.resolve("alpha-aaaaaaaa")
        # Simulate IDA restart: same session id, new port.
        _publish("alpha-aaaaaaaa", port=2222)
        second = registry.resolve("alpha-aaaaaaaa")
        assert first is not second
        assert second.port == 2222

    def test_invalidate_drops_cached_client(self):
        _publish("alpha-aaaaaaaa", port=1111)
        registry = SessionRegistry()
        first = registry.resolve("alpha-aaaaaaaa")
        registry.invalidate("alpha-aaaaaaaa")
        # Subsequent resolve rebuilds from sidecar.
        second = registry.resolve("alpha-aaaaaaaa")
        assert first is not second

    def test_disappearing_sidecar_evicts_cache(self):
        _publish("alpha-aaaaaaaa", port=1111)
        registry = SessionRegistry()
        registry.resolve("alpha-aaaaaaaa")  # warm cache
        session.remove("alpha-aaaaaaaa")
        with pytest.raises(SessionNotFoundError):
            registry.resolve("alpha-aaaaaaaa")


class TestMakeDispatch:
    def test_dispatch_routes_through_client(self, monkeypatch: pytest.MonkeyPatch):
        _publish("alpha-aaaaaaaa", port=9999)

        seen: list[tuple[str, dict]] = []

        def fake_call(self, method: str, params: dict):
            seen.append((method, params))
            return "ok"

        monkeypatch.setattr(IDARpcClient, "call", fake_call)
        dispatch = SessionRegistry().make_dispatch()
        assert dispatch("ping", {"x": 1}, "alpha-aaaaaaaa") == "ok"
        assert seen == [("ping", {"x": 1})]

    def test_dispatch_propagates_session_resolution_errors(self):
        dispatch = SessionRegistry().make_dispatch()
        with pytest.raises(SessionNotFoundError):
            dispatch("ping", {}, None)
