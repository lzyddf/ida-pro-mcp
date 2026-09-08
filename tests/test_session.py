"""Tests for the per-IDA session sidecar registry."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ida_pro_mcp.plugin import session


@pytest.fixture(autouse=True)
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect both base_dir and sessions_dir to a tempdir for each test.

    The module computes ``Path.home() / ".ida-pro-mcp-headless"`` from scratch in
    every helper so we patch :func:`base_dir` (the single source of truth)
    rather than poking module-level globals.
    """
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


def _make(session_id: str = "binary-deadbeef", *, port: int = 12345, pid: int | None = None) -> session.SessionInfo:
    return session.make_info(
        session_id=session_id,
        host="127.0.0.1",
        port=port,
        pid=pid if pid is not None else os.getpid(),
        idb_path=f"/tmp/{session_id}.i64",
        input_file=f"/tmp/{session_id}",
    )


class TestDeriveSessionId:
    def test_deterministic_for_same_path(self):
        assert session.derive_session_id("/tmp/foo.i64") == session.derive_session_id("/tmp/foo.i64")

    def test_different_paths_different_ids(self):
        a = session.derive_session_id("/tmp/foo.i64")
        b = session.derive_session_id("/tmp/bar.i64")
        assert a != b

    def test_basename_appears_in_id(self):
        sid = session.derive_session_id("/some/dir/crackme.exe.i64")
        assert sid.startswith("crackme.exe.i64-")

    def test_sanitizes_slashes_in_basename(self):
        # ``derive_session_id`` works on the basename so backslashes shouldn't appear,
        # but messy inputs (e.g. someone passes a path with embedded weird chars)
        # must not produce invalid filenames.
        sid = session.derive_session_id("/tmp/weird name with spaces.bin")
        assert "/" not in sid
        assert " " not in sid


class TestNormalizeInputFile:
    """``--path`` and ``open_file`` must agree on the path form used for ids."""

    def test_relative_and_absolute_resolve_to_the_same_path(self, tmp_path, monkeypatch):
        binary = tmp_path / "crackme.exe"
        binary.write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        assert session.normalize_input_file("crackme.exe") == binary.resolve()

    def test_expanduser_is_applied(self):
        # Platform-independent: ``~`` must expand to the real home directory.
        assert session.normalize_input_file("~") == Path.home().resolve()

    def test_session_id_for_path_matches_manual_derivation(self, tmp_path):
        binary = tmp_path / "crackme.exe"
        assert session.session_id_for_path(binary) == session.derive_session_id(
            str(session.normalize_input_file(binary))
        )


class TestRoundTrip:
    def test_write_get_remove(self):
        info = _make()
        path = session.write(info)
        assert path.exists()
        loaded = session.get(info.session_id)
        assert loaded == info
        session.remove(info.session_id)
        assert session.get(info.session_id) is None

    def test_write_overwrites_existing(self):
        first = _make(port=1111)
        second = _make(port=2222)
        session.write(first)
        session.write(second)
        loaded = session.get(first.session_id)
        assert loaded is not None
        assert loaded.port == 2222

    def test_remove_missing_is_noop(self):
        # Must not raise even when the file does not exist.
        session.remove("nonexistent-12345678")


class TestLiveness:
    def test_dead_pid_filtered_from_list_all(self, isolate_sessions_dir: Path):
        alive = _make("alive-aaaaaaaa")
        dead = _make("dead-bbbbbbbb", pid=2**31 - 1)  # vanishingly unlikely PID
        session.write(alive)
        session.write(dead)

        live = session.list_all()
        ids = [s.session_id for s in live]
        assert "alive-aaaaaaaa" in ids
        assert "dead-bbbbbbbb" not in ids
        # Stale file is GC'd by ``list_all``.
        assert not (isolate_sessions_dir / "sessions" / "dead-bbbbbbbb.json").exists()

    def test_dead_pid_returns_none_from_get(self, isolate_sessions_dir: Path):
        dead = _make("zombie-cccccccc", pid=2**31 - 1)
        session.write(dead)
        assert session.get("zombie-cccccccc") is None
        assert not (isolate_sessions_dir / "sessions" / "zombie-cccccccc.json").exists()


class TestStaleEntries:
    def test_list_all_skips_unparseable_files(self, isolate_sessions_dir: Path):
        good = _make("good-eeeeeeee")
        session.write(good)
        # Drop a malformed sibling that should be silently skipped + removed.
        bad_path = isolate_sessions_dir / "sessions" / "junk.json"
        bad_path.write_text("not json", encoding="utf-8")

        live = session.list_all()
        assert [s.session_id for s in live] == ["good-eeeeeeee"]
        assert not bad_path.exists()

    def test_list_all_skips_missing_keys(self, isolate_sessions_dir: Path):
        # Required keys absent -> SessionInfo.from_dict raises KeyError -> dropped.
        path = isolate_sessions_dir / "sessions" / "broken.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"session_id": "broken"}), encoding="utf-8")
        assert session.list_all() == []
        assert not path.exists()

    def test_list_all_sorted_by_creation_time(self):
        first = session.make_info(
            session_id="first-11111111",
            host="127.0.0.1",
            port=1, pid=os.getpid(),
            idb_path="/tmp/a.i64", input_file="/tmp/a",
            created_at=10.0,
        )
        second = session.make_info(
            session_id="second-22222222",
            host="127.0.0.1",
            port=2, pid=os.getpid(),
            idb_path="/tmp/b.i64", input_file="/tmp/b",
            created_at=20.0,
        )
        session.write(second)
        session.write(first)
        ids = [s.session_id for s in session.list_all()]
        assert ids == ["first-11111111", "second-22222222"]
