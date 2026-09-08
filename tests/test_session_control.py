"""Tests for programmatic session shutdown (the ``session close`` backend)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp import session_control
from ida_pro_mcp.plugin import session


@pytest.fixture(autouse=True)
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the sidecar registry at a tempdir so tests never touch ~/.ida-pro-mcp-headless."""
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


def _make(session_id: str, *, pid: int | None = None) -> session.SessionInfo:
    return session.make_info(
        session_id=session_id,
        host="127.0.0.1",
        port=12345,
        pid=os.getpid() if pid is None else pid,
        idb_path=f"/tmp/{session_id}.i64",
        input_file=f"/tmp/{session_id}",
    )


class _FakeSpawner:
    """Records ``close`` calls; can fail for selected session ids."""

    def __init__(self, *, graceful: bool = True, fail_on: tuple[str, ...] = ()) -> None:
        self.calls: list[tuple[str, float | None]] = []
        self._graceful = graceful
        self._fail_on = set(fail_on)

    def close(self, session_id: str, *, timeout: float | None = None) -> bool:
        self.calls.append((session_id, timeout))
        if session_id in self._fail_on:
            raise FileNotFoundError(f"No live session named {session_id!r}")
        return self._graceful


class TestLiveSessionIds:
    def test_empty_when_no_sidecars(self):
        assert session_control.live_session_ids() == []

    def test_returns_every_live_id_oldest_first(self):
        session.write(_make("alpha"))
        session.write(_make("beta"))
        assert session_control.live_session_ids() == ["alpha", "beta"]

    def test_skips_sidecars_whose_pid_is_gone(self):
        # pid 0 is never a valid target, so the entry is treated as stale.
        session.write(_make("dead", pid=0))
        assert session_control.live_session_ids() == []


class TestLiveSessions:
    def test_empty_when_no_sidecars(self):
        assert session_control.live_sessions() == []

    def test_returns_session_info_objects(self):
        session.write(_make("alpha"))
        (info,) = session_control.live_sessions()
        assert info.session_id == "alpha"


class TestResolveTargets:
    def test_explicit_ids_pass_through_in_order(self):
        assert session_control.resolve_targets(session_ids=["a", "b"]) == ["a", "b"]

    def test_paths_are_mapped_to_their_session_ids(self, tmp_path: Path):
        binary = tmp_path / "crackme.exe"
        expected = session.session_id_for_path(binary)
        assert session_control.resolve_targets(paths=[str(binary)]) == [expected]

    def test_duplicates_are_collapsed_keeping_first_seen_order(self):
        assert session_control.resolve_targets(session_ids=["b", "a", "b"]) == ["b", "a"]

    def test_same_session_named_by_id_and_path_is_collapsed(self, tmp_path: Path):
        binary = tmp_path / "crackme.exe"
        session_id = session.session_id_for_path(binary)
        resolved = session_control.resolve_targets(
            session_ids=[session_id], paths=[str(binary)]
        )
        assert resolved == [session_id]

    def test_relative_and_absolute_paths_agree(self, tmp_path: Path, monkeypatch):
        binary = tmp_path / "crackme.exe"
        binary.write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        assert session_control.resolve_targets(paths=["crackme.exe"]) == (
            session_control.resolve_targets(paths=[str(binary)])
        )

    def test_no_inputs_yields_no_targets(self):
        assert session_control.resolve_targets() == []


class TestCloseSessions:
    def test_returns_one_outcome_per_target_in_order(self):
        spawner = _FakeSpawner()
        outcomes = session_control.close_sessions(["alpha", "beta"], spawner=spawner)
        assert [outcome.session_id for outcome in outcomes] == ["alpha", "beta"]
        assert all(outcome.closed for outcome in outcomes)
        assert [call[0] for call in spawner.calls] == ["alpha", "beta"]

    def test_reports_escalated_hard_kill(self):
        spawner = _FakeSpawner(graceful=False)
        (outcome,) = session_control.close_sessions(["alpha"], spawner=spawner)
        assert outcome.closed is True
        assert outcome.graceful is False
        assert outcome.error is None

    def test_failure_does_not_stop_the_batch(self):
        spawner = _FakeSpawner(fail_on=("alpha",))
        outcomes = session_control.close_sessions(
            ["alpha", "beta", "gamma"], spawner=spawner
        )
        assert [outcome.closed for outcome in outcomes] == [False, True, True]
        assert outcomes[0].error is not None
        assert outcomes[0].graceful is None
        # Every target was still attempted.
        assert [call[0] for call in spawner.calls] == ["alpha", "beta", "gamma"]

    def test_timeout_is_forwarded(self):
        spawner = _FakeSpawner()
        session_control.close_sessions(["alpha"], timeout=2.5, spawner=spawner)
        assert spawner.calls == [("alpha", 2.5)]

    def test_timeout_omitted_uses_spawner_default(self):
        spawner = _FakeSpawner()
        session_control.close_sessions(["alpha"], spawner=spawner)
        assert spawner.calls == [("alpha", None)]

    def test_empty_targets_is_a_no_op(self):
        spawner = _FakeSpawner()
        assert session_control.close_sessions([], spawner=spawner) == []
        assert spawner.calls == []


class TestCloseOutcome:
    def test_to_dict_shape(self):
        outcome = session_control.CloseOutcome("alpha", closed=True, graceful=True)
        assert outcome.to_dict() == {
            "session_id": "alpha",
            "closed": True,
            "graceful": True,
            "error": None,
        }
