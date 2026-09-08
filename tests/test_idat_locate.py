"""Tests for :func:`spawner.locate_idat` discovery logic.

Resolution is intentionally trivial -- read ``IDA_PRO_HOME`` and look for
``idat`` / ``idat.exe`` inside that directory. The tests pin every failure
mode (env unset, env points at a file, env points at a directory missing
``idat``, found-but-not-executable) so future refactors can't silently
re-introduce a ``PATH`` lookup or a platform-default fallback.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ida_pro_mcp.spawner import IdatNotFoundError, locate_idat, locate_idat_in_home


def _fake_idat(directory: Path, name: str | None = None) -> Path:
    """Create an executable file masquerading as ``idat`` inside *directory*.

    On Windows the executability check keys off the file extension
    (``PATHEXT``), so the default name is ``idat.exe``; on POSIX it's
    bare ``idat`` with the exec bit set. ``locate_idat`` probes both
    names on POSIX (preferring ``idat``) and ``idat.exe`` on Windows.
    """
    if name is None:
        name = "idat.exe" if sys.platform == "win32" else "idat"
    fake = directory / name
    fake.write_text("#!/bin/sh\nexit 0\n")
    if sys.platform != "win32":
        fake.chmod(0o755)
    return fake


@pytest.fixture(autouse=True)
def clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make sure no real env var leaks in from the developer's shell."""
    monkeypatch.delenv("IDA_PRO_HOME", raising=False)


def test_env_home_points_at_idat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake = _fake_idat(tmp_path)
    monkeypatch.setenv("IDA_PRO_HOME", str(tmp_path))
    assert locate_idat() == fake.resolve()


def test_explicit_home_points_at_idat_without_environment(tmp_path: Path):
    """The config-time validator must not depend on process environment."""
    fake = _fake_idat(tmp_path)
    assert locate_idat_in_home(tmp_path) == fake.resolve()


def test_unset_env_raises(tmp_path: Path):
    """No ``IDA_PRO_HOME`` -> immediate, actionable error."""
    with pytest.raises(IdatNotFoundError, match="IDA_PRO_HOME is not set"):
        locate_idat()


def test_env_pointing_at_file_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A *file* path is not a valid install dir."""
    bogus = tmp_path / "idat.exe"
    bogus.write_text("not a directory")
    monkeypatch.setenv("IDA_PRO_HOME", str(bogus))
    with pytest.raises(IdatNotFoundError, match="not a directory"):
        locate_idat()


def test_explicit_home_rejects_missing_directory(tmp_path: Path):
    missing = tmp_path / "missing-ida"
    with pytest.raises(IdatNotFoundError, match="not a directory"):
        locate_idat_in_home(missing)


def test_env_dir_without_idat_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Directory exists but contains nothing named ``idat``."""
    monkeypatch.setenv("IDA_PRO_HOME", str(tmp_path))
    with pytest.raises(IdatNotFoundError) as exc:
        locate_idat()
    msg = str(exc.value)
    assert "Could not locate" in msg
    # The error must surface the searched paths so the user can debug
    # without re-running with verbose flags.
    expected_name = "idat.exe" if sys.platform == "win32" else "idat"
    assert expected_name in msg


def test_non_executable_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A file present but not executable must not match.

    "Not executable" is platform-specific: POSIX clears the exec bit;
    Windows uses an extension absent from ``PATHEXT`` (``.txt`` here).
    Both should be rejected for the same reason -- the user gave us a
    home dir whose ``idat`` can't be ``Popen``'d.
    """
    if sys.platform == "win32":
        bad = tmp_path / "idat.txt"
        bad.write_text("not executable")
    else:
        bad = tmp_path / "idat"
        bad.write_text("not executable")
        bad.chmod(0o644)
    monkeypatch.setenv("IDA_PRO_HOME", str(tmp_path))
    with pytest.raises(IdatNotFoundError):
        locate_idat()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX prefers idat over idat.exe")
def test_posix_prefers_idat_over_idat_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """On POSIX both names are accepted, with bare ``idat`` winning."""
    posix_idat = _fake_idat(tmp_path, name="idat")
    _fake_idat(tmp_path, name="idat.exe")
    monkeypatch.setenv("IDA_PRO_HOME", str(tmp_path))
    assert locate_idat() == posix_idat.resolve()


def test_user_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """``~`` in ``IDA_PRO_HOME`` is expanded before probing."""
    _fake_idat(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows expanduser uses this
    monkeypatch.setenv("IDA_PRO_HOME", "~")
    located = locate_idat()
    assert located.parent == tmp_path.resolve()
