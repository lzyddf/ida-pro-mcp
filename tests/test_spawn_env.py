"""Unit tests for :meth:`Spawner._spawn_env` env scrubbing.

These tests live in their own module so they aren't gated on POSIX like the
fake-idat integration tests in ``test_spawner.py``: the bug they protect
against -- ``PYTHONHOME`` from an MCP host (Cursor / Claude / Windsurf)
poisoning IDA's embedded Python -- is most often hit on Windows, where IDA
ships its own pinned interpreter under ``<ida>/python`` and any external
``PYTHONHOME`` flips ``init.py`` over with "SRE module mismatch".
"""
from __future__ import annotations

import pytest

from ida_pro_mcp.spawner import _PYTHON_ENV_VARS_TO_STRIP, Spawner


@pytest.fixture()
def fresh_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every var the spawner cares about so we control the baseline."""
    for name in (*_PYTHON_ENV_VARS_TO_STRIP, "TVHEADLESS", "IDA_PRO_MCP_PACKAGE_ROOT"):
        monkeypatch.delenv(name, raising=False)


def test_python_home_is_stripped(fresh_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """``PYTHONHOME`` set by an MCP host must not reach idat.

    Concretely: Cursor's ``mcp.json`` often forwards ``PYTHONHOME`` so the
    proxy's venv interpreter can find its stdlib via a uv-managed CPython.
    Forwarding that to idat makes IDA's embedded Python load ``_sre``
    from the *wrong* CPython and ``init.py`` aborts -- IDA then refuses
    to even recognise ``.py`` files, so the bootstrap script never runs.
    """
    monkeypatch.setenv("PYTHONHOME", r"C:\does-not-exist\python311")
    env = Spawner()._spawn_env()
    assert "PYTHONHOME" not in env


def test_all_python_vars_are_stripped(fresh_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """The full blocklist (PYTHONHOME, PYTHONPATH, VIRTUAL_ENV, ...) is cleaned."""
    sentinel = "spawner-leaked-this"
    for name in _PYTHON_ENV_VARS_TO_STRIP:
        monkeypatch.setenv(name, sentinel)

    env = Spawner()._spawn_env()

    leaked = sorted(name for name in _PYTHON_ENV_VARS_TO_STRIP if name in env)
    assert leaked == []


def test_unrelated_env_passes_through(fresh_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stripping must not be over-eager: the user's regular env still flows."""
    monkeypatch.setenv("USER_KEEP_ME", "yes")
    env = Spawner()._spawn_env()
    assert env.get("USER_KEEP_ME") == "yes"


def test_required_env_is_set(fresh_env) -> None:
    """``TVHEADLESS`` and the package-root pointer remain in place."""
    env = Spawner()._spawn_env()
    assert env.get("TVHEADLESS") == "1"
    assert "IDA_PRO_MCP_PACKAGE_ROOT" in env


def test_existing_tvheadless_is_respected(fresh_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """User override of TVHEADLESS wins -- ``setdefault``, not assignment."""
    monkeypatch.setenv("TVHEADLESS", "0")
    env = Spawner()._spawn_env()
    assert env["TVHEADLESS"] == "0"


class TestStripVenvFromPath:
    """``_strip_venv_from_path`` must remove venv ``Scripts``/``bin`` entries.

    IDA 9.0's IDAPython auto-detects venvs by walking ``PATH`` and
    switches its embedded interpreter to a ``python.exe`` it finds
    inside one. When the proxy is launched via ``uv run`` from a
    project checkout, ``PATH`` starts with ``<repo>/.venv/Scripts`` and
    that switch breaks the C-extension load (``pydantic_core`` is the
    canonical victim).
    """

    def test_strips_windows_scripts_dir(self, tmp_path, monkeypatch):
        import os

        from ida_pro_mcp.spawner import _strip_venv_from_path

        venv = tmp_path / "proj" / ".venv"
        scripts = venv / "Scripts"
        scripts.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = ...")

        keep = tmp_path / "real_python"
        keep.mkdir()

        path = os.pathsep.join([str(scripts), str(keep)])
        result = _strip_venv_from_path(path)
        assert str(scripts) not in result.split(os.pathsep)
        assert str(keep) in result.split(os.pathsep)

    def test_strips_posix_bin_dir(self, tmp_path):
        import os

        from ida_pro_mcp.spawner import _strip_venv_from_path

        venv = tmp_path / "proj" / ".venv"
        bin_dir = venv / "bin"
        bin_dir.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = ...")

        path = os.pathsep.join([str(bin_dir), "/usr/bin"])
        result = _strip_venv_from_path(path)
        assert str(bin_dir) not in result.split(os.pathsep)
        assert "/usr/bin" in result.split(os.pathsep)

    def test_keeps_unrelated_dirs(self, tmp_path):
        import os

        from ida_pro_mcp.spawner import _strip_venv_from_path

        regular = tmp_path / "tools" / "bin"
        regular.mkdir(parents=True)
        # No pyvenv.cfg sibling -> not a venv -> keep.
        path = os.pathsep.join([str(regular), "/usr/local/bin"])
        result = _strip_venv_from_path(path)
        assert result.split(os.pathsep) == [str(regular), "/usr/local/bin"]

    def test_handles_empty_path(self):
        from ida_pro_mcp.spawner import _strip_venv_from_path

        assert _strip_venv_from_path("") == ""

    def test_skips_unreadable_entries(self, tmp_path):
        import os

        from ida_pro_mcp.spawner import _strip_venv_from_path

        # Garbage entries (NUL char on POSIX, reserved name on Windows)
        # must not raise -- the helper is best-effort.
        weird = "\x00invalid\x00path"
        result = _strip_venv_from_path(os.pathsep.join([weird, "/usr/bin"]))
        # The weird entry may stay or go (depends on Path() semantics
        # for the platform); the point is the helper survived.
        parts = result.split(os.pathsep)
        assert "/usr/bin" in parts


class TestSpawnEnvScrubsVenvPath:
    """End-to-end check: ``_spawn_env`` cleans ``PATH`` of venv entries."""

    def test_path_loses_venv_scripts(self, tmp_path, fresh_env, monkeypatch):
        import os

        venv = tmp_path / ".venv"
        scripts = venv / "Scripts"
        scripts.mkdir(parents=True)
        (venv / "pyvenv.cfg").write_text("home = ...")

        original = os.pathsep.join([str(scripts), r"C:\Windows\System32"])
        monkeypatch.setenv("PATH", original)

        env = Spawner()._spawn_env()
        parts = env.get("PATH", "").split(os.pathsep)
        assert str(scripts) not in parts
        assert r"C:\Windows\System32" in parts

    def test_uv_internal_pythonhome_is_stripped(self, fresh_env, monkeypatch):
        # uv's launch shim records its driver interpreter here. Because
        # IDA looks at ``PATH`` and several PEP 405 markers, leaving
        # this var around (which can point at a non-IDA-compatible
        # Python install) is one more way to mis-trigger the venv
        # auto-switch on IDA 9.0.
        monkeypatch.setenv(
            "UV_INTERNAL__PYTHONHOME",
            r"C:\Users\me\AppData\Roaming\uv\python\cpython-3.11-windows",
        )
        env = Spawner()._spawn_env()
        assert "UV_INTERNAL__PYTHONHOME" not in env
