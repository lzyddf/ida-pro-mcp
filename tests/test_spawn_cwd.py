"""Tests for :meth:`Spawner._spawn_cwd`.

IDA 9.0 auto-switches to a ``.venv`` interpreter detected next to the
working directory. When the proxy is launched from the project checkout,
inheriting that cwd causes the spawned ``idat`` to load Python from the
project's ``.venv`` -- a cross-version mismatch that breaks every C
extension. ``_spawn_cwd`` mitigates this by anchoring on the binary's
parent directory instead.

These tests are platform-agnostic; the ``.venv`` detection itself is an
IDA behaviour and not directly observable here, but we can exercise the
helper deterministically across the cases that matter.
"""
from __future__ import annotations

import os
from pathlib import Path

from ida_pro_mcp.spawner import Spawner


class TestSpawnCwd:
    def test_uses_binary_parent_when_directory(self, tmp_path: Path):
        binary = tmp_path / "subdir" / "thing.exe"
        binary.parent.mkdir()
        binary.write_bytes(b"\x90")

        spawner = Spawner()
        cwd = spawner._spawn_cwd(binary)
        assert Path(cwd).resolve() == binary.parent.resolve()

    def test_falls_back_to_process_cwd_when_parent_missing(self, tmp_path: Path):
        # Construct a binary path whose parent doesn't exist on disk
        # (simulates a now-unmounted share or test edge case where the
        # caller resolved the path but it vanished before spawn).
        ghost_parent = tmp_path / "ghost" / "missing-dir"
        binary = ghost_parent / "thing.exe"

        spawner = Spawner()
        cwd = spawner._spawn_cwd(binary)
        assert Path(cwd).resolve() == Path(os.getcwd()).resolve()

    def test_does_not_inherit_caller_cwd_with_venv(self, tmp_path: Path, monkeypatch):
        # Pretend the proxy CLI is being invoked from a project root
        # that contains a ``.venv`` (the exact shape that triggers
        # IDA 9.0's interpreter switch). The chosen cwd must not be
        # this directory; it must be the binary's parent.
        proj_root = tmp_path / "proj"
        (proj_root / ".venv" / "Scripts").mkdir(parents=True)
        monkeypatch.chdir(proj_root)

        binary_dir = tmp_path / "samples"
        binary_dir.mkdir()
        binary = binary_dir / "target.exe"
        binary.write_bytes(b"\x90")

        spawner = Spawner()
        cwd = spawner._spawn_cwd(binary)
        assert Path(cwd).resolve() == binary_dir.resolve()
        assert Path(cwd).resolve() != proj_root.resolve()
