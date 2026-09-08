"""Tests for the segment-perm renderer used by ``list_segments``."""
from __future__ import annotations

import idaapi
import pytest

from ida_pro_mcp.plugin.tools.listings import _segment_perms


@pytest.fixture(autouse=True)
def stable_segperm_constants(monkeypatch):
    """Pin SEGPERM_* to fixed bits regardless of stub behaviour.

    Outside IDA we get :class:`_Stub` sentinels for the SEGPERM constants
    that all collapse to ``0`` -- handy for module import, useless for
    bitwise testing. We pin them here so the renderer can be exercised in
    isolation.
    """
    monkeypatch.setattr(idaapi, "SEGPERM_READ", 0b100, raising=False)
    monkeypatch.setattr(idaapi, "SEGPERM_WRITE", 0b010, raising=False)
    monkeypatch.setattr(idaapi, "SEGPERM_EXEC", 0b001, raising=False)


class TestSegmentPerms:
    def test_zero_is_unknown(self):
        # The loader didn't record permissions; better to surface that than
        # to lie about a "no rights" segment.
        assert _segment_perms(0) == "???"

    def test_full_rwx(self):
        assert _segment_perms(0b111) == "rwx"

    def test_read_only(self):
        assert _segment_perms(0b100) == "r--"

    def test_read_execute(self):
        assert _segment_perms(0b101) == "r-x"

    def test_read_write(self):
        assert _segment_perms(0b110) == "rw-"

    def test_write_only(self):
        assert _segment_perms(0b010) == "-w-"

    def test_execute_only(self):
        assert _segment_perms(0b001) == "--x"
