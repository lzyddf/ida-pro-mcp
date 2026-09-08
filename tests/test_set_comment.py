"""Behavioural tests for ``set_comment`` partial-failure handling.

Hex-Rays attaches pseudocode comments to a (treeloc, itp) pair, where ``itp``
identifies *which* punctuation token of the ctree node the comment sits on.
Some ctree shapes -- multi-line ``a || b || c`` chains, ternary expressions,
switch labels -- have no canonical ITP slot at the EA Hex-Rays returned via
``get_eamap``. The classic cyber.wtf workaround (probe a list of candidate
ITPs and accept the first that doesn't orphan) silently fails on those
shapes; an earlier implementation surfaced that failure as a hard RPC error
even though the disassembly comment had already been written, leaving the
caller to either retry the same write or abandon the finding.

These tests exercise the contract that the disassembly comment is
authoritative and the pseudocode mirror is best-effort:

* disassembly write succeeds, pseudocode mirror succeeds -> no error;
* disassembly write succeeds, pseudocode mirror fails  -> still no error;
* disassembly write fails -> raises (we did not honour the caller's intent).
"""
from __future__ import annotations

import logging

import pytest

from ida_pro_mcp.plugin import ida_sync
from ida_pro_mcp.plugin.errors import IDAError
from ida_pro_mcp.plugin.tools import comments


@pytest.fixture(autouse=True)
def _inline_execute_sync(monkeypatch):
    """Run sync trampolines inline so we can drive the wrapped handler directly."""
    def _inline(runner, _safety):
        runner()
        return 1

    monkeypatch.setattr(ida_sync.idaapi, "execute_sync", _inline)


class _FakeTreeloc:
    """Mimics the SWIG ``treeloc_t`` shape used by the comment placement loop."""

    def __init__(self):
        self.ea = 0
        self.itp = 0


class _FakeCFunc:
    """Minimal fake satisfying the surface ``_attach_to_pseudocode`` touches.

    The comment-placement loop calls (in order):
      1. ``has_orphan_cmts`` / ``del_orphan_cmts`` to clear stale state
      2. ``set_user_cmt(treeloc, text)``
      3. ``has_orphan_cmts`` again to decide whether the ITP stuck

    The fake parameterises step 3: ``orphan_for_itp`` is a callable telling
    us whether a given ITP value would have produced an orphan, so each test
    can describe its own ctree shape by predicate.
    """

    def __init__(self, *, entry_ea: int, eamap_target: int | None,
                 orphan_for_itp):
        self.entry_ea = entry_ea
        self._eamap_target = eamap_target
        self._orphan_for_itp = orphan_for_itp
        self._last_itp: int | None = None
        self._has_orphan = False
        self.set_calls: list[tuple[int, int, str]] = []

    def get_eamap(self):
        if self._eamap_target is None:
            return {}
        proxy = type("_E", (), {"ea": self._eamap_target})
        return {self._eamap_target: [proxy]}

    def has_orphan_cmts(self):
        return self._has_orphan

    def del_orphan_cmts(self):
        self._has_orphan = False

    def set_user_cmt(self, treeloc, text: str):
        self.set_calls.append((treeloc.ea, treeloc.itp, text))
        self._last_itp = treeloc.itp
        self._has_orphan = self._orphan_for_itp(treeloc.itp)

    def save_user_cmts(self):
        pass

    def refresh_func_ctext(self):
        pass


@pytest.fixture()
def fake_idaapi(monkeypatch):
    """Patch ``idaapi.set_cmt`` / ``treeloc_t`` / ``ITP_*`` for in-memory testing.

    The real ``idaapi`` is the stub installed by ``_ida_stub`` outside IDA;
    we replace just the symbols ``set_comment`` actually hits so the rest of
    the import graph stays untouched.
    """
    calls: list[tuple[int, str, bool]] = []

    def _set_cmt(ea, text, repeatable):
        calls.append((ea, text, repeatable))
        return True

    monkeypatch.setattr(comments.idaapi, "set_cmt", _set_cmt)
    monkeypatch.setattr(comments.idaapi, "treeloc_t", _FakeTreeloc)
    # Each ITP_* is just a distinct integer; any int works for the loop.
    for i, name in enumerate(comments._ITP_CANDIDATE_NAMES, start=1):
        monkeypatch.setattr(comments.idaapi, name, i, raising=False)
    return calls


def _patch_decompiler(monkeypatch, cfunc):
    monkeypatch.setattr(comments, "decompile_checked", lambda _ea: cfunc)


class TestSetCommentBestEffort:
    def test_pseudocode_mirror_success_writes_both(self, fake_idaapi, monkeypatch):
        cfunc = _FakeCFunc(
            entry_ea=0x401000,
            eamap_target=0x401050,
            orphan_for_itp=lambda itp: itp != 1,  # ITP_SEMI (=1) sticks
        )
        _patch_decompiler(monkeypatch, cfunc)

        comments.set_comment(address="0x401050", comment="hello")

        assert fake_idaapi == [(0x401050, "hello", False)]
        # Loop tried ITP_SEMI first and stopped.
        assert cfunc.set_calls == [(0x401050, 1, "hello")]

    def test_no_eamap_entry_does_not_raise(self, fake_idaapi, monkeypatch, caplog):
        """``ea`` not in the eamap used to raise NOT_FOUND; now it's a log line."""
        cfunc = _FakeCFunc(
            entry_ea=0x401000,
            eamap_target=None,
            orphan_for_itp=lambda _itp: True,
        )
        _patch_decompiler(monkeypatch, cfunc)
        with caplog.at_level(logging.INFO, logger="ida_pro_mcp.plugin.tools.comments"):
            comments.set_comment(address="0x401050", comment="hello")
        assert fake_idaapi == [(0x401050, "hello", False)]
        assert any("pseudocode mirror" in rec.message for rec in caplog.records)

    def test_all_itps_orphan_does_not_raise(self, fake_idaapi, monkeypatch, caplog):
        """Multi-line ``||`` chain: every candidate ITP orphans; no error surfaces."""
        cfunc = _FakeCFunc(
            entry_ea=0x401000,
            eamap_target=0x40121c,
            orphan_for_itp=lambda _itp: True,
        )
        _patch_decompiler(monkeypatch, cfunc)
        with caplog.at_level(logging.INFO, logger="ida_pro_mcp.plugin.tools.comments"):
            comments.set_comment(address="0x40121c", comment="flag is here")

        # Disassembly write happened exactly once.
        assert fake_idaapi == [(0x40121c, "flag is here", False)]
        # All ITP candidates were probed (proves we walked the full list).
        assert {itp for _, itp, _ in cfunc.set_calls} == set(range(1, len(comments._ITP_CANDIDATE_NAMES) + 1))
        # The user-facing log explains the partial outcome.
        assert any("pseudocode mirror" in rec.message for rec in caplog.records)

    def test_decompiler_unavailable_does_not_raise(self, fake_idaapi, monkeypatch):
        """Hex-Rays missing/license fail must not lose the disassembly write."""
        from ida_pro_mcp.plugin.errors import IDAErrorKind

        def _no_decomp(_ea):
            raise IDAError("no license", IDAErrorKind.DECOMPILER_UNAVAILABLE)

        monkeypatch.setattr(comments, "decompile_checked", _no_decomp)
        comments.set_comment(address="0x401050", comment="hello")
        assert fake_idaapi == [(0x401050, "hello", False)]

    def test_disassembly_failure_still_raises(self, monkeypatch):
        """A failed ``set_cmt`` is the one error that *must* propagate."""
        monkeypatch.setattr(comments.idaapi, "set_cmt", lambda *_args: False)
        with pytest.raises(IDAError, match="Failed to set disassembly comment"):
            comments.set_comment(address="0x401050", comment="hello")

    def test_entry_ea_uses_func_cmt_path(self, fake_idaapi, monkeypatch):
        """At ``entry_ea`` we use ``set_func_cmt`` (a different SDK call)."""
        cfunc = _FakeCFunc(
            entry_ea=0x401000,
            eamap_target=0x401000,
            orphan_for_itp=lambda _itp: True,
        )
        _patch_decompiler(monkeypatch, cfunc)
        func_cmt_calls: list[tuple[int, str, bool]] = []
        monkeypatch.setattr(
            comments.idc,
            "set_func_cmt",
            lambda ea, text, repeatable: func_cmt_calls.append((ea, text, repeatable)),
        )
        comments.set_comment(address="0x401000", comment="entry")
        assert func_cmt_calls == [(0x401000, "entry", True)]
        # The eamap probing loop must NOT run for entry-ea comments.
        assert cfunc.set_calls == []
