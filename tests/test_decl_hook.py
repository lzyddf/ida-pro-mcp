"""Tests for the parse_decls diagnostics hook surface."""
from __future__ import annotations

import sys

from ida_pro_mcp.plugin.tools import _decl_hook


class TestDiagnosticsSupported:
    def test_matches_platform(self):
        assert _decl_hook.diagnostics_supported() == (sys.platform == "win32")


class TestSwigFallback:
    def test_returns_empty_messages(self, monkeypatch):
        # Stub the parse function so we don't need the real IDA.
        monkeypatch.setattr(
            _decl_hook.ida_typeinf, "parse_decls", lambda *a, **kw: 0
        )
        errors, messages = _decl_hook._swig_parse_decls("typedef int x;", 0)
        assert errors == 0
        assert messages == []
