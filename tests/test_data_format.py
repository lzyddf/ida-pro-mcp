"""Tests for the byte-format helper used by ``read_bytes``.

The bridge function ``read_bytes`` itself talks to IDA and is exercised in
the integration tests; here we cover the pure renderer in isolation so the
three encodings stay in lock-step with the wire description in the tool's
docstring.
"""
from __future__ import annotations

import base64
import inspect

import pytest

from ida_pro_mcp.plugin.errors import IDAError
from ida_pro_mcp.plugin.tools import data
from ida_pro_mcp.plugin.tools.data import _format_raw_bytes


class TestFormatRawBytes:
    def test_empty_hex_spaced(self):
        assert _format_raw_bytes(b"", "hex_spaced") == ""

    def test_hex_spaced_matches_dump_style(self):
        # Legacy wire format -- one ``0xNN`` per byte, separated by spaces.
        assert _format_raw_bytes(b"\x01\x02\xff", "hex_spaced") == "0x01 0x02 0xff"

    def test_hex_compact_is_bare_hex(self):
        assert _format_raw_bytes(b"\xde\xad\xbe\xef", "hex_compact") == "deadbeef"

    def test_hex_compact_empty(self):
        assert _format_raw_bytes(b"", "hex_compact") == ""

    def test_base64_round_trip(self):
        raw = bytes(range(32))
        encoded = _format_raw_bytes(raw, "base64")
        assert base64.b64decode(encoded) == raw

    def test_compact_is_denser_than_spaced(self):
        # Sanity guard for the documented "~4x denser" claim. A single byte
        # is "0xNN" (4 chars) vs "NN" (2 chars), so the ratio is 2x; for a
        # 32-byte payload the prefix + space overhead pushes spaced out to
        # 5*N-1 vs 2*N for compact.
        raw = bytes(32)
        spaced = _format_raw_bytes(raw, "hex_spaced")
        compact = _format_raw_bytes(raw, "hex_compact")
        assert len(spaced) > 2 * len(compact)

    def test_unknown_format_raises_with_helpful_message(self):
        with pytest.raises(IDAError) as exc_info:
            _format_raw_bytes(b"\x00", "rot13")  # type: ignore[arg-type]
        message = str(exc_info.value)
        assert "rot13" in message
        for choice in ("hex_spaced", "hex_compact", "base64"):
            assert choice in message


def test_read_bytes_rejects_unreadable_ranges(monkeypatch):
    monkeypatch.setattr(data.ida_bytes, "get_bytes", lambda _ea, _size: None, raising=False)
    raw_read_bytes = inspect.unwrap(data.read_bytes)
    with pytest.raises(IDAError, match="Failed to read 4 bytes"):
        raw_read_bytes("0x401000", 4)
