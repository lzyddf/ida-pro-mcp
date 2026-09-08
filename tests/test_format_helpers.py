"""Tests for the format helpers (format_ea, format_hex, format_bytes)."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin.format import (
    format_bytes,
    format_ea,
    format_hex,
    format_padded_hex,
)


class TestFormatHex:
    def test_zero(self):
        assert format_hex(0) == "0x0"

    def test_basic(self):
        assert format_hex(0x100) == "0x100"

    def test_lowercase(self):
        assert format_hex(0xCAFEBABE) == "0xcafebabe"

    def test_matches_format_ea_for_now(self):
        # The two are deliberately interchangeable in rendering, but distinct
        # in semantic intent. Keeping this test makes future divergence loud.
        assert format_hex(0x401000) == format_ea(0x401000)


class TestFormatBytes:
    def test_empty(self):
        assert format_bytes(b"") == ""

    def test_single(self):
        assert format_bytes(b"\x01") == "0x01"

    def test_multiple(self):
        assert format_bytes(b"\x01\x02\xff") == "0x01 0x02 0xff"


class TestFormatPaddedHex:
    def test_zero_padding_one_byte(self):
        assert format_padded_hex(0xA, 1) == "0x0A"

    def test_zero_padding_pointer(self):
        assert format_padded_hex(0x401000, 8) == "0x0000000000401000"

    def test_value_already_at_width(self):
        assert format_padded_hex(0xDEADBEEF, 4) == "0xDEADBEEF"

    def test_uppercase_letters(self):
        assert format_padded_hex(0xabc, 2) == "0x0ABC"

    def test_zero_byte_width_renders_bare_hex(self):
        assert format_padded_hex(0xFF, 0) == "0xFF"

    def test_negative_byte_width_raises(self):
        with pytest.raises(ValueError):
            format_padded_hex(0, -1)
