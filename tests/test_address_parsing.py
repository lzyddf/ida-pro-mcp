"""Tests for address parsing and formatting helpers."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin.errors import IDAError
from ida_pro_mcp.plugin.format import format_ea, parse_ea, parse_int


class TestFormatEA:
    def test_basic(self):
        assert format_ea(0x401000) == "0x401000"

    def test_zero(self):
        assert format_ea(0) == "0x0"

    def test_lowercase(self):
        assert format_ea(0xABCDEF) == "0xabcdef"


class TestParseEA:
    def test_int_passthrough(self):
        assert parse_ea(0x1234) == 0x1234

    def test_bare_digits_are_hex(self):
        # IDA-style: "1234" means 0x1234, NOT decimal 1234.
        assert parse_ea("1234") == 0x1234

    def test_hex_with_prefix(self):
        assert parse_ea("0x1234") == 0x1234

    def test_bare_hex_with_letters(self):
        assert parse_ea("abcd") == 0xABCD

    def test_octal_with_prefix(self):
        assert parse_ea("0o17") == 15

    def test_binary_with_prefix(self):
        assert parse_ea("0b101") == 0b101

    def test_explicit_decimal_prefix(self):
        # '0d' is our extension since standard int() doesn't accept it.
        assert parse_ea("0d1234") == 1234

    def test_whitespace_tolerated(self):
        assert parse_ea("  0x10  ") == 0x10

    def test_empty_raises(self):
        with pytest.raises(IDAError):
            parse_ea("")

    def test_garbage_raises(self):
        with pytest.raises(IDAError):
            parse_ea("not-a-number")

    def test_invalid_decimal_with_prefix_raises(self):
        with pytest.raises(IDAError):
            parse_ea("0dABC")


class TestParseInt:
    def test_int_passthrough(self):
        assert parse_int(42) == 42

    def test_decimal(self):
        assert parse_int("42") == 42

    def test_hex_with_prefix(self):
        assert parse_int("0x10") == 16

    def test_no_hex_fallback_for_bare_letters(self):
        # Unlike parse_ea, parse_int does NOT accept letters without 0x prefix.
        with pytest.raises(IDAError):
            parse_int("abc")

    def test_negative(self):
        assert parse_int("-5") == -5
