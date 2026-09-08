"""Tests for the pure helpers backing the ``convert_number`` tool."""
from __future__ import annotations

import pytest

from ida_pro_mcp.number_conversion import (
    _minimum_byte_width,
    _printable_ascii,
    _to_bytes_either_sign,
)
from ida_pro_mcp.plugin.errors import IDAError


class TestMinimumByteWidth:
    def test_zero_is_one(self):
        assert _minimum_byte_width(0) == 1

    def test_small_positive_fits_in_one(self):
        assert _minimum_byte_width(1) == 1
        assert _minimum_byte_width(255) == 1

    def test_just_over_byte_needs_two(self):
        assert _minimum_byte_width(256) == 2

    def test_dword_pattern_fits_in_four(self):
        # 0xFFFFFFFF is exactly 32 bits unsigned.
        assert _minimum_byte_width(0xFFFFFFFF) == 4

    def test_signed_negative_one_fits_in_one(self):
        # -1 is 0xFF as signed byte.
        assert _minimum_byte_width(-1) == 1

    def test_signed_negative_128_fits_in_one(self):
        assert _minimum_byte_width(-128) == 1

    def test_signed_minus_129_needs_two(self):
        assert _minimum_byte_width(-129) == 2


class TestToBytesEitherSign:
    def test_unsigned_pattern_packs(self):
        # 0xDEADBEEF is the canonical "32-bit pattern" RE users want -- the
        # old signed-only path raised here.
        assert _to_bytes_either_sign(0xDEADBEEF, 4) == b"\xef\xbe\xad\xde"

    def test_negative_uses_signed(self):
        assert _to_bytes_either_sign(-1, 1) == b"\xff"
        assert _to_bytes_either_sign(-1, 4) == b"\xff\xff\xff\xff"

    def test_value_too_big_raises(self):
        with pytest.raises(IDAError, match="too big"):
            _to_bytes_either_sign(0x1_0000_0000, 4)

    def test_zero_packs_as_zero(self):
        assert _to_bytes_either_sign(0, 1) == b"\x00"


class TestPrintableAscii:
    def test_all_printable(self):
        assert _printable_ascii(b"hello") == "hello"

    def test_trailing_nulls_stripped(self):
        assert _printable_ascii(b"hi\x00\x00") == "hi"

    def test_non_printable_returns_none(self):
        assert _printable_ascii(b"hi\x01") is None

    def test_empty_is_empty(self):
        assert _printable_ascii(b"") == ""
