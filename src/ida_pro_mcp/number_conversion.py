"""Pure number-conversion helpers used by the proxy-local MCP tool."""
from __future__ import annotations

from typing import Annotated

from .plugin.doc import Doc
from .plugin.errors import IDAError, IDAErrorKind
from .plugin.models import ConvertedNumber
from .plugin.params import ConvertNumberSizeParam


def _minimum_byte_width(value: int) -> int:
    """Return the minimum byte width for an unsigned or two's-complement value."""
    if value == 0:
        return 1
    if value > 0:
        return max(1, (value.bit_length() + 7) // 8)
    return max(1, ((value + 1).bit_length() + 8) // 8)


def _printable_ascii(raw: bytes) -> str | None:
    """Return *raw* as ASCII iff every non-trailing-null byte is printable."""
    chars: list[str] = []
    for byte in raw.rstrip(b"\x00"):
        if not 32 <= byte <= 126:
            return None
        chars.append(chr(byte))
    return "".join(chars)


def _to_bytes_either_sign(value: int, width: int) -> bytes:
    """Pack *value* little-endian, preferring unsigned then signed encoding."""
    if value >= 0:
        try:
            return value.to_bytes(width, "little", signed=False)
        except OverflowError:
            pass
    try:
        return value.to_bytes(width, "little", signed=True)
    except OverflowError as exc:
        raise IDAError(
            f"Number {value} is too big for {width} bytes",
            IDAErrorKind.INVALID_INPUT,
        ) from exc


def convert_number(
    text: Annotated[
        str,
        Doc("Number to convert; use 0x/0o/0b prefixes or bare decimal"),
    ],
    size: ConvertNumberSizeParam = None,
) -> ConvertedNumber:
    """Convert an integer literal to decimal, hex, bytes, ASCII and binary forms."""
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise IDAError(f"Invalid number: {text}", IDAErrorKind.INVALID_INPUT) from exc

    width = size if size is not None else _minimum_byte_width(value)
    if width <= 0:
        raise IDAError("size must be greater than zero", IDAErrorKind.INVALID_INPUT)
    raw = _to_bytes_either_sign(value, width)
    return ConvertedNumber(
        decimal=value,
        hexadecimal=hex(value),
        bytes=raw.hex(" "),
        ascii=_printable_ascii(raw),
        binary=bin(value),
    )
