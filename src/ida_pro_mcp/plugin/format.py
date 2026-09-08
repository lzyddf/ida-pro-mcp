"""Number / address / byte rendering and parsing primitives.

Every wire-facing integer round-trips through these helpers so the JSON
contract (always lowercase ``0x`` hex for addresses; bare bytes joined by
spaces; etc.) stays uniform.
"""
from __future__ import annotations

from .errors import IDAError, IDAErrorKind


def format_hex(value: int) -> str:
    """Canonical lowercase hex form for arbitrary integers, e.g. ``"0x100"``.

    Used for sizes, CRCs and other non-address numerics that we still want to
    serialise as hex so they round-trip cleanly through JSON.
    """
    return f"0x{value:x}"


def format_ea(ea: int) -> str:
    """Canonical lowercase hex form for effective addresses, e.g. ``"0x401000"``.

    Every RPC payload returns addresses through this function so the wire
    contract stays uniform. Semantically distinct from :func:`format_hex` even
    though the rendering happens to match: callers should pick the right one
    so the intent is obvious to readers.
    """
    return f"0x{ea:x}"


def format_bytes(raw: bytes) -> str:
    """Render *raw* as space-separated ``0x..`` bytes (matches IDA dump style)."""
    return " ".join(f"{b:#04x}" for b in raw)


def format_padded_hex(value: int, byte_width: int) -> str:
    """Render *value* as upper-case hex, zero-padded to ``byte_width`` bytes.

    Used when displaying fixed-width fields (pointer values, struct members)
    where leading zeros carry information about the field's declared size.

    *byte_width* is a programmer-supplied invariant (always ``>= 0``); the
    guard catches local-bugs only and therefore raises :class:`ValueError`,
    not the user-facing :class:`IDAError`.
    """
    if byte_width < 0:
        raise ValueError(f"byte_width must be >= 0, got {byte_width}")
    return f"0x{value:0{byte_width * 2}X}"


def parse_ea(address: str | int) -> int:
    """Parse an effective address from a string or int.

    Addresses default to **hex** interpretation: ``"1234"`` and ``"0x1234"`` and
    ``"abc"`` all map to the same hex constants. This matches IDA's UI and the
    way reverse-engineering content is universally written. Use an explicit
    base prefix to opt out:

    * ``"0x..."`` -- hex (redundant but accepted)
    * ``"0o..."`` -- octal
    * ``"0b..."`` -- binary
    * ``"0d..."`` -- decimal (custom prefix; standard ``int`` doesn't recognise it)

    For raw integers (offsets, sizes) prefer :func:`parse_int`, which keeps
    decimal-by-default semantics.
    """
    if isinstance(address, int):
        return address

    text = address.strip()
    if not text:
        raise IDAError("Empty address", IDAErrorKind.INVALID_INPUT)

    if text[:2].lower() == "0d":
        try:
            return int(text[2:], 10)
        except ValueError as exc:
            raise IDAError(f"Failed to parse address: {address}", IDAErrorKind.INVALID_INPUT) from exc

    if text[:2].lower() in ("0x", "0o", "0b"):
        try:
            return int(text, 0)
        except ValueError as exc:
            raise IDAError(f"Failed to parse address: {address}", IDAErrorKind.INVALID_INPUT) from exc

    try:
        return int(text, 16)
    except ValueError as exc:
        raise IDAError(f"Failed to parse address: {address}", IDAErrorKind.INVALID_INPUT) from exc


def parse_int(text: str | int) -> int:
    """Parse an integer (offset, size, etc.) from text or int.

    Unlike :func:`parse_ea`, no hex fallback is performed: ``"10"`` is always
    decimal ten. Use this for non-address numeric inputs to avoid surprises.
    """
    if isinstance(text, int):
        return text
    try:
        return int(text.strip(), 0)
    except ValueError as exc:
        raise IDAError(f"Failed to parse integer: {text}", IDAErrorKind.INVALID_INPUT) from exc
