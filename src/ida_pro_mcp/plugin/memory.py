"""Raw IDB memory readers.

Centralises the ``ida_bytes.get_byte / get_word / get_dword / get_qword``
dispatch table so callers don't need to know which width maps to which
function. Native pointer width detection lives here too -- it depends on
``ida_ida.inf_is_64bit`` which only exists inside IDA, so isolating it keeps
the surface importable by stubs.
"""
from __future__ import annotations

import struct
from collections.abc import Callable

import ida_bytes
import ida_ida
import idautils

_FIXED_SIZE_READERS: dict[int, Callable[[int], int]] = {
    1: ida_bytes.get_byte,
    2: ida_bytes.get_word,
    4: ida_bytes.get_dword,
    8: ida_bytes.get_qword,
}


def read_fixed_int(ea: int, size: int) -> int | None:
    """Read a 1/2/4/8-byte unsigned integer at *ea*, or ``None`` for other sizes."""
    reader = _FIXED_SIZE_READERS.get(size)
    return reader(ea) if reader is not None else None


def native_pointer_size() -> int:
    """Return 8 for 64-bit IDBs, 4 otherwise."""
    return 8 if ida_ida.inf_is_64bit() else 4


def read_pointer(ea: int) -> int:
    """Read a native-width pointer at *ea*."""
    return _FIXED_SIZE_READERS[native_pointer_size()](ea)


def get_image_size() -> int:
    """Return the loaded image size, falling back to a heuristic for non-PE files."""
    image_size = ida_ida.inf_get_omax_ea() - ida_ida.inf_get_omin_ea()
    header = idautils.peutils_t().header()
    if header and header[:4] == b"PE\0\0":
        image_size = struct.unpack("<I", header[0x50:0x54])[0]
    return image_size
