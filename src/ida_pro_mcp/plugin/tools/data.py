"""Memory / global value read tools."""
from __future__ import annotations

import base64
from typing import Annotated, Literal

import ida_bytes
import ida_nalt
import ida_typeinf
import idaapi

from ..doc import Doc
from ..errors import IDAError, IDAErrorKind
from ..format import format_bytes, format_ea, parse_ea
from ..ida_sync import idaread
from ..memory import read_fixed_int
from ..names import resolve_name_or_address
from ..params import AddressParam, GlobalTargetParam
from ..registry import jsonrpc

ValueKind = Literal["byte", "word", "dword", "qword", "string"]
BytesFormat = Literal["hex_spaced", "hex_compact", "base64"]

_NAMED_SIZES: dict[str, int] = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def _format_raw_bytes(raw: bytes, output_format: BytesFormat) -> str:
    """Render ``raw`` according to ``output_format``.

    ``hex_spaced`` (default) preserves the historical wire format (one
    ``0xNN`` per byte joined by spaces) so existing clients keep working.
    ``hex_compact`` is the same payload without the ``0x`` prefixes or
    spaces -- ~4x more compact, friendlier to LLM token budgets. ``base64``
    is the densest option for arbitrary binary data and round-trips through
    JSON without escaping.
    """
    if output_format == "hex_spaced":
        return format_bytes(raw)
    if output_format == "hex_compact":
        return raw.hex()
    if output_format == "base64":
        return base64.b64encode(raw).decode("ascii")
    raise IDAError(
        f"Unknown output_format: {output_format!r} "
        "(expected 'hex_spaced', 'hex_compact', or 'base64')",
        IDAErrorKind.INVALID_INPUT,
    )


def _read_typed_global(ea: int) -> str:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        size = tif.get_size()
        if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if raw is None:
                raise IDAError(
                    f"Failed to read string at {format_ea(ea)}", IDAErrorKind.OPERATION_FAILED
                )
            return f'"{raw.decode("utf-8", errors="replace").strip()}"'
    elif ida_bytes.has_any_name(ea):
        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise IDAError(
                f"Failed to get size for variable at {format_ea(ea)}",
                IDAErrorKind.OPERATION_FAILED,
            )
    else:
        raise IDAError(
            f"Failed to get type information for variable at {format_ea(ea)}",
            IDAErrorKind.NOT_FOUND,
        )

    return _read_any_size(ea, size)


def _read_any_size(ea: int, size: int) -> str:
    value = read_fixed_int(ea, size)
    if value is not None:
        return hex(value)
    raw = ida_bytes.get_bytes(ea, size) or b""
    return format_bytes(raw)


_KIND_DESCRIPTION = (
    "Read mode. 'byte' / 'word' / 'dword' / 'qword' return one fixed-width "
    "integer as 0x...; 'string' returns a NUL-terminated literal."
)
_OUTPUT_FORMAT_DESCRIPTION = (
    "Byte rendering: 'hex_compact' (default) is bare hex, 'hex_spaced' is "
    "the legacy 0x.. 0x.. form, and 'base64' is densest for binary blobs."
)


@jsonrpc
@idaread
def get_global_variable_value(target: GlobalTargetParam) -> str:
    """Read a typed global variable selected by name or address."""
    return _read_typed_global(resolve_name_or_address(target, kind="global variable"))


@jsonrpc
@idaread
def read_value(
    address: AddressParam,
    kind: Annotated[ValueKind, Doc(_KIND_DESCRIPTION)],
) -> str:
    """Read a fixed-width integer or NUL-terminated string at an address."""
    ea = parse_ea(address)
    if kind in _NAMED_SIZES:
        value = read_fixed_int(ea, _NAMED_SIZES[kind])
        if value is None:
            raise IDAError(f"Unsupported width for kind={kind!r}", IDAErrorKind.INVALID_INPUT)
        return hex(value)
    if kind == "string":
        raw = idaapi.get_strlit_contents(ea, -1, 0)
        if raw is None:
            raise IDAError(
                f"Failed to read string at {format_ea(ea)}",
                IDAErrorKind.OPERATION_FAILED,
            )
        return raw.decode("utf-8", errors="replace")
    raise IDAError(f"Unknown value kind: {kind!r}", IDAErrorKind.INVALID_INPUT)


@jsonrpc
@idaread
def read_bytes(
    address: AddressParam,
    size: Annotated[int, Doc("Number of bytes to read", gt=0)],
    output_format: Annotated[
        BytesFormat, Doc(_OUTPUT_FORMAT_DESCRIPTION)
    ] = "hex_compact",
) -> str:
    """Read raw bytes at an address using a compact selectable encoding."""
    ea = parse_ea(address)
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None or len(raw) != size:
        actual = 0 if raw is None else len(raw)
        raise IDAError(
            f"Failed to read {size} bytes at {format_ea(ea)} (read {actual})",
            IDAErrorKind.OPERATION_FAILED,
        )
    return _format_raw_bytes(raw, output_format)
