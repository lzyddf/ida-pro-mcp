"""Decompiler-backed tools."""
from __future__ import annotations

import ida_hexrays
import ida_lines
import idaapi

from ..decomp import decompile_checked
from ..format import format_ea
from ..ida_sync import idaread
from ..models import DecompiledLine
from ..names import resolve_function_target
from ..params import FunctionTargetParam
from ..registry import jsonrpc


def _line_address(cfunc: ida_hexrays.cfunc_t, sl, line_idx: int) -> int | None:
    """Best-effort address extraction for one pseudocode line.

    The entry line always maps to the function start. For other lines we
    consult the ctree item at column 0:

    1. Prefer the item's ``ea`` attribute when present (preferred path -- it
       comes straight from the SDK).
    2. Fall back to parsing ``"<hex addr>: ..."`` out of ``item.dstr()``
       when the SDK does not expose a usable ``ea``. This rendering is *not*
       a documented contract, so it can drift across IDA minor versions; if
       we ever stop seeing addresses in the output, look here first.
    """
    if line_idx == 0:
        return cfunc.entry_ea

    item = ida_hexrays.ctree_item_t()
    if not cfunc.get_line_item(sl.line, 0, False, None, item, None):  # type: ignore[arg-type]
        return None

    ea = getattr(item, "ea", None)
    if isinstance(ea, int) and ea != idaapi.BADADDR:
        return ea

    rendered = item.dstr()
    if not rendered:
        return None
    head, _, _ = rendered.partition(": ")
    try:
        return int(head, 16)
    except ValueError:
        return None


@jsonrpc
@idaread
def decompile_function(function: FunctionTargetParam) -> list[DecompiledLine]:
    """Decompile a named/addressed function with per-line address mapping."""
    start = resolve_function_target(function)
    cfunc = decompile_checked(start)

    out: list[DecompiledLine] = []
    for i, sl in enumerate(cfunc.get_pseudocode()):
        text = ida_lines.tag_remove(sl.line)
        addr = _line_address(cfunc, sl, i)
        entry: DecompiledLine = {"line": i, "text": text}
        if addr is not None:
            entry["address"] = format_ea(addr)
        out.append(entry)
    return out


@jsonrpc
@idaread
def decompile_function_text(
    function: FunctionTargetParam,
) -> str:
    """Decompile a function and return the pseudocode as a single string.

    Token-cheaper alternative to :func:`decompile_function` when the caller
    only needs the rendered code and not the per-line address mapping.
    """
    ea = resolve_function_target(function)
    cfunc = decompile_checked(ea)
    return "\n".join(ida_lines.tag_remove(sl.line) for sl in cfunc.get_pseudocode())
