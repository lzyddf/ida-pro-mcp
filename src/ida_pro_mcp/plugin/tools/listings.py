"""Listing tools: globals, imports, strings, local types, segments."""
from __future__ import annotations

import logging

import ida_nalt
import ida_segment
import ida_typeinf
import idaapi
import idautils

from ..format import format_ea
from ..ida_sync import idaread
from ..models import Global, Import, Page, Segment, String
from ..params import FilterParam, PageCountParam, PageOffsetParam
from ..registry import jsonrpc
from ._helpers import paginate, substring_filter

logger = logging.getLogger(__name__)


_SEGMENT_CLASSES: dict[int, str] = {
    idaapi.SEG_CODE: "CODE",
    idaapi.SEG_DATA: "DATA",
    idaapi.SEG_BSS: "BSS",
    idaapi.SEG_NULL: "NULL",
    idaapi.SEG_XTRN: "XTRN",
    idaapi.SEG_COMM: "COMM",
    idaapi.SEG_ABSSYM: "ABSSYM",
    idaapi.SEG_GRP: "GRP",
    idaapi.SEG_IMP: "IMP",
}

_BITNESS_TABLE: tuple[int, ...] = (16, 32, 64)


def _segment_perms(perm: int) -> str:
    """Render an IDA segment ``perm`` bitmask as the conventional ``rwx`` triple."""
    if perm == 0:
        # IDA reports 0 when permissions weren't recorded by the loader; the
        # tristate "unknown" reads more honestly as dashes than as "---" with
        # an implicit no-permission claim.
        return "???"
    return (
        ("r" if perm & idaapi.SEGPERM_READ else "-")
        + ("w" if perm & idaapi.SEGPERM_WRITE else "-")
        + ("x" if perm & idaapi.SEGPERM_EXEC else "-")
    )


@jsonrpc
@idaread
def list_globals(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
    filter: FilterParam = "",
) -> Page[Global]:
    """List globals in the database (paginated, optionally filtered)"""
    items: list[Global] = [
        Global(address=format_ea(addr), name=name)
        for addr, name in idautils.Names()
        if not idaapi.get_func(addr)
    ]
    return paginate(substring_filter(items, filter, "name"), offset, count)


def _make_import_accumulator(rv: list[Import], module_name: str):
    """Build an enum_import_names callback bound to *module_name*.

    Defining the closure outside the loop avoids the late-binding pitfall
    that would otherwise have every callback see the final module name.
    """
    def _accumulate(ea: int, symbol_name: str | None, ordinal: int) -> bool:
        name = symbol_name or f"#{ordinal}"
        rv.append(Import(address=format_ea(ea), imported_name=name, module=module_name))
        return True

    return _accumulate


@jsonrpc
@idaread
def list_imports(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
) -> Page[Import]:
    """List all imported symbols with their name and module (paginated)"""
    rv: list[Import] = []
    for module_idx in range(ida_nalt.get_import_module_qty()):
        module_name = ida_nalt.get_import_module_name(module_idx) or "<unnamed>"
        ida_nalt.enum_import_names(module_idx, _make_import_accumulator(rv, module_name))
    return paginate(rv, offset, count)


@jsonrpc
@idaread
def list_strings(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
    filter: FilterParam = "",
) -> Page[String]:
    """List strings in the database (paginated, optionally filtered)"""
    strings: list[String] = []
    for item in idautils.Strings():
        if item is None:
            continue
        try:
            text = str(item)
        except Exception as exc:
            logger.debug("failed to decode string at %#x: %s", item.ea, exc)
            continue
        if text:
            strings.append(String(address=format_ea(item.ea), length=item.length, string=text))
    return paginate(substring_filter(strings, filter, "string"), offset, count)


def _format_local_type(ordinal: int, tif: ida_typeinf.tinfo_t) -> str:
    type_name = tif.get_type_name() or f"<Anonymous Type #{ordinal}>"
    pieces = [f"\nType #{ordinal}: {type_name}"]

    if tif.is_udt():
        flags = (
            ida_typeinf.PRTYPE_MULTI
            | ida_typeinf.PRTYPE_TYPE
            | ida_typeinf.PRTYPE_SEMI
            | ida_typeinf.PRTYPE_DEF
            | ida_typeinf.PRTYPE_METHODS
            | ida_typeinf.PRTYPE_OFFSETS
        )
        decl = tif._print(None, flags)
        if decl:
            pieces.append(f"  C declaration:\n{decl}")
    else:
        decl = tif._print(
            None,
            ida_typeinf.PRTYPE_1LINE | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI,
        )
        if decl:
            pieces.append(f"  Simple declaration:\n{decl}")
    return "".join(pieces)


def _local_type_entries() -> list[dict[str, str]]:
    """Materialise every local type as a ``{"name", "decl"}`` row.

    Wrapped in dicts so :func:`substring_filter` (which keys on field name)
    can filter on ``name`` without re-parsing the rendered declaration.
    """
    rows: list[dict[str, str]] = []
    idati = ida_typeinf.get_idati()
    for ordinal in range(1, ida_typeinf.get_ordinal_limit(idati)):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(idati, ordinal):
            continue
        name = tif.get_type_name() or f"<Anonymous Type #{ordinal}>"
        rows.append({"name": name, "decl": _format_local_type(ordinal, tif)})
    return rows


@jsonrpc
@idaread
def list_segments() -> list[Segment]:
    """List the segments / sections of the loaded binary.

    One entry per IDA segment, ordered by start address, with the rendered
    permission triple, the IDA segment class (``CODE``/``DATA``/``BSS``/...),
    and the bitness. Useful as an early "what's in this binary" overview
    before drilling into specific addresses.
    """
    rv: list[Segment] = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(start)
        if seg is None:
            continue
        entry: Segment = {
            "name": ida_segment.get_segm_name(seg) or "",
            "start": format_ea(seg.start_ea),
            "end": format_ea(seg.end_ea),
            "perms": _segment_perms(seg.perm),
        }
        sclass = _SEGMENT_CLASSES.get(seg.type)
        if sclass:
            entry["sclass"] = sclass
        bitness_idx = seg.bitness
        if 0 <= bitness_idx < len(_BITNESS_TABLE):
            entry["bitness"] = _BITNESS_TABLE[bitness_idx]
        rv.append(entry)
    return rv


@jsonrpc
@idaread
def list_local_types(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
    filter: FilterParam = "",
) -> Page[str]:
    """List Local types in the database (paginated, optionally filtered by name)"""
    rows = substring_filter(_local_type_entries(), filter, "name")
    return paginate([row["decl"] for row in rows], offset, count)
