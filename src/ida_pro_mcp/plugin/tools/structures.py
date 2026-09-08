"""Structure / UDT inspection tools."""
from __future__ import annotations

import logging

import ida_bytes
import ida_typeinf

from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import format_ea, format_hex, format_padded_hex, parse_ea
from ..ida_sync import idaread
from ..memory import native_pointer_size, read_fixed_int, read_pointer
from ..models import (
    Page,
    StructureAtAddress,
    StructureDefinition,
    StructureMember,
    StructureMemberValue,
)
from ..params import (
    AddressParam,
    FilterParam,
    PageCountParam,
    PageOffsetParam,
    StructureNameParam,
)
from ..registry import jsonrpc
from ._helpers import paginate, substring_filter

logger = logging.getLogger(__name__)


def _udt_members(tif: ida_typeinf.tinfo_t) -> list[StructureMember]:
    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        return []
    return [
        StructureMember(
            name=m.name,
            offset=format_hex(m.offset // 8),
            size=format_hex(m.size // 8),
            type=str(m.type),
        )
        for m in udt
    ]


def _resolve_named_udt(name: str) -> ida_typeinf.tinfo_t:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, name):
        raise IDAError(f"Structure '{name}' not found", IDAErrorKind.NOT_FOUND)
    if not tif.is_udt():
        raise IDAError(f"'{name}' is not a user-defined type", IDAErrorKind.INVALID_INPUT)
    return tif


@jsonrpc
@idaread
def list_structures(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
    filter: FilterParam = "",
) -> Page[StructureDefinition]:
    """List defined structures (paginated, optionally filtered by name)"""
    out: list[StructureDefinition] = []
    for ordinal in range(1, ida_typeinf.get_ordinal_limit()):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal) or not tif.is_udt():
            continue
        name = tif.get_type_name() or f"<Anonymous Type #{ordinal}>"
        out.append(StructureDefinition(
            name=name,
            size=format_ea(tif.get_size()),
            members=_udt_members(tif),
        ))
    return paginate(substring_filter(out, filter, "name"), offset, count)


@jsonrpc
@idaread
def get_structure(name: StructureNameParam) -> StructureDefinition:
    """Get a single structure definition by name"""
    tif = _resolve_named_udt(name)
    return StructureDefinition(
        name=name,
        size=format_hex(tif.get_size()),
        members=_udt_members(tif),
    )


_DUMP_BYTES_LIMIT = 16


def _read_member_value(member_addr: int, member_type: ida_typeinf.tinfo_t, member_size: int) -> str:
    try:
        if member_type.is_ptr():
            return format_padded_hex(read_pointer(member_addr), native_pointer_size())

        value = read_fixed_int(member_addr, member_size)
        if value is not None:
            return f"{format_padded_hex(value, member_size)} ({value})"

        chunk_size = min(member_size, _DUMP_BYTES_LIMIT) if member_size > 0 else _DUMP_BYTES_LIMIT
        chunk = ida_bytes.get_bytes(member_addr, chunk_size) or b""
        formatted = " ".join(f"{b:02X}" for b in chunk)
        return f"[{formatted}{'...' if member_size > _DUMP_BYTES_LIMIT else ''}]"
    except Exception as e:
        logger.debug("failed to read member at %#x: %s", member_addr, e)
        return "<failed to read>"


@jsonrpc
@idaread
def get_structure_at_address(
    address: AddressParam,
    struct_name: StructureNameParam,
) -> StructureAtAddress:
    """Read structure field values at a specific address"""
    addr = parse_ea(address)
    tif = _resolve_named_udt(struct_name)

    udt_data = ida_typeinf.udt_type_data_t()
    ensure_ok(tif.get_udt_details(udt_data), "Failed to get structure details")

    members: list[StructureMemberValue] = []
    for member in udt_data:
        offset_bytes = member.begin() // 8
        member_addr = addr + offset_bytes
        member_size = member.type.get_size()

        info: StructureMemberValue = {
            "name": member.name,
            "offset": format_ea(offset_bytes),
            "type": str(member.type),
            "size": int(member_size),
            "value": _read_member_value(member_addr, member.type, member_size),
        }
        if member.type.is_udt():
            info["is_nested_udt"] = True
        members.append(info)

    return StructureAtAddress(
        struct_name=struct_name,
        address=format_ea(addr),
        members=members,
    )
