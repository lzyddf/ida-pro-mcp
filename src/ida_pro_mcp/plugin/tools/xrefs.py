"""Cross-reference tools."""
from __future__ import annotations

import ida_idaapi
import ida_typeinf
import idautils

from ..errors import IDAErrorKind, ensure_ok
from ..format import format_ea, parse_ea
from ..funcs import get_function
from ..ida_sync import idaread
from ..models import Xref
from ..params import AddressParam, FieldNameParam, StructureNameParam
from ..registry import jsonrpc


def _xref_for(addr: int, iscode: bool) -> Xref:
    return Xref(
        address=format_ea(addr),
        type="code" if iscode else "data",
        function=get_function(addr, raise_error=False),
    )


@jsonrpc
@idaread
def get_xrefs_to(address: AddressParam) -> list[Xref]:
    """Get all cross references to the given address"""
    target = parse_ea(address)
    return [_xref_for(xref.frm, bool(xref.iscode)) for xref in idautils.XrefsTo(target)]  # type: ignore[attr-defined]


@jsonrpc
@idaread
def get_xrefs_to_field(
    struct_name: StructureNameParam,
    field_name: FieldNameParam,
) -> list[Xref]:
    """Get all cross references to a named struct field (member)"""
    til = ida_typeinf.get_idati()
    ensure_ok(til, "Failed to retrieve type library.")

    tif = ida_typeinf.tinfo_t()
    ensure_ok(
        tif.get_named_type(til, struct_name, ida_typeinf.BTF_STRUCT, True, False),
        f"Structure '{struct_name}' not found",
        IDAErrorKind.NOT_FOUND,
    )

    idx = ida_typeinf.get_udm_by_fullname(None, f"{struct_name}.{field_name}")  # type: ignore[arg-type]
    ensure_ok(
        idx != -1,
        f"Field '{field_name}' not found in structure '{struct_name}'",
        IDAErrorKind.NOT_FOUND,
    )

    tid = tif.get_udm_tid(idx)
    ensure_ok(
        tid != ida_idaapi.BADADDR,
        f"Unable to get tid for structure '{struct_name}' and field '{field_name}'",
    )

    return [_xref_for(xref.frm, bool(xref.iscode)) for xref in idautils.XrefsTo(tid)]  # type: ignore[attr-defined]
