"""Breakpoint CRUD tools.

Pure breakpoint manipulation: set / delete / enable / disable. Querying
breakpoints lives in :mod:`debug_state`; debugger lifecycle in
:mod:`debug_control`.
"""
from __future__ import annotations

from typing import Annotated

import ida_dbg
import idaapi

from ..doc import Doc
from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import format_ea, parse_ea
from ..ida_sync import idawrite
from ..params import AddressParam
from ..registry import jsonrpc, unsafe


def _breakpoint_exists(ea: int) -> bool:
    """O(1) probe for a breakpoint at *ea*; avoids walking the full bpt list."""
    return ida_dbg.get_bpt(ea, ida_dbg.bpt_t())


@jsonrpc
@idawrite
@unsafe
def dbg_set_breakpoint(address: AddressParam) -> str:
    """Set a breakpoint at the specified address."""
    ea = parse_ea(address)
    if idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT):
        return f"Breakpoint set at {format_ea(ea)}"
    if _breakpoint_exists(ea):
        return f"Breakpoint already exists at {format_ea(ea)}"
    raise IDAError(
        f"Failed to set breakpoint at {format_ea(ea)}",
        IDAErrorKind.OPERATION_FAILED,
    )


@jsonrpc
@idawrite
@unsafe
def dbg_delete_breakpoint(address: AddressParam) -> str:
    """Delete a breakpoint at the specified address."""
    ea = parse_ea(address)
    ensure_ok(idaapi.del_bpt(ea), f"Failed to delete breakpoint at {format_ea(ea)}")
    return f"Deleted breakpoint at {format_ea(ea)}"


@jsonrpc
@idawrite
@unsafe
def dbg_enable_breakpoint(
    address: AddressParam,
    enable: Annotated[bool, Doc("True to enable, False to disable")],
) -> str:
    """Enable or disable a breakpoint at the specified address."""
    ea = parse_ea(address)
    verb = "enable" if enable else "disable"
    ensure_ok(
        idaapi.enable_bpt(ea, enable),
        f"Failed to {verb} breakpoint at {format_ea(ea)}",
    )
    return f"{verb.capitalize()}d breakpoint at {format_ea(ea)}"
