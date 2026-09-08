"""Debugger lifecycle controls (start, stop, step, run-to).

Process state changes that alter the debuggee. Read-only inspection lives in
:mod:`debug_state`; breakpoint CRUD in :mod:`debug_breakpoints`.
"""
from __future__ import annotations

import logging
from typing import Annotated

import ida_dbg
import ida_entry
import ida_idaapi
import idaapi

from ..doc import Doc
from ..errors import ensure_ok
from ..format import format_ea, parse_ea
from ..ida_sync import idawrite
from ..params import AddressParam
from ..registry import jsonrpc, unsafe
from ._debug_common import current_ip_hex, ensure_debugger_running, list_breakpoints

logger = logging.getLogger(__name__)


def _seed_entry_breakpoints() -> int:
    added = 0
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        if address != ida_idaapi.BADADDR and ida_dbg.add_bpt(address, 0, idaapi.BPT_SOFT):
            added += 1
    return added


@jsonrpc
@idawrite
@unsafe
def dbg_start_process(
    auto_breakpoint_at_entry: Annotated[
        bool,
        Doc(
            "When True (default) and no breakpoints exist, seed one at each entry "
            "point so the process pauses immediately. Set False to start without "
            "modifying breakpoints."
        ),
    ] = True,
) -> str:
    """Start the debugger; returns the current instruction pointer."""
    if auto_breakpoint_at_entry and not list_breakpoints():
        added = _seed_entry_breakpoints()
        if added:
            logger.info("dbg_start_process: auto-added %d breakpoint(s) at entry points", added)

    ensure_ok(
        idaapi.start_process("", "", "") == 1,
        "Failed to start debugger (did the user configure the debugger first?)",
    )
    return current_ip_hex()


@jsonrpc
@idawrite
@unsafe
def dbg_exit_process() -> str:
    """Exit the debugger."""
    ensure_debugger_running()
    ensure_ok(idaapi.exit_process(), "Failed to exit debugger")
    return "ok"


@jsonrpc
@idawrite
@unsafe
def dbg_continue_process() -> str:
    """Continue execution; returns the current instruction pointer."""
    ensure_debugger_running()
    ensure_ok(idaapi.continue_process(), "Failed to continue debugger")
    return current_ip_hex()


@jsonrpc
@idawrite
@unsafe
def dbg_run_to(address: AddressParam) -> str:
    """Run the debugger to the specified address."""
    ensure_debugger_running()
    ea = parse_ea(address)
    ensure_ok(idaapi.run_to(ea), f"Failed to run to address {format_ea(ea)}")
    return current_ip_hex()


@jsonrpc
@idawrite
@unsafe
def dbg_step_into() -> str:
    """Step into the current instruction."""
    ensure_debugger_running()
    ensure_ok(idaapi.step_into(), "Failed to step into")
    return current_ip_hex()


@jsonrpc
@idawrite
@unsafe
def dbg_step_over() -> str:
    """Step over the current instruction."""
    ensure_debugger_running()
    ensure_ok(idaapi.step_over(), "Failed to step over")
    return current_ip_hex()
