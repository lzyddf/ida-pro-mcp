"""Read-only debugger state inspection (registers, call stack, breakpoints).

Pure observers -- they never start, stop or step the debuggee. The actual
control surface lives in :mod:`debug_control`; CRUD on breakpoints lives in
:mod:`debug_breakpoints`.
"""
from __future__ import annotations

import os

import ida_dbg
import ida_idd
import ida_name

from ..format import format_ea
from ..ida_sync import idaread
from ..models import Breakpoint, CallStackFrame, RegisterValue, ThreadRegisters
from ..registry import jsonrpc, unsafe
from ._debug_common import ensure_debugger_running, list_breakpoints


def _format_register_value(value: object) -> str:
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, bytes):
        return value.hex(" ")
    return str(value)


@jsonrpc
@idaread
@unsafe
def dbg_get_registers() -> list[ThreadRegisters]:
    """Get all registers and their values. Only available while debugging."""
    dbg = ensure_debugger_running()
    result: list[ThreadRegisters] = []
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        regs: list[RegisterValue] = []
        for reg_index, rv in enumerate(ida_dbg.get_reg_vals(tid)):
            reg_info = dbg.regs(reg_index)
            regs.append(RegisterValue(
                name=reg_info.name,
                value=_format_register_value(rv.pyval(reg_info.dtype)),
            ))
        result.append(ThreadRegisters(thread_id=tid, registers=regs))
    return result


def _build_callstack_frame(frame) -> CallStackFrame:
    info: CallStackFrame = {"address": format_ea(frame.callea)}
    try:
        module_info = ida_idd.modinfo_t()
        info["module"] = (
            os.path.basename(module_info.name)
            if ida_dbg.get_module_info(frame.callea, module_info)
            else "<unknown>"
        )
        info["symbol"] = (
            ida_name.get_nice_colored_name(
                frame.callea,
                ida_name.GNCN_NOCOLOR
                | ida_name.GNCN_NOLABEL
                | ida_name.GNCN_NOSEG
                | ida_name.GNCN_PREFDBG,
            )
            or "<unnamed>"
        )
    except Exception as e:
        info["error"] = str(e)
    return info


@jsonrpc
@idaread
@unsafe
def dbg_get_call_stack() -> list[CallStackFrame]:
    """Get the current call stack."""
    tid = ida_dbg.get_current_thread()
    trace = ida_idd.call_stack_t()
    if not ida_dbg.collect_stack_trace(tid, trace):
        return []
    return [_build_callstack_frame(frame) for frame in trace]


@jsonrpc
@idaread
@unsafe
def dbg_list_breakpoints() -> list[Breakpoint]:
    """List all breakpoints in the program."""
    return list_breakpoints()
