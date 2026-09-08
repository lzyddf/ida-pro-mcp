"""Function-level RPC tools (lookup, listing, callees, callers, entry points)."""
from __future__ import annotations

import ida_entry
import idaapi
import idautils
import idc

from ..format import format_ea
from ..funcs import get_func_or_raise
from ..funcs import get_function as make_function
from ..ida_sync import idaread
from ..models import Callee, Function, Page
from ..names import resolve_function_target
from ..params import (
    FunctionTargetParam,
    PageCountParam,
    PageOffsetParam,
)
from ..registry import jsonrpc
from ._helpers import paginate

_CALL_OPS = (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni)
_DIRECT_CALL_OP_TYPES = (idaapi.o_mem, idaapi.o_near, idaapi.o_far)


@jsonrpc
@idaread
def get_function(function: FunctionTargetParam) -> Function:
    """Get a function by name or by any address inside it."""
    return make_function(resolve_function_target(function))


@jsonrpc
@idaread
def list_functions(
    offset: PageOffsetParam = 0,
    count: PageCountParam = 100,
) -> Page[Function]:
    """List all functions in the database (paginated)"""
    functions = [make_function(address) for address in idautils.Functions()]
    return paginate(functions, offset, count)


@jsonrpc
@idaread
def get_callees(function: FunctionTargetParam) -> list[Callee]:
    """Get all direct callees of a function selected by name or address."""
    func = get_func_or_raise(function)
    func_start = func.start_ea
    func_end = idc.find_func_end(func_start)

    seen: set[tuple[str, str, str]] = set()
    callees: list[Callee] = []
    current_ea = func_start
    while current_ea < func_end:
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, current_ea)
        if insn.itype in _CALL_OPS:
            target = idc.get_operand_value(current_ea, 0)
            target_type = idc.get_operand_type(current_ea, 0)
            if target_type in _DIRECT_CALL_OP_TYPES:
                func_type = "internal" if idaapi.get_func(target) is not None else "external"
                func_name = idc.get_name(target)
                if func_name:
                    address = format_ea(target)
                    key = (address, func_name, func_type)
                    if key not in seen:
                        seen.add(key)
                        callees.append(Callee(address=address, name=func_name, type=func_type))
        current_ea = idc.next_head(current_ea, func_end)
    return callees


@jsonrpc
@idaread
def get_callers(function: FunctionTargetParam) -> list[Function]:
    """Get each function that directly calls the selected function."""
    target = get_func_or_raise(function).start_ea
    callers: dict[str, Function] = {}
    for caller_address in idautils.CodeRefsTo(target, 0):
        func = make_function(caller_address, raise_error=False)
        if not func:
            continue
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, caller_address)
        if insn.itype not in _CALL_OPS:
            continue
        callers[func["address"]] = func
    return list(callers.values())


@jsonrpc
@idaread
def get_entry_points() -> list[Function]:
    """Get all entry points in the database"""
    result: list[Function] = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        func = make_function(address, raise_error=False)
        if func is not None:
            result.append(func)
    return result
