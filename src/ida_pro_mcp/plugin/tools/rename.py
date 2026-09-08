"""Reversible rename tools for functions, local variables and globals."""
from __future__ import annotations

import ida_hexrays
import idaapi

from ..decomp import refresh_decompiler_ctext
from ..errors import ensure_ok
from ..format import format_ea
from ..funcs import get_func_or_raise
from ..ida_sync import idawrite
from ..names import resolve_name_ea_or_raise
from ..params import FunctionTargetParam, NewNameParam, OldNameParam
from ..registry import jsonrpc


@jsonrpc
@idawrite
def rename_local_variable(
    function: FunctionTargetParam,
    old_name: OldNameParam,
    new_name: NewNameParam,
):
    """Rename a local variable in a function."""
    func = get_func_or_raise(function)
    ensure_ok(
        ida_hexrays.rename_lvar(func.start_ea, old_name, new_name),
        f"Failed to rename local variable {old_name} in function {format_ea(func.start_ea)}",
    )
    refresh_decompiler_ctext(func.start_ea)


@jsonrpc
@idawrite
def rename_global_variable(old_name: OldNameParam, new_name: NewNameParam):
    """Rename a global variable."""
    ea = resolve_name_ea_or_raise(old_name, kind="global variable")
    ensure_ok(
        idaapi.set_name(ea, new_name),
        f"Failed to rename global variable {old_name} to {new_name}",
    )
    refresh_decompiler_ctext(ea)


@jsonrpc
@idawrite
def rename_function(function: FunctionTargetParam, new_name: NewNameParam):
    """Rename a function selected by name or address."""
    func = get_func_or_raise(function)
    ensure_ok(
        idaapi.set_name(func.start_ea, new_name),
        f"Failed to rename function {format_ea(func.start_ea)} to {new_name}",
    )
    refresh_decompiler_ctext(func.start_ea)
