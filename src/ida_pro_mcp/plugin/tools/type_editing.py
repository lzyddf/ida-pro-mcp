"""High-risk C type declaration and type-application tools."""
from __future__ import annotations

from typing import Annotated

import ida_hexrays
import ida_typeinf

from ..decomp import refresh_decompiler_ctext
from ..doc import Doc
from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import format_ea
from ..funcs import get_func_or_raise
from ..ida_sync import idawrite
from ..names import resolve_name_or_address
from ..params import FunctionTargetParam, GlobalTargetParam, TypeNameParam, VariableNameParam
from ..registry import jsonrpc, unsafe
from ..types import get_type_by_name, parse_c_type
from ._decl_hook import diagnostics_supported, parse_decls_with_messages


@jsonrpc
@idawrite
@unsafe
def set_global_variable_type(target: GlobalTargetParam, new_type: TypeNameParam):
    """Set the type of a global selected by name or address."""
    ea = resolve_name_or_address(target, kind="global variable")
    tif = get_type_by_name(new_type)
    ensure_ok(
        ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL),
        f"Failed to apply type {new_type} at {format_ea(ea)}",
    )


@jsonrpc
@idawrite
@unsafe
def set_function_prototype(
    function: FunctionTargetParam,
    prototype: Annotated[str, Doc("New function prototype")],
):
    """Set a function's prototype."""
    func = get_func_or_raise(function)
    tif = parse_c_type(prototype, expect="function")
    ensure_ok(
        ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.PT_SIL),
        "Failed to apply type",
    )
    refresh_decompiler_ctext(func.start_ea)


def _build_lvar_type_modifier(var_name: str, new_type: ida_typeinf.tinfo_t):
    """Construct the SWIG subclass lazily so proxy-side imports remain safe."""

    class _LvarTypeModifier(ida_hexrays.user_lvar_modifier_t):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            ida_hexrays.user_lvar_modifier_t.__init__(self)
            self.var_name = var_name
            self.new_type = new_type

        def modify_lvars(self, lvinf):
            for lvar_saved in lvinf.lvvec:
                if lvar_saved.name == self.var_name:
                    lvar_saved.type = self.new_type
                    return True
            return False

    return _LvarTypeModifier()


_NO_DIAGNOSTICS_HINT = (
    "(parser diagnostics are only captured on Windows; "
    "re-run on Windows or check the IDA output window for details)"
)


@jsonrpc
@idawrite
@unsafe
def declare_c_type(
    c_declaration: Annotated[
        str,
        Doc(
            "C declaration, e.g. 'typedef int foo_t;' or "
            "'struct bar { int a; bool b; };'"
        ),
    ],
):
    """Create or update a local type from a C declaration."""
    flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
    errors, messages = parse_decls_with_messages(c_declaration, flags)
    pretty = "\n".join(messages) if messages else ""
    if errors > 0:
        detail = pretty if pretty else _NO_DIAGNOSTICS_HINT
        raise IDAError(
            f"Failed to parse type:\n{c_declaration}\n\nErrors:\n{detail}",
            IDAErrorKind.PARSE_FAILED,
        )
    if pretty:
        return f"success\n\nInfo:\n{pretty}"
    if not diagnostics_supported():
        return f"success {_NO_DIAGNOSTICS_HINT}"
    return "success"


@jsonrpc
@idawrite
@unsafe
def set_local_variable_type(
    function: FunctionTargetParam,
    variable_name: VariableNameParam,
    new_type: TypeNameParam,
):
    """Set a local variable's type."""
    new_tif = parse_c_type(new_type)
    func = get_func_or_raise(function)
    ensure_ok(
        ida_hexrays.rename_lvar(func.start_ea, variable_name, variable_name),
        f"Failed to find local variable: {variable_name}",
        IDAErrorKind.NOT_FOUND,
    )
    modifier = _build_lvar_type_modifier(variable_name, new_tif)
    ensure_ok(
        ida_hexrays.modify_user_lvars(func.start_ea, modifier),
        f"Failed to modify local variable: {variable_name}",
    )
    refresh_decompiler_ctext(func.start_ea)
