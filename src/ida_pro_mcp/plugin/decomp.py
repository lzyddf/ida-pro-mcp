"""Hex-Rays decompiler glue.

The Hex-Rays plugin is initialised lazily on first use. Errors are turned
into :class:`IDAError` with operator-friendly messages so the LLM can pick
the right fallback (for example, "use disassemble_function instead" when no
decompiler license is present).
"""
from __future__ import annotations

import contextlib

import ida_hexrays
import ida_kernwin
import idaapi

from .errors import IDAError, IDAErrorKind
from .format import format_ea


def decompile_checked(address: int) -> ida_hexrays.cfunc_t:
    """Decompile *address* or raise :class:`IDAError` with a useful message."""
    if not ida_hexrays.init_hexrays_plugin():
        raise IDAError(
            "Hex-Rays decompiler is not available",
            IDAErrorKind.DECOMPILER_UNAVAILABLE,
        )
    error = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile_func(address, error, ida_hexrays.DECOMP_WARNINGS)
    if not cfunc:
        if error.code == ida_hexrays.MERR_LICENSE:
            raise IDAError(
                "Decompiler license is not available. Use `disassemble_function` "
                "to get the assembly code instead.",
                IDAErrorKind.DECOMPILER_UNAVAILABLE,
            )
        message = f"Decompilation failed at {format_ea(address)}"
        if error.str:
            message += f": {error.str}"
        if error.errea != idaapi.BADADDR:
            message += f" (address: {format_ea(error.errea)})"
        raise IDAError(message, IDAErrorKind.OPERATION_FAILED)
    return cfunc  # type: ignore[return-value] (SWIG)


def refresh_decompiler_widget() -> None:
    widget = ida_kernwin.get_current_widget()
    if widget is None:
        return
    vu = ida_hexrays.get_widget_vdui(widget)
    if vu is not None:
        vu.refresh_ctext()


def refresh_decompiler_ctext(function_address: int) -> None:
    """Best-effort refresh of the pseudocode view; silent on decompiler failure."""
    with contextlib.suppress(IDAError):
        decompile_checked(function_address).refresh_func_ctext()
