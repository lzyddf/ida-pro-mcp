"""Function lookup helpers.

Wraps the ``idaapi.get_func`` call shape into the typed :class:`Function`
schema that we expose on the wire, plus a strict ``raise-on-missing`` variant
used by every write-side tool.
"""
from __future__ import annotations

from typing import Literal, overload

import ida_funcs
import idaapi

from .errors import IDAError, IDAErrorKind
from .format import format_ea, format_hex, parse_ea
from .models import Function
from .names import resolve_function_target


@overload
def get_function(address: int, *, raise_error: Literal[True]) -> Function: ...
@overload
def get_function(address: int) -> Function: ...
@overload
def get_function(address: int, *, raise_error: Literal[False]) -> Function | None: ...


def get_function(address: int, *, raise_error: bool = True) -> Function | None:
    """Build the wire-shaped :class:`Function` payload for *address*.

    With ``raise_error=False`` returns ``None`` when no function exists at
    *address*; the default raises :class:`IDAError` so callers don't need to
    repeat the null check.
    """
    fn = idaapi.get_func(address)
    if fn is None:
        if raise_error:
            raise IDAError(
                f"No function found at address {format_ea(address)}",
                IDAErrorKind.NOT_FOUND,
            )
        return None
    # IDA 9.0 dropped the ``func_t.get_name`` shortcut; the canonical
    # name lookup is ``ida_funcs.get_func_name(ea)`` which works on
    # every supported version. Use ``start_ea`` (not the caller's
    # ``address``, which may point mid-function) so the returned name
    # always matches what IDA shows in the function list.
    return Function(
        address=format_ea(fn.start_ea),
        name=ida_funcs.get_func_name(fn.start_ea) or "",
        size=format_hex(fn.end_ea - fn.start_ea),
    )


def get_func_or_raise(target: str | int) -> ida_funcs.func_t:
    """Resolve a function name/address or raise :class:`IDAError` if missing.

    Centralises the ``get_func + None check`` pattern used by every write-side tool.
    """
    ea = parse_ea(target) if isinstance(target, int) else resolve_function_target(target)
    func = idaapi.get_func(ea)
    if not func:
        raise IDAError(
            f"No function found at address {format_ea(ea)}",
            IDAErrorKind.NOT_FOUND,
        )
    return func
