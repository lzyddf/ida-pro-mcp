"""Shared helpers for debugger tool modules.

The debugger surface is split across :mod:`debug_state`, :mod:`debug_breakpoints`
and :mod:`debug_control`; this module hosts the small primitives that more
than one of them needs (notably ``_ensure_running`` and ``_list_breakpoints``).
The leading underscore keeps the auto-discovery loop in :mod:`tools` from
treating it as a tool module.
"""
from __future__ import annotations

import ida_dbg
import ida_idd

from ..errors import IDAError, IDAErrorKind
from ..format import format_ea
from ..models import Breakpoint


def ensure_debugger_running() -> ida_idd.debugger_t:
    """Return the active debugger or raise a structured error if none is."""
    dbg = ida_idd.get_dbg()
    if not dbg:
        raise IDAError("Debugger not running", IDAErrorKind.DEBUGGER_INACTIVE)
    return dbg


def current_ip_hex() -> str:
    """Return the current instruction pointer as a hex string, or raise."""
    ip = ida_dbg.get_ip_val()
    if ip is None:
        raise IDAError(
            "Debugger has no current instruction pointer",
            IDAErrorKind.DEBUGGER_INACTIVE,
        )
    return format_ea(ip)


def list_breakpoints() -> list[Breakpoint]:
    """Snapshot all currently-installed breakpoints."""
    breakpoints: list[Breakpoint] = []
    for i in range(ida_dbg.get_bpt_qty()):
        bpt = ida_dbg.bpt_t()
        if not ida_dbg.getn_bpt(i, bpt):
            continue
        breakpoints.append(Breakpoint(
            ea=format_ea(bpt.ea),
            enabled=bool(bpt.flags & ida_dbg.BPT_ENABLED),
            condition=str(bpt.condition) if bpt.condition else None,
        ))
    return breakpoints
