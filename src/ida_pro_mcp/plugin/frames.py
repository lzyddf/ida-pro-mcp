"""Stack-frame inspection helpers shared across plugin tools.

Both :mod:`.tools.stack` (RPC surface for managing frame variables) and
:mod:`.tools.disasm` (which embeds the frame layout in its function
disassembly payload) need to walk the same UDT and produce the same
:class:`StackFrameVariable` rows. Putting the walker here breaks the
horizontal ``disasm -> stack`` dependency that previously forced
``tools/`` modules to import from each other.

Keep this module free of policy decisions (rename / delete safety, etc.) --
those belong in the calling tool. Only the *read* shape lives here.
"""
from __future__ import annotations

import ida_funcs
import ida_typeinf

from .format import format_hex
from .models import StackFrameVariable


def collect_stack_frame_variables(func: ida_funcs.func_t) -> list[StackFrameVariable]:
    """Collect named (non-gap) stack frame members for *func*.

    Returns an empty list when the function has no usable frame (e.g. a
    leaf function with no locals) so callers can include the field
    unconditionally without a special-case check.
    """
    tif = ida_typeinf.tinfo_t()
    if not tif.get_type_by_tid(func.frame) or not tif.is_udt():
        return []

    udt = ida_typeinf.udt_type_data_t()
    tif.get_udt_details(udt)
    return [
        StackFrameVariable(
            name=udm.name,
            offset=format_hex(udm.offset // 8),
            size=format_hex(udm.size // 8),
            type=str(udm.type),
        )
        for udm in udt
        if not udm.is_gap()
    ]
