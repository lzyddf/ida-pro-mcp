"""Disassembler tools."""
from __future__ import annotations

import ida_funcs
import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from ..format import format_ea
from ..frames import collect_stack_frame_variables
from ..funcs import get_func_or_raise
from ..ida_sync import idaread
from ..models import Argument, DisassemblyFunction, DisassemblyLine
from ..params import FunctionTargetParam
from ..registry import jsonrpc


def _disasm_one(ea: int, func_name: str, func_start: int) -> DisassemblyLine:
    seg = idaapi.getseg(ea)
    segment: str | None = idaapi.get_segm_name(seg) if seg else None

    label: str | None = idc.get_name(ea, 0)
    if not label or (label == func_name and ea == func_start):
        label = None

    comments: list[str] = []
    for repeatable in (False, True):
        cmt = idaapi.get_cmt(ea, repeatable)
        if cmt:
            comments.append(cmt)

    mnem: str = idc.print_insn_mnem(ea) or ""
    ops: list[str] = []
    for op_index in range(idaapi.UA_MAXOP):
        if idc.get_operand_type(ea, op_index) == idaapi.o_void:
            break
        ops.append(idc.print_operand(ea, op_index) or "")
    instruction = f"{mnem} {', '.join(ops)}".rstrip()

    line: DisassemblyLine = {"address": format_ea(ea), "instruction": instruction}
    if segment:
        line["segment"] = segment
    if label:
        line["label"] = label
    if comments:
        line["comments"] = comments
    return line


def _func_signature(func_ea: int) -> tuple[str | None, list[Argument] | None]:
    tif = ida_typeinf.tinfo_t()
    if not (ida_nalt.get_tinfo(tif, func_ea) and tif.is_func()):
        return None, None
    ftd = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(ftd):
        return None, None
    return (
        str(ftd.rettype),
        [Argument(name=(a.name or f"arg{i}"), type=str(a.type)) for i, a in enumerate(ftd)],
    )


@jsonrpc
@idaread
def disassemble_function(function: FunctionTargetParam) -> DisassemblyFunction:
    """Get assembly code for a function."""
    func: ida_funcs.func_t = get_func_or_raise(function)
    func_name: str = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"

    lines = [
        _disasm_one(ea, func_name, func.start_ea)
        for ea in idautils.FuncItems(func.start_ea)
        if ea != idaapi.BADADDR
    ]
    rettype, args = _func_signature(func.start_ea)

    out: DisassemblyFunction = {
        "name": func_name,
        "start_ea": format_ea(func.start_ea),
        "stack_frame": collect_stack_frame_variables(func),
        "lines": lines,
    }
    if rettype:
        out["return_type"] = rettype
    if args is not None:
        out["arguments"] = args
    return out


def _render_disasm_text(line: DisassemblyLine) -> str:
    """Format one :class:`DisassemblyLine` into a single ``addr  instr ; cmt`` row.

    Labels are emitted on their own line above the instruction (mirroring
    IDA's default listing) so callers can still grep for ``loc_xxx:``.
    """
    head = f"{line['address']}  {line['instruction']}"
    comments = line.get("comments")
    if comments:
        head = f"{head}  ; {'; '.join(comments)}"
    label = line.get("label")
    return f"{label}:\n{head}" if label else head


@jsonrpc
@idaread
def disassemble_function_text(
    function: FunctionTargetParam,
) -> str:
    """Disassemble a function and return the listing as a single string.

    Token-cheaper alternative to :func:`disassemble_function` when the
    caller only needs the rendered text. Each line follows the format
    ``<addr>  <instruction>[  ; <comments>]``; user-defined labels are
    emitted on their own line, the same way IDA's listing renders them.
    """
    func = get_func_or_raise(function)
    func_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    return "\n".join(
        _render_disasm_text(_disasm_one(insn_ea, func_name, func.start_ea))
        for insn_ea in idautils.FuncItems(func.start_ea)
        if insn_ea != idaapi.BADADDR
    )
