"""Stack-frame variable tools."""
from __future__ import annotations

from dataclasses import dataclass

import ida_frame
import ida_funcs
import ida_typeinf

from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import parse_int
from ..frames import collect_stack_frame_variables
from ..funcs import get_func_or_raise
from ..ida_sync import idaread, idawrite
from ..models import StackFrameVariable
from ..params import (
    FunctionTargetParam,
    NewNameParam,
    OffsetParam,
    OldNameParam,
    TypeNameParam,
    VariableNameParam,
)
from ..registry import jsonrpc, unsafe
from ..types import get_type_by_name


@jsonrpc
@idaread
def get_stack_frame_variables(function: FunctionTargetParam) -> list[StackFrameVariable]:
    """Retrieve the stack frame variables for a given function"""
    return collect_stack_frame_variables(get_func_or_raise(function))


@dataclass(frozen=True)
class _ResolvedFrameMember:
    """Cached frame-member lookup result.

    Stores *plain values* extracted from the udt member so the SWIG-owned
    ``udt_type_data_t`` vector that produced them can go out of scope without
    invalidating pointers we still need. ``type`` is copy-constructed from
    the source ``tinfo_t`` and holds a ref-counted handle into the type
    library, so it survives the vector independently.
    """
    frame_tif: ida_typeinf.tinfo_t
    name: str
    offset_bytes: int
    size_bytes: int
    type: ida_typeinf.tinfo_t
    tid: int


def _resolve_frame_member(func: ida_funcs.func_t, name: str) -> _ResolvedFrameMember:
    """Resolve a frame member by name.

    IDA 9.0 RTM (build 240925) ships a ``tinfo_t`` SWIG binding that does *not*
    expose the ``get_udm(name)`` overload (it landed in a later 9.x patch).
    To stay compatible across 8.x / 9.x we drive the lookup through
    ``udt_type_data_t`` and walk the udm vector ourselves.
    """
    frame_tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame_tif, func):
        raise IDAError("No frame returned for function", IDAErrorKind.NOT_FOUND)

    udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(udt):
        raise IDAError(
            "Failed to read UDT details for stack frame",
            IDAErrorKind.NOT_FOUND,
        )

    for idx in range(udt.size()):
        member = udt[idx]
        if member.name != name:
            continue
        return _ResolvedFrameMember(
            frame_tif=frame_tif,
            name=member.name,
            offset_bytes=member.offset // 8,
            size_bytes=member.size // 8,
            type=ida_typeinf.tinfo_t(member.type),
            tid=frame_tif.get_udm_tid(idx),
        )

    raise IDAError(f"{name} not found in stack frame", IDAErrorKind.NOT_FOUND)


def _args_region_start(frame_tif: ida_typeinf.tinfo_t) -> int:
    """Return the byte offset where the arguments region begins.

    We deliberately *don't* use ``ida_frame.is_funcarg_off`` here: in IDA
    9.0 / metapc the underlying ``processor_t::is_funcarg_off`` branches on
    ``stkup()`` and ends up returning True for *every* offset below the
    args.end_ea boundary -- including local variables sitting low in the
    frame. Walking the UDT and stopping at the highest "special" member
    (saved registers + return address) gives the same boundary the IDA UI
    displays without depending on a processor-specific predicate.

    Returns ``0`` when no special members are present (rare: leaf functions
    with no saved-regs/retaddr slot); callers should treat that as "args
    region cannot be determined" and skip the check rather than reject.
    """
    udt = ida_typeinf.udt_type_data_t()
    if not frame_tif.get_udt_details(udt):
        return 0
    boundary = 0
    for idx in range(udt.size()):
        tid = frame_tif.get_udm_tid(idx)
        if not ida_frame.is_special_frame_member(tid):
            continue
        member = udt[idx]
        end = member.offset // 8 + member.size // 8
        if end > boundary:
            boundary = end
    return boundary


def _check_mutable(member: _ResolvedFrameMember, func: ida_funcs.func_t, name: str, action: str) -> None:
    """Reject mutations against frame members that aren't user-managed.

    *action* is interpolated into the error message ("refusing to <action>"),
    so callers should pass an imperative verb phrase like ``"rename"`` or
    ``"delete"``.
    """
    if ida_frame.is_special_frame_member(member.tid):
        raise IDAError(
            f"{name} is a special frame member; refusing to {action}",
            IDAErrorKind.PERMISSION_DENIED,
        )
    args_start = _args_region_start(member.frame_tif)
    if args_start and member.offset_bytes >= args_start:
        raise IDAError(
            f"{name} is an argument member; refusing to {action}",
            IDAErrorKind.PERMISSION_DENIED,
        )


@jsonrpc
@idawrite
def rename_stack_frame_variable(
    function: FunctionTargetParam,
    old_name: OldNameParam,
    new_name: NewNameParam,
):
    """Change the name of a stack variable for an IDA function"""
    func = get_func_or_raise(function)
    member = _resolve_frame_member(func, old_name)
    _check_mutable(member, func, old_name, "rename")

    sval = ida_frame.soff_to_fpoff(func, member.offset_bytes)
    ensure_ok(
        ida_frame.define_stkvar(func, new_name, sval, member.type),
        "failed to rename stack frame variable",
    )


@jsonrpc
@idawrite
@unsafe
def create_stack_frame_variable(
    function: FunctionTargetParam,
    offset: OffsetParam,
    variable_name: VariableNameParam,
    type_name: TypeNameParam,
):
    """For a given function, create a stack variable at an offset and with a specific type"""
    func = get_func_or_raise(function)

    frame_tif = ida_typeinf.tinfo_t()
    ensure_ok(
        ida_frame.get_func_frame(frame_tif, func),
        "No frame returned",
        IDAErrorKind.NOT_FOUND,
    )

    tif = get_type_by_name(type_name)
    ensure_ok(
        ida_frame.define_stkvar(func, variable_name, parse_int(offset), tif),
        "failed to define stack frame variable",
    )


@jsonrpc
@idawrite
@unsafe
def set_stack_frame_variable_type(
    function: FunctionTargetParam,
    variable_name: VariableNameParam,
    type_name: TypeNameParam,
):
    """For a given function, set the type of a stack variable"""
    func = get_func_or_raise(function)
    member = _resolve_frame_member(func, variable_name)

    tif = get_type_by_name(type_name)
    ensure_ok(
        ida_frame.set_frame_member_type(func, member.offset_bytes, tif),
        "failed to set stack frame variable type",
    )


@jsonrpc
@idawrite
@unsafe
def delete_stack_frame_variable(
    function: FunctionTargetParam,
    variable_name: VariableNameParam,
):
    """Delete the named stack variable for a given function"""
    func = get_func_or_raise(function)
    member = _resolve_frame_member(func, variable_name)
    _check_mutable(member, func, variable_name, "delete")

    end = member.offset_bytes + member.size_bytes
    ensure_ok(
        ida_frame.delete_frame_members(func, member.offset_bytes, end),
        "failed to delete stack frame variable",
    )
