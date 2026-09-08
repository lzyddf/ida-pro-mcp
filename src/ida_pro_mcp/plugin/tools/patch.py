"""Binary patching tools (always unsafe)."""
from __future__ import annotations

from typing import Annotated

import ida_bytes
import idautils

from ..doc import Doc
from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import format_ea, parse_ea
from ..ida_sync import idawrite
from ..params import AddressParam
from ..registry import jsonrpc, unsafe


def _assemble_and_patch(ea: int, instruction: str) -> int:
    ok, raw = idautils.Assemble(ea, instruction)
    ensure_ok(
        ok,
        f"Failed to assemble instruction: {instruction}",
        IDAErrorKind.PARSE_FAILED,
    )
    try:
        ida_bytes.patch_bytes(ea, raw)
    except Exception as e:
        raise IDAError(
            f"Failed to patch bytes at {format_ea(ea)}", IDAErrorKind.OPERATION_FAILED
        ) from e
    return len(raw)


@jsonrpc
@idawrite
@unsafe
def patch_address_assembles(
    address: AddressParam,
    instructions: Annotated[str, Doc("Assembly instructions separated by ';'")],
) -> str:
    """Assemble and patch a series of instructions starting at the given address."""
    ea = parse_ea(address)
    pieces = [piece.strip() for piece in instructions.split(";") if piece.strip()]
    if not pieces:
        raise IDAError("No instructions provided", IDAErrorKind.INVALID_INPUT)
    for instruction in pieces:
        ea += _assemble_and_patch(ea, instruction)
    return f"Patched {len(pieces)} instructions"
