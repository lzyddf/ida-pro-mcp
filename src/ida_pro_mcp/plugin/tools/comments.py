"""Comment management tools."""
from __future__ import annotations

import logging

import ida_hexrays
import idaapi
import idc

from ..decomp import decompile_checked
from ..errors import IDAError, IDAErrorKind, ensure_ok
from ..format import format_ea, parse_ea
from ..ida_sync import idawrite
from ..params import AddressParam, CommentTextParam
from ..registry import jsonrpc

logger = logging.getLogger(__name__)

# Hex-Rays attaches every pseudocode comment to a (treeloc, item_preciser)
# pair. The "right" itp depends on the ctree node's shape and there's no API
# to ask Hex-Rays which one applies, so we walk a curated list and pick the
# first that doesn't produce an orphan comment.
#
# We use an explicit whitelist instead of ``range(ITP_SEMI, ITP_COLON)`` so
# a future SDK that inserts new ITP values in the middle (or re-orders them)
# can't silently start probing irrelevant attachment points. Each name is
# resolved lazily via ``getattr`` so missing values on older SDKs degrade
# gracefully instead of crashing at import time.
_ITP_CANDIDATE_NAMES: tuple[str, ...] = (
    "ITP_SEMI",
    "ITP_CURLY1",
    "ITP_CURLY2",
    "ITP_BRACE1",
    "ITP_BRACE2",
    "ITP_ARG1",
    "ITP_ARG64",
    "ITP_ELSE",
    "ITP_DO",
    "ITP_CASE",
    "ITP_ASM",
    "ITP_COLON",
)


def _itp_candidates() -> list[int]:
    """Return the ordered list of ITP punctuation values worth probing.

    Resolved lazily so the module imports cleanly under stub modules and so
    SDK builds that don't expose every name still get a usable subset.
    Empty results raise -- silently turning the loop into a no-op would
    produce a cryptic "Failed to set" later.
    """
    values: list[int] = []
    for name in _ITP_CANDIDATE_NAMES:
        value = getattr(idaapi, name, None)
        if isinstance(value, int):
            values.append(value)
    if not values:
        raise IDAError(
            "No usable ITP_* values exposed by this IDA SDK; "
            "decompiler comment placement needs updating",
            IDAErrorKind.OPERATION_FAILED,
        )
    return values


def _try_attach_at_ctree_ea(cfunc: ida_hexrays.cfunc_t, anchor_ea: int, comment: str) -> bool:
    """Try every plausible ITP at *anchor_ea*; return True on the first that sticks.

    "Sticks" means the set didn't generate an orphan comment -- the standard
    Hex-Rays signal that we picked the wrong attachment point for this node.
    """
    if cfunc.has_orphan_cmts():
        cfunc.del_orphan_cmts()

    tl = idaapi.treeloc_t()
    tl.ea = anchor_ea
    for itp in _itp_candidates():
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        if not cfunc.has_orphan_cmts():
            cfunc.save_user_cmts()
            cfunc.refresh_func_ctext()
            return True
        cfunc.del_orphan_cmts()
    return False


def _attach_to_pseudocode(cfunc: ida_hexrays.cfunc_t, ea: int, comment: str) -> bool:
    """Mirror *comment* into the pseudocode view at *ea*; ``True`` on success.

    Hex-Rays attaches every pseudocode comment to a (treeloc, itp) pair, where
    ``itp`` describes *which* punctuation token of the ctree node the comment
    sits on (semicolon, brace, colon, ...). The "right" itp depends on the
    statement's shape, and there's no API to ask Hex-Rays which one applies.
    The classic workaround (see the cyber.wtf TrickBot writeup linked below)
    is to walk the plausible itp values in order; the first one that doesn't
    produce an orphan comment is the correct attachment point.
    https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/

    Returns ``False`` (rather than raising) when no candidate ITP sticks --
    typical for multi-line ``a || b || c`` chains, ternary expressions, and
    other ctree shapes whose punctuation slots don't line up with the
    canonical list. Callers decide whether the partial result (disassembly
    comment set, pseudocode comment skipped) is worth surfacing as an
    error or just a log line.
    """
    if ea == cfunc.entry_ea:
        idc.set_func_cmt(ea, comment, True)
        cfunc.refresh_func_ctext()
        return True

    eamap = cfunc.get_eamap()
    if ea not in eamap:
        logger.debug("no ctree node at %s; skipping pseudocode mirror", format_ea(ea))
        return False

    return _try_attach_at_ctree_ea(cfunc, eamap[ea][0].ea, comment)


@jsonrpc
@idawrite
def set_comment(address: AddressParam, comment: CommentTextParam):
    """Set a comment for a given address in the function disassembly and pseudocode.

    Disassembly placement is exact and always required to succeed; pseudocode
    mirroring is *best-effort*. Some ctree shapes (multi-line ``||`` chains,
    ternary expressions, switch labels...) have no canonical ITP punctuation
    slot at the address Hex-Rays returned via ``get_eamap``; those cases are
    logged and silently skipped rather than failing the whole call. The
    alternative -- raising on partial failure -- left the disassembly comment
    written but the call reported as an error, which led LLM clients to
    retry the same write or abandon the finding entirely.
    """
    ea = parse_ea(address)

    ensure_ok(
        idaapi.set_cmt(ea, comment, False),
        f"Failed to set disassembly comment at {format_ea(ea)}",
    )

    try:
        cfunc = decompile_checked(ea)
    except IDAError:
        return  # decompiler unavailable; disassembly comment still set

    if not _attach_to_pseudocode(cfunc, ea, comment):
        # Disassembly is the source of truth; the pseudocode mirror is just
        # a UX nicety. Log so a developer can investigate, but don't surface
        # this as an RPC failure -- the caller's intent ("attach a comment
        # at this EA") was honoured.
        logger.info(
            "pseudocode mirror at %s skipped (no usable ITP attachment); "
            "disassembly comment written",
            format_ea(ea),
        )
