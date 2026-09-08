"""Reusable parameter type aliases shared across tool definitions.

Centralising the ``Annotated[T, Doc(...)]`` boilerplate keeps descriptions
consistent (every function target accepts names and addresses the same way)
and shrinks each tool module.

Tool authors should reach for these aliases by default; introduce a one-off
``Annotated[..., Doc(...)]`` only when the parameter genuinely has
tool-specific semantics that would mislead readers if generalised.

:class:`~ida_pro_mcp.plugin.doc.Doc` is used instead of ``pydantic.Field`` so
this module -- and everything the IDA-side import chain pulls in -- stays
dependency-free. The proxy translates ``Doc`` into a pydantic field when it
builds the MCP schema; see :mod:`ida_pro_mcp._schema`.

NOTE: ``from __future__ import annotations`` is fine here because nothing in
this module uses :class:`typing.TypedDict`. If you ever add a TypedDict alias
(e.g. for a structured argument), drop the future import or move the TypedDict
to :mod:`.models` -- PEP 563 turns every annotation into a string at class
creation time, but TypedDict's ``__required_keys__`` machinery only recognises
``NotRequired[...]`` when it sees the runtime sentinel object, not the string
``"NotRequired[...]"``. With the future import enabled, every ``NotRequired``
field would silently become required.
"""
from __future__ import annotations

from typing import Annotated

from .doc import Doc

# --- Address / numeric -------------------------------------------------------

AddressParam = Annotated[
    str,
    Doc(
        "Hex address (e.g. '0x401000' or '401000'). Bare strings are interpreted as hex; "
        "use the '0x'/'0o'/'0b' prefixes for explicit bases or '0d' to force decimal."
    ),
]

FunctionTargetParam = Annotated[
    str,
    Doc(
        "Function name or hex address (any address inside the function works). "
        "Hex-looking names are resolved as addresses first and then as names."
    ),
]

# Source-compatible alias for embedders; new public tools use the clearer name.
FunctionAddressParam = FunctionTargetParam

GlobalTargetParam = Annotated[
    str,
    Doc("Global variable name or hex address"),
]

OffsetParam = Annotated[
    str,
    Doc(
        "Stack-pointer-relative offset for ``define_stkvar`` (IDA's "
        "``sval_t`` -- *not* the byte offset shown by "
        "get_stack_frame_variables, which is the frame UDT offset). "
        "Decimal by default, hex needs the '0x' prefix. To insert a new "
        "local at the position of an existing variable, pass that "
        "variable's offset as displayed by get_stack_frame_variables; "
        "anything in the arguments / saved-registers / return-address "
        "region will silently overwrite that slot."
    ),
]

# --- Pagination --------------------------------------------------------------

PageOffsetParam = Annotated[
    int,
    Doc("Offset to start listing from (start at 0)", ge=0),
]

PageCountParam = Annotated[
    int,
    Doc(
        "Number of items to list (100 is a good default, 0 means remainder)",
        ge=0,
    ),
]

FilterParam = Annotated[
    str,
    Doc("Case-insensitive substring filter (empty string for no filter)"),
]

# --- Naming ------------------------------------------------------------------

OldNameParam = Annotated[str, Doc("Current name")]
NewNameParam = Annotated[str, Doc("New name (empty for a default name)")]

VariableNameParam = Annotated[str, Doc("Name of the variable")]
TypeNameParam = Annotated[str, Doc("C type name")]
StructureNameParam = Annotated[str, Doc("Name of the structure")]
FieldNameParam = Annotated[str, Doc("Name of the field (member) inside the structure")]

# --- Misc --------------------------------------------------------------------

CommentTextParam = Annotated[str, Doc("Comment text")]

ConvertNumberSizeParam = Annotated[
    int | None,
    Doc(
        "Size of the variable in bytes (omit to let the server infer)",
        gt=0,
    ),
]
