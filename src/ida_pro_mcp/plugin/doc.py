"""Declarative parameter metadata the IDA side can carry without pydantic.

Tool signatures annotate parameters as ``Annotated[T, Doc(...)]``. The IDA
side only needs two things from that metadata:

* the base type, to convert incoming JSON-RPC arguments; and
* the numeric bounds, to reject out-of-range values.

Both are plain Python data. The human-readable ``description`` is only needed
by the proxy when it builds the MCP JSON Schema, and :mod:`ida_pro_mcp._schema`
translates a :class:`Doc` into the ``pydantic.Field`` that FastMCP expects.

Keeping this module dependency-free is what lets the IDA-side import chain run
inside IDAPython -- whatever Python version IDA bundles -- while the proxy may
use any interpreter. Adding a compiled dependency here would reintroduce the
ABI coupling this split exists to remove.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Doc:
    """Description plus optional numeric bounds for one parameter.

    ``ge`` / ``gt`` mirror the pydantic constraints of the same name: they are
    inclusive and exclusive lower bounds respectively. They are only meaningful
    for numeric parameters; :mod:`ida_pro_mcp.plugin.coerce` ignores them for
    every other type.
    """

    description: str
    ge: int | None = None
    gt: int | None = None
