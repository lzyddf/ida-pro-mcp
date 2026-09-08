"""Translate IDA-side :class:`~ida_pro_mcp.plugin.doc.Doc` metadata into pydantic.

FastMCP builds each tool's JSON Schema from the proxy's view of the function:
it reads the ``Annotated`` metadata attached to parameters and forwards
``pydantic.Field`` arguments (``description``, ``ge``, ``gt``) into the schema.
The IDA-side signatures deliberately use ``Doc`` instead of ``pydantic.Field``
so that the in-IDA import chain stays free of compiled dependencies -- see
:mod:`ida_pro_mcp.plugin.coerce` for the full reasoning.

This module is the single bridge between the two worlds. It rewrites a
function's resolved annotations, replacing every ``Doc`` with the equivalent
``pydantic.Field``, and is imported only by proxy-side code
(:mod:`ida_pro_mcp._tool_bridge`); the IDA side never touches it.

Without this translation the tools would still *work*, but every parameter
description and numeric bound would silently disappear from ``tools/list``,
because FastMCP only synthesises metadata for parameters that have none.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Annotated, Any, get_args, get_origin

from pydantic import Field
from pydantic.fields import FieldInfo

from .plugin._typing import resolved_signature
from .plugin.doc import Doc


def to_pydantic_field(doc: Doc) -> FieldInfo:
    """Return the ``pydantic.Field`` equivalent of *doc*."""
    kwargs: dict[str, Any] = {"description": doc.description}
    if doc.ge is not None:
        kwargs["ge"] = doc.ge
    if doc.gt is not None:
        kwargs["gt"] = doc.gt
    return Field(**kwargs)


def translate_annotation(annotation: Any) -> Any:
    """Return *annotation* with every ``Doc`` metadata item replaced by a Field.

    Annotations without ``Annotated`` metadata, and ``Annotated`` layers whose
    metadata is already pydantic-native, are returned unchanged.
    """
    if get_origin(annotation) is not Annotated:
        return annotation
    base, *metadata = get_args(annotation)
    translated = [
        to_pydantic_field(item) if isinstance(item, Doc) else item for item in metadata
    ]
    return Annotated[(base, *translated)]


def translate_signature(
    sig: inspect.Signature, hints: dict[str, Any]
) -> inspect.Signature:
    """Return *sig* with every parameter and return annotation translated.

    *hints* is the resolved-hint mapping that produced *sig*; it is consulted so
    that annotations still expressed as forward references get translated too.
    """
    new_params = [
        param.replace(
            annotation=translate_annotation(hints.get(name, param.annotation))
        )
        for name, param in sig.parameters.items()
    ]
    return_annotation = translate_annotation(
        hints.get("return", sig.return_annotation)
    )
    return sig.replace(parameters=new_params, return_annotation=return_annotation)


def apply_param_docs(func: Callable[..., Any]) -> Callable[..., Any]:
    """Rewrite *func*'s signature so FastMCP sees pydantic ``Field`` metadata.

    Used for tools registered directly (not through the RPC proxy), such as the
    locally-implemented ``convert_number``. The function object itself is
    returned so this can be used inline.
    """
    sig, hints = resolved_signature(func, use_module_globals=True)
    translated = translate_signature(sig, hints)
    func.__signature__ = translated  # type: ignore[attr-defined]
    func.__annotations__ = {
        param.name: param.annotation
        for param in translated.parameters.values()
        if param.annotation is not inspect.Parameter.empty
    }
    if translated.return_annotation is not inspect.Signature.empty:
        func.__annotations__["return"] = translated.return_annotation
    return func
