"""Standard-library conversion of JSON-RPC arguments to their declared types.

The IDA-side dispatcher validates incoming arguments before calling a tool.
It cannot use pydantic: ``pydantic_core`` is a compiled extension built for a
single CPython ABI, while the IDA-side package is imported by *two* different
interpreters -- the proxy's own Python and the IDAPython that IDA bundles. A
compiled dependency therefore breaks as soon as those versions differ, which
is exactly what :mod:`ida_pro_mcp.spawner.process_env` documents happening on
a machine whose IDA ships Python 3.12 while ``uv tool install`` picked 3.11.

This module reimplements, in pure stdlib, precisely the conversions the tool
signatures need. Scope is deliberately narrow -- the shapes actually used:
``str``, ``int``, ``bool``, ``float``, ``Literal[...]``, ``list[...]``,
``Optional[...]`` and the ``Annotated[T, Doc(...)]`` bounds. Anything else is
passed through untouched.

Behaviour mirrors pydantic's lax mode for those shapes (case-by-case parity is
asserted in ``tests/test_coerce.py``), so swapping the implementation is not
observable on the wire: ``"31"`` becomes ``31``, ``"0x1f"`` does not, and
``"yes"`` is a valid boolean while ``"2"`` is not.
"""
from __future__ import annotations

import inspect
import types
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from .doc import Doc

# Accepted boolean spellings, matching pydantic's lax mode. Anything else --
# including "2" or "" -- is rejected rather than guessed at.
_BOOL_TRUE = frozenset({"true", "1", "t", "y", "yes", "on"})
_BOOL_FALSE = frozenset({"false", "0", "f", "n", "no", "off"})


class CoercionError(ValueError):
    """Raised when a value cannot be converted to its declared parameter type."""


def coerce(value: Any, annotation: Any) -> Any:
    """Convert *value* to *annotation*, or raise :class:`CoercionError`.

    ``Annotated`` metadata is stripped before conversion and its bounds applied
    afterwards, so ``Annotated[int, Doc("...", ge=0)]`` rejects ``-1`` while a
    bare ``int`` accepts it.
    """
    base, metadata = _strip_annotated(annotation)
    converted = _convert(value, base)
    _apply_bounds(converted, metadata)
    return converted


def _strip_annotated(annotation: Any) -> tuple[Any, tuple[Any, ...]]:
    """Return ``(base_annotation, metadata)`` with every ``Annotated`` layer removed."""
    metadata: tuple[Any, ...] = ()
    while get_origin(annotation) is Annotated:
        args = get_args(annotation)
        annotation = args[0]
        metadata = (*metadata, *args[1:])
    return annotation, metadata


def _convert(value: Any, annotation: Any) -> Any:
    if annotation is None or annotation is Any or annotation is object:
        return value
    if annotation is inspect.Parameter.empty:
        return value
    if annotation is type(None):
        if value is None:
            return None
        raise CoercionError("Input should be None")

    origin = get_origin(annotation)
    if origin is Literal:
        return _coerce_literal(value, annotation)
    if origin is Union or origin is types.UnionType:
        return _coerce_union(value, annotation)
    if origin is list:
        return _coerce_list(value, annotation)

    if annotation is bool:
        return _coerce_bool(value)
    if annotation is int:
        return _coerce_int(value)
    if annotation is float:
        return _coerce_float(value)
    if annotation is str:
        return _coerce_str(value)

    # Structured types (TypedDict, dataclasses, ...) never appear as RPC
    # parameters in this project; pass them through rather than guessing.
    return value


def _coerce_int(value: Any) -> int:
    # bool is an int subclass, so it must be checked first: pydantic maps
    # True/False to 1/0 rather than rejecting them.
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise CoercionError("Input should be a valid integer, got a non-integral float")
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip(), 10)
        except ValueError as exc:
            raise CoercionError(
                "Input should be a valid integer, unable to parse string as an integer"
            ) from exc
    raise CoercionError("Input should be a valid integer")


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        if value in (0, 1):
            return bool(value)
        raise CoercionError("Input should be a valid boolean, unable to interpret input")
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _BOOL_TRUE:
            return True
        if text in _BOOL_FALSE:
            return False
        raise CoercionError("Input should be a valid boolean, unable to interpret input")
    raise CoercionError("Input should be a valid boolean, unable to interpret input")


def _coerce_float(value: Any) -> float:
    if isinstance(value, bool | int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError as exc:
            raise CoercionError(
                "Input should be a valid number, unable to parse string as a number"
            ) from exc
    raise CoercionError("Input should be a valid number")


def _coerce_str(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8")
    raise CoercionError("Input should be a valid string")


def _coerce_literal(value: Any, annotation: Any) -> Any:
    """Return *value* iff it is one of the literal members, comparing types too.

    The type check matters because ``1 == True`` and ``"1" != 1``; without it a
    JSON number could silently satisfy a string-valued ``Literal``.
    """
    allowed = get_args(annotation)
    for candidate in allowed:
        if type(value) is type(candidate) and value == candidate:
            return value
    rendered = " or ".join(repr(item) for item in allowed)
    raise CoercionError(f"Input should be {rendered}")


def _coerce_list(value: Any, annotation: Any) -> list[Any]:
    if not isinstance(value, list):
        raise CoercionError("Input should be a valid list")
    args = get_args(annotation)
    item_annotation = args[0] if args else Any
    return [coerce(item, item_annotation) for item in value]


def _coerce_union(value: Any, annotation: Any) -> Any:
    members = get_args(annotation)
    optional = type(None) in members
    if value is None:
        if optional:
            return None
        raise CoercionError("Input should not be None")

    concrete = [member for member in members if member is not type(None)]
    if len(concrete) == 1:
        return coerce(value, concrete[0])

    for member in concrete:
        try:
            return coerce(value, member)
        except CoercionError:
            continue
    rendered = " or ".join(str(member) for member in concrete)
    raise CoercionError(f"Input should be {rendered}")


def _apply_bounds(value: Any, metadata: tuple[Any, ...]) -> None:
    """Enforce ``Doc.ge`` / ``Doc.gt`` on numeric *value*; other metadata is ignored."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return
    for item in metadata:
        if not isinstance(item, Doc):
            continue
        if item.ge is not None and value < item.ge:
            raise CoercionError(f"Input should be greater than or equal to {item.ge}")
        if item.gt is not None and value <= item.gt:
            raise CoercionError(f"Input should be greater than {item.gt}")
