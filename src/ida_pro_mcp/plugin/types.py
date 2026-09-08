"""C type name resolution.

Maps human-friendly aliases (``int``, ``DWORD``, ``unsigned long long``, ...)
to ``ida_typeinf.tinfo_t`` instances. Falls back to ``parse_decl`` for
arbitrary user-typed declarations so callers don't have to know whether a
string is a primitive alias, a named type, or a custom decl.

Two entry points:

* :func:`get_type_by_name` -- "give me the tinfo_t for this type name", with
  alias / named-type / parse-decl fallback. Use for fields, locals, args.
* :func:`parse_c_type` -- "parse this arbitrary declaration into a tinfo_t",
  optionally asserting a shape (e.g. ``expect="function"`` for prototypes).
"""
from __future__ import annotations

import logging
from typing import Literal

import ida_typeinf

from .errors import IDAError, IDAErrorKind

logger = logging.getLogger(__name__)

_PRIMITIVE_TYPES: dict[tuple[str, ...], int] = {
    ("int8", "__int8", "int8_t", "char", "signed char"): ida_typeinf.BTF_INT8,
    ("uint8", "__uint8", "uint8_t", "unsigned char", "byte", "BYTE"): ida_typeinf.BTF_UINT8,
    ("int16", "__int16", "int16_t", "short", "short int", "signed short", "signed short int"): ida_typeinf.BTF_INT16,
    ("uint16", "__uint16", "uint16_t", "unsigned short", "unsigned short int", "word", "WORD"): ida_typeinf.BTF_UINT16,
    ("int32", "__int32", "int32_t", "int", "signed int", "long", "long int", "signed long", "signed long int"): ida_typeinf.BTF_INT32,
    ("uint32", "__uint32", "uint32_t", "unsigned int", "unsigned long", "unsigned long int", "dword", "DWORD"): ida_typeinf.BTF_UINT32,
    ("int64", "__int64", "int64_t", "long long", "long long int", "signed long long", "signed long long int"): ida_typeinf.BTF_INT64,
    ("uint64", "__uint64", "uint64_t", "unsigned int64", "unsigned long long", "unsigned long long int", "qword", "QWORD"): ida_typeinf.BTF_UINT64,
    ("int128", "__int128", "int128_t", "__int128_t"): ida_typeinf.BTF_INT128,
    ("uint128", "__uint128", "uint128_t", "__uint128_t", "unsigned int128"): ida_typeinf.BTF_UINT128,
    ("float",): ida_typeinf.BTF_FLOAT,
    ("double",): ida_typeinf.BTF_DOUBLE,
    ("long double", "ldouble"): ida_typeinf.BTF_LDOUBLE,
    ("bool", "_Bool", "boolean"): ida_typeinf.BTF_BOOL,
    ("void",): ida_typeinf.BTF_VOID,
}

_NAMED_TYPE_KINDS = (
    ida_typeinf.BTF_STRUCT,
    ida_typeinf.BTF_TYPEDEF,
    ida_typeinf.BTF_ENUM,
    ida_typeinf.BTF_UNION,
)


def get_type_by_name(type_name: str) -> ida_typeinf.tinfo_t:
    """Resolve a C type name to a tinfo_t, supporting common aliases."""
    for aliases, btf in _PRIMITIVE_TYPES.items():
        if type_name in aliases:
            return ida_typeinf.tinfo_t(btf)

    tif = ida_typeinf.tinfo_t()
    for kind in _NAMED_TYPE_KINDS:
        if tif.get_named_type(None, type_name, kind):
            return tif

    # Anything that isn't a primitive alias or a known UDT goes through the
    # full declaration parser. IDA 9.0 RTM's SWIG binding only exposes the
    # ``tinfo_t() / tinfo_t(type_t) / tinfo_t(tinfo_t const&)`` overloads,
    # so a bare ``tinfo_t(str)`` raises ``TypeError``; ``parse_c_type``
    # already wraps that path with a ``parse_decl`` fallback.
    try:
        return parse_c_type(type_name)
    except IDAError as exc:
        raise IDAError(
            f"Unable to retrieve {type_name} type info object",
            IDAErrorKind.NOT_FOUND,
        ) from exc


_TypeShape = Literal["any", "function"]


def parse_c_type(
    declaration: str,
    *,
    expect: _TypeShape = "any",
) -> ida_typeinf.tinfo_t:
    """Parse an arbitrary C declaration into a :class:`tinfo_t`.

    Tries the direct ``tinfo_t(declaration, ...)`` constructor first, then
    falls back to ``parse_decl`` (with ``;`` appended) for anything the
    constructor can't digest. Both paths use ``PT_SIL`` so IDA does not pop
    a UI dialog mid-RPC.

    *expect* lets callers assert a structural property of the parsed type:

    * ``"any"`` -- accept any shape (default).
    * ``"function"`` -- raise :class:`IDAError` if the parsed type is not a
      function type. Used by ``set_function_prototype``.
    """
    try:
        tif = ida_typeinf.tinfo_t(declaration, None, ida_typeinf.PT_SIL)
        if tif:
            _check_shape(tif, expect, declaration)
            return tif
    except Exception as exc:
        # ``tinfo_t(...)`` rejecting the string is the *expected* path that
        # falls through to ``parse_decl`` -- but log the message at debug so
        # genuinely surprising failures (e.g. SWIG breakage) leave a trail.
        logger.debug("tinfo_t(%r) failed, falling back to parse_decl: %s", declaration, exc)

    tif = ida_typeinf.tinfo_t()
    try:
        ida_typeinf.parse_decl(tif, None, declaration.rstrip(";") + ";", ida_typeinf.PT_SIL)  # type: ignore[arg-type]
    except Exception as exc:
        raise IDAError(
            f"Failed to parse type: {declaration}", IDAErrorKind.PARSE_FAILED,
        ) from exc
    _check_shape(tif, expect, declaration)
    return tif


def _check_shape(tif: ida_typeinf.tinfo_t, expect: _TypeShape, declaration: str) -> None:
    if expect == "function" and not tif.is_func():
        raise IDAError(
            f"Parsed declaration is not a function type: {declaration}",
            IDAErrorKind.INVALID_INPUT,
        )
