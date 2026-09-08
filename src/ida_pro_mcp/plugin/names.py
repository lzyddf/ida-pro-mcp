"""Name resolution and the demangled-name cache.

The cache is encapsulated as a small object (rather than a free ``global``)
so additional caches can be added without piling them onto a single
``invalidate_caches`` function. It registers itself with
:mod:`plugin.caches` so :mod:`plugin.idb_hooks` flushes everything in one
sweep on database close / rename events.
"""
from __future__ import annotations

import ida_name
import idaapi
import idautils

from .caches import register_invalidator
from .errors import IDAError, IDAErrorKind
from .format import parse_ea

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def resolve_name_ea(name: str) -> int | None:
    """Return the EA bound to *name* (any kind), or ``None`` if not found."""
    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    return None if ea == idaapi.BADADDR else ea


def resolve_name_ea_or_raise(name: str, *, kind: str = "name") -> int:
    """Like :func:`resolve_name_ea` but raises a domain error when missing."""
    ea = resolve_name_ea(name)
    if ea is None:
        raise IDAError(f"{kind.capitalize()} {name!r} not found", IDAErrorKind.NOT_FOUND)
    return ea


def resolve_name_or_address(target: str, *, kind: str = "name") -> int:
    """Resolve an IDA name first, then fall back to address parsing.

    Name-first ordering preserves legitimate hex-looking symbols while explicit
    ``0x``/``0d`` prefixes remain unambiguous address inputs.
    """
    stripped = target.strip()
    if not stripped:
        raise IDAError(f"Empty {kind} target", IDAErrorKind.INVALID_INPUT)
    ea = resolve_name_ea(stripped)
    if ea is not None:
        return ea
    try:
        return parse_ea(stripped)
    except IDAError as exc:
        raise IDAError(f"{kind.capitalize()} {target!r} not found", IDAErrorKind.NOT_FOUND) from exc


class _DemangledNameCache:
    """Per-IDB cache of demangled-name -> EA.

    Building the map can be slow on large IDBs (one demangle call per
    function). The cache is keyed on the loaded input file path so reopening
    a different IDB in the same IDA session produces a fresh map; the
    :mod:`plugin.idb_hooks` cache invalidator wipes it eagerly on database
    close / rename events.
    """

    __slots__ = ("_key", "_mapping")

    def __init__(self) -> None:
        self._key: str | None = None
        self._mapping: dict[str, int] = {}

    def _current_key(self) -> str:
        return idaapi.get_input_file_path() or ""

    def _build(self) -> dict[str, int]:
        mapping: dict[str, int] = {}
        for ea in idautils.Functions():
            # MNG_NODEFINIT inhibits everything except the main name; default
            # demangling adds the function signature and decorators.
            demangled = idaapi.demangle_name(ida_name.get_name(ea), idaapi.MNG_NODEFINIT)
            if demangled:
                mapping[demangled] = ea
        return mapping

    def get(self) -> dict[str, int]:
        """Return the cached mapping, rebuilding if the IDB key changed."""
        key = self._current_key()
        if self._key != key:
            self._mapping = self._build()
            self._key = key
        return self._mapping

    def invalidate(self) -> None:
        self._key = None
        self._mapping = {}


_demangled_cache = _DemangledNameCache()
register_invalidator(_demangled_cache.invalidate)


def lookup_function_ea_by_name(name: str) -> int:
    """Resolve a function EA by name, falling back to demangled lookup.

    Demangled lookups consult :class:`_DemangledNameCache`; on a cache miss
    the cache is invalidated and rebuilt once in case a recent rename made
    the cached map stale.
    """
    ea = resolve_name_ea(name)
    if ea is not None:
        return ea
    mapping = _demangled_cache.get()
    if name in mapping:
        return mapping[name]

    _demangled_cache.invalidate()
    mapping = _demangled_cache.get()
    if name in mapping:
        return mapping[name]

    raise IDAError(f"No function found with name {name}", IDAErrorKind.NOT_FOUND)


def resolve_function_target(target: str) -> int:
    """Accept a hex address *or* a function name and return the matching EA.

    Strategy:

    1. Trim whitespace; reject the empty string with :class:`IDAError`.
    2. If the literal *looks* like a base-prefixed integer (``0x``/``0o``/
       ``0b``/``0d``) or pure hex digits, try parsing it as an address;
       accept only when an actual function lives there. This guards against
       ambiguous inputs like ``"abc"`` or ``"fcf94739"`` -- they parse as
       hex but rarely point at a function, so we still fall back to the
       name lookup below.
    3. Otherwise (or after the address fast-path missed) defer to
       :func:`lookup_function_ea_by_name`, which checks both the raw name
       table and the demangled-name cache.

    The fall-through ordering means name lookups always get the chance to
    win; callers who pass a real function name never see a cryptic
    "address parses but isn't a function" error.
    """
    stripped = target.strip()
    if not stripped:
        raise IDAError("Empty function target", IDAErrorKind.INVALID_INPUT)

    looks_hex = stripped[:2].lower() in ("0x", "0o", "0b", "0d") or all(
        c in _HEX_DIGITS for c in stripped
    )
    if looks_hex:
        try:
            ea = parse_ea(stripped)
        except IDAError:
            ea = None
        if ea is not None and idaapi.get_func(ea) is not None:
            return ea

    return lookup_function_ea_by_name(stripped)
