"""Capture textual diagnostics from IDA's ``parse_decls``.

IDA's Python binding for ``parse_decls`` discards the printf-style messages
emitted by the parser. On Windows we can hook the underlying C ABI through
``ctypes`` to recover them; on other platforms the messages list is left
empty until SWIG exposes them.

Loading the ``ida`` shared library is expensive, so the hook is constructed
lazily and cached for the lifetime of the process.
"""
from __future__ import annotations

import functools
import logging
import sys
from collections.abc import Callable

import ida_typeinf

logger = logging.getLogger(__name__)

ParseFn = Callable[[str, int], tuple[int, list[str]]]


def _swig_parse_decls(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    return ida_typeinf.parse_decls(None, decls, False, hti_flags), []


@functools.lru_cache(maxsize=1)
def _windows_parse_decls() -> ParseFn:
    """Lazily build the Windows ctypes-based ``parse_decls`` wrapper.

    Falls back to the SWIG path if the symbol cannot be located so we never
    crash on an exotic IDA build.
    """
    import ctypes

    try:
        ida_dll = ctypes.CDLL("ida")
        ida_dll.parse_decls.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        ida_dll.parse_decls.restype = ctypes.c_int
    except (OSError, AttributeError) as exc:
        logger.debug("falling back to SWIG parse_decls: %s", exc)
        return _swig_parse_decls

    def _hooked(decls: str, hti_flags: int) -> tuple[int, list[str]]:
        c_decls = decls.encode("utf-8")
        messages: list[str] = []

        # ``magic_printer`` is bound to a local so the ctypes trampoline stays
        # alive for the duration of the ``parse_decls`` call. Do not factor
        # this out into a free function -- the trampoline must be GC-rooted
        # while C code holds the function pointer. (``parse_decls`` is
        # synchronous; if it ever became async this would need rethinking.)
        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
        def magic_printer(fmt: bytes, arg1: bytes) -> int:
            if fmt.count(b"%") == 1 and b"%s" in fmt:
                formatted = fmt.replace(b"%s", arg1)
                # ``errors="replace"`` so a malformed UTF-8 byte from IDA's
                # parser doesn't tank the whole call -- we'd rather show a
                # placeholder character than crash.
                messages.append(formatted.decode("utf-8", errors="replace"))
                return len(formatted) + 1
            messages.append(f"unsupported magic_printer fmt: {fmt!r}")
            return 0

        errors = ida_dll.parse_decls(None, c_decls, magic_printer, hti_flags)
        return errors, messages

    return _hooked


def parse_decls_with_messages(decls: str, hti_flags: int) -> tuple[int, list[str]]:
    """Parse a C declaration block, returning ``(error_count, messages)``.

    Messages are populated on Windows; empty otherwise.
    """
    parser: ParseFn = _windows_parse_decls() if sys.platform == "win32" else _swig_parse_decls
    return parser(decls, hti_flags)


def diagnostics_supported() -> bool:
    """Return whether the running platform exposes parser diagnostics.

    Used by callers (notably ``declare_c_type``) to surface a clearer "no
    detail available" message instead of an empty error string.
    """
    return sys.platform == "win32"
