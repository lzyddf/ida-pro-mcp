"""Plugin-level exception types and JSON-RPC error code constants.

The error codes follow the JSON-RPC 2.0 specification:
https://www.jsonrpc.org/specification#error_object

Codes in the ``-32000`` to ``-32099`` range are reserved for application-level
errors; we use ``-32000`` for IDA domain errors and ``-32098`` for transport
issues (e.g. wrong endpoint).
"""
from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Any


class JSONRPCErrorCode(IntEnum):
    """Numeric error codes used by the JSON-RPC layer."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    INVALID_ENDPOINT = -32098
    SESSION_NOT_FOUND = -32097
    SESSION_AMBIGUOUS = -32096
    IDA_ERROR = -32000


class IDAErrorKind(StrEnum):
    """Coarse category for ``IDAError`` instances.

    JSON-RPC code ``-32000`` is the same for every IDA domain error, so the
    *kind* string is what clients should branch on (``data["kind"]`` on the
    wire). Keep this enum small -- a handful of well-known buckets that map
    cleanly to "what the LLM should try next" beats fine-grained taxonomies
    that just inflate the surface.
    """

    UNKNOWN = "unknown"
    NOT_FOUND = "not_found"
    INVALID_INPUT = "invalid_input"
    PARSE_FAILED = "parse_failed"
    DECOMPILER_UNAVAILABLE = "decompiler_unavailable"
    OPERATION_FAILED = "operation_failed"
    PERMISSION_DENIED = "permission_denied"
    DEBUGGER_INACTIVE = "debugger_inactive"


class JSONRPCError(Exception):
    """Raised by the RPC layer to produce a structured JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.data = data


class IDAError(Exception):
    """Domain error raised by tool implementations.

    *message* is the human-readable string surfaced to the LLM.
    *kind* is a coarse category clients can branch on without parsing the
    message; defaults to :attr:`IDAErrorKind.UNKNOWN` so legacy ``raise
    IDAError("...")`` sites keep working.
    """

    def __init__(self, message: str, kind: IDAErrorKind = IDAErrorKind.UNKNOWN):
        super().__init__(message)
        self.message = message
        self.kind = kind


class IDASyncError(Exception):
    """Raised when the IDA main-thread sync wrapper detects misuse (e.g. nesting)."""


class IDARpcTransportError(RuntimeError):
    """Raised on the client side for transport-level failures.

    Distinguishes "could not talk to IDA at all" (HTTP errors, malformed JSON,
    socket failures) from :class:`~ida_pro_mcp.plugin.jsonrpc.RemoteJSONRPCError`
    which signals a server-reported RPC error.
    """


def ensure_ok(
    ok: object,
    message: str,
    kind: IDAErrorKind = IDAErrorKind.OPERATION_FAILED,
) -> None:
    """Raise :class:`IDAError` with *message* / *kind* when *ok* is falsy.

    Distills the ubiquitous ``if not ida_call(...): raise IDAError(...)``
    pattern down to one expressive line. Tools that need a different default
    kind (e.g. :attr:`IDAErrorKind.NOT_FOUND` for "couldn't resolve a name")
    pass it explicitly.
    """
    if not ok:
        raise IDAError(message, kind)


# --- Server-side dispatch table ---------------------------------------------
#
# Maps tool-side exception classes to the JSON-RPC error code the server
# should report. ``JSONRPCError`` carries its own code and is therefore not
# in the table -- callers should special-case it.
#
# ``IDASyncError`` is *deliberately omitted*: it signals tool-author misuse
# of the main-thread sync wrappers (e.g. nested ``@idawrite``) rather than a
# domain error the LLM can recover from. Letting it fall through to
# ``INTERNAL_ERROR`` makes the bug visible in the IDA output window via the
# default exception-logging path and keeps the wire surface small.
# Subclasses are honoured via ``isinstance``, so adding a new domain error
# class here is a one-line change when a real need arises.
EXCEPTION_TO_CODE: tuple[tuple[type[BaseException], JSONRPCErrorCode], ...] = (
    (IDAError, JSONRPCErrorCode.IDA_ERROR),
)


def code_for_exception(exc: BaseException) -> JSONRPCErrorCode:
    """Return the JSON-RPC error code for *exc* via :data:`EXCEPTION_TO_CODE`.

    Falls back to :attr:`JSONRPCErrorCode.INTERNAL_ERROR` for unknown types.
    """
    for cls, code in EXCEPTION_TO_CODE:
        if isinstance(exc, cls):
            return code
    return JSONRPCErrorCode.INTERNAL_ERROR


def exception_classes() -> tuple[type[BaseException], ...]:
    """Tuple of registered classes, suitable for ``except (...) as e:``."""
    return tuple(cls for cls, _ in EXCEPTION_TO_CODE)

