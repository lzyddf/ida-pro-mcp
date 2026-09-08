"""Shared IDA-side protocol package.

Importing :mod:`ida_pro_mcp.plugin` is intentionally side-effect free. Proxy
modules frequently need lightweight protocol pieces such as ``constants``,
``errors`` or ``session``; those imports must not install IDA SDK stubs and
eagerly import every tool implementation.

Call :func:`load_tools` explicitly in processes that need the RPC tool
registry populated. The proxy bridge and headless bootstrap do this at their
composition boundaries.
"""
from __future__ import annotations

from .errors import (
    IDAError,
    IDAErrorKind,
    IDARpcTransportError,
    IDASyncError,
    JSONRPCError,
    JSONRPCErrorCode,
    ensure_ok,
)
from .registry import jsonrpc, rpc_registry, unsafe


def load_tools() -> tuple[str, ...]:
    """Load every IDA tool module once and return the module names."""
    from .tools import load_tools as _load_tools

    return _load_tools()


__all__ = [
    "IDAError",
    "IDAErrorKind",
    "IDARpcTransportError",
    "IDASyncError",
    "JSONRPCError",
    "JSONRPCErrorCode",
    "ensure_ok",
    "jsonrpc",
    "load_tools",
    "rpc_registry",
    "unsafe",
]
