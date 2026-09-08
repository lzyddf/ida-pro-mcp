"""Canonical command-line arguments for launching the MCP proxy.

The generated MCP config and OS-service installers both launch
``ida_pro_mcp.__main__`` directly. Keeping their argv construction here makes
the CLI subcommand contract a single source of truth: every non-empty launch
must begin with ``serve``.
"""
from __future__ import annotations

from typing import Final, Literal

from .plugin.constants import DEFAULT_HOST, DEFAULT_REMOTE_PORT

Transport = Literal["stdio", "streamable-http", "sse"]
HTTPTransport = Literal["streamable-http", "sse"]

VALID_TRANSPORTS: Final[tuple[Transport, ...]] = ("stdio", "streamable-http", "sse")
HTTP_TRANSPORTS: Final[tuple[HTTPTransport, ...]] = ("streamable-http", "sse")


def build_serve_argv(
    *,
    transport: Transport = "stdio",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_REMOTE_PORT,
    unsafe: bool = False,
) -> list[str]:
    """Return arguments accepted by :func:`ida_pro_mcp.cli.main`.

    Host and port are emitted only for HTTP transports; they are meaningless
    under stdio and should not leak into generated client configurations.
    """
    if transport not in VALID_TRANSPORTS:
        raise ValueError(f"unsupported transport {transport!r}")

    argv = ["serve"]
    if transport != "stdio":
        argv.extend(("--transport", transport, "--host", host, "--port", str(port)))
    if unsafe:
        argv.append("--unsafe")
    return argv
