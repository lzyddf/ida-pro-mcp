"""FastMCP server assembly for the ``ida-pro-mcp-headless`` proxy.

This module *only* knows how to compose a :class:`FastMCP` server out of
:class:`SessionRegistry`, the JSON-RPC dispatch, and the local /
remote tool registries. CLI argparse + subcommand dispatch live in
:mod:`ida_pro_mcp.cli`; the IDA-side plugin lives in
:mod:`ida_pro_mcp.plugin`.

Multi-IDA support is built in: the :class:`SessionRegistry` discovers
every running IDA via the per-session sidecar files written by the plugin,
and the FastMCP bridge appends a ``session`` parameter to every tool so
the LLM can pick the target.
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from ._tool_bridge import Backend, register_local_tools, register_remote_tools
from .plugin.constants import DEFAULT_HOST, DEFAULT_REMOTE_PORT, MCP_SERVER_NAME
from .session_registry import SessionRegistry
from .spawner import Spawner


def build_mcp_server(
    registry: SessionRegistry,
    *,
    include_unsafe: bool,
    spawner: Spawner | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_REMOTE_PORT,
) -> FastMCP:
    """Build a fully-configured FastMCP server bound to *registry*.

    Public so tests and embedders can drive the assembly without going through
    the argparse-driven CLI. Pass ``spawner=None`` to disable the AI-driven
    ``open_file`` / ``close_file`` tools (handy for embedders or sandboxed
    environments where launching ``idat`` is not allowed). *host* and *port*
    must be supplied at construction time for HTTP transports: FastMCP derives
    its DNS-rebinding policy from the initial host, so mutating the settings
    later can leave a ``0.0.0.0`` listener that rejects every non-loopback
    ``Host`` header.
    """
    # ``log_level="ERROR"`` is required to keep Cline happy:
    # https://github.com/jlowin/fastmcp/issues/81
    mcp = FastMCP(MCP_SERVER_NAME, log_level="ERROR", host=host, port=port)
    dispatch = registry.make_dispatch()
    backend = Backend(
        dispatch=dispatch,
        list_sessions=registry.list_sessions,
        spawner=spawner,
    )
    register_local_tools(mcp, backend=backend, include_unsafe=include_unsafe)
    register_remote_tools(mcp, dispatch=dispatch, include_unsafe=include_unsafe)
    return mcp
