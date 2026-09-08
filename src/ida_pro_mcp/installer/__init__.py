"""Installer subpackage: interpreter probing and MCP config rendering.

The responsibilities live in dedicated submodules:

* :mod:`.proxy_python` -- locate the *proxy* interpreter the MCP host should
  spawn; forward the Python env vars (``PYTHONHOME`` etc.) it needs.
* :mod:`.config` -- render the ``mcpServers`` JSON snippet (optional
  ``unsafe`` / HTTP-transport variants).

Only the *public* helpers are re-exported here. Tests that need to override
internal behaviour should monkeypatch the *submodule* attribute directly,
e.g. ``ida_pro_mcp.installer.proxy_python._venv_python``.
"""
from __future__ import annotations

from .config import build_mcp_config, print_mcp_config
from .proxy_python import (
    PYTHON_ENV_VARS,
    collect_python_env,
    get_python_executable,
)

__all__ = [
    "PYTHON_ENV_VARS",
    "build_mcp_config",
    "collect_python_env",
    "get_python_executable",
    "print_mcp_config",
]
