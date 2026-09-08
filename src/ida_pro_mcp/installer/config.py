"""Render an MCP client config snippet that the user can paste into their client."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from ..plugin.constants import (
    DEFAULT_HOST,
    DEFAULT_REMOTE_PORT,
    DEFAULT_TIMEOUT_S,
    MCP_SERVER_NAME,
)
from ..runtime_args import Transport, build_serve_argv
from ..spawner.locator import IDA_HOME_ENV_VAR, locate_idat_in_home
from .proxy_python import collect_python_env, get_python_executable

PACKAGE_DIR = Path(__file__).resolve().parent.parent  # src/ida_pro_mcp/
SERVER_ENTRY_PY = PACKAGE_DIR / "__main__.py"

# Visible placeholder that lands in ``env.IDA_PRO_HOME`` when the user has
# not exported the variable themselves. The string is shouty (uppercase +
# ``REPLACE_``) so it survives a casual scan. Real paths supplied explicitly
# or through ``IDA_PRO_HOME`` are validated before user-facing config output;
# only the deliberate placeholder bypasses validation.
_IDA_HOME_PLACEHOLDER = "REPLACE_WITH_PATH_TO_IDA_INSTALL_DIR"

# Per-transport URL paths FastMCP exposes when run with HTTP transports.
# Mirrors :class:`mcp.server.fastmcp.server.Settings` defaults; if FastMCP
# changes these, regenerated configs would point at 404s without a hint,
# so we keep a local copy and assert the mapping in tests.
_HTTP_TRANSPORT_PATHS: dict[str, str] = {
    "streamable-http": "/mcp",
    "sse": "/sse",
}


def _resolve_ida_home(explicit: str | None = None) -> tuple[str, bool]:
    """Pick the value to write into ``env.IDA_PRO_HOME``.

    Returns ``(value, is_placeholder)``. If the user already exported
    ``IDA_PRO_HOME`` we forward it verbatim so the rendered config is
    ready-to-paste; otherwise we emit the placeholder and rely on
    :func:`print_mcp_config` to surface a one-line stderr hint.
    """
    if explicit:
        return explicit, False
    existing = os.environ.get(IDA_HOME_ENV_VAR)
    if existing:
        return existing, False
    return _IDA_HOME_PLACEHOLDER, True


def _validated_ida_home(explicit: str | None = None) -> tuple[str, bool]:
    """Resolve the IDA home value and immediately validate every real path.

    ``config`` may still render the visible placeholder when neither an
    explicit value nor ``IDA_PRO_HOME`` is present. Any concrete value must
    contain an executable ``idat`` accepted by the runtime locator.
    """
    value, is_placeholder = _resolve_ida_home(explicit)
    if not is_placeholder:
        locate_idat_in_home(value)
    return value, is_placeholder


def _build_stdio_config(
    env: dict[str, str] | None,
    *,
    unsafe: bool,
    ida_home: str | None,
) -> dict[str, Any]:
    """Render the ``command``/``args``/``env`` shape used by stdio transports."""
    args_list = [str(SERVER_ENTRY_PY), *build_serve_argv(unsafe=unsafe)]
    config: dict[str, Any] = {
        "command": get_python_executable(),
        "args": args_list,
        "timeout": DEFAULT_TIMEOUT_S,
        "disabled": False,
    }
    merged_env: dict[str, str] = dict(env) if env else {}
    merged_env.setdefault(IDA_HOME_ENV_VAR, _resolve_ida_home(ida_home)[0])
    config["env"] = merged_env
    return config


def _build_http_config(*, transport: str, host: str, port: int) -> dict[str, Any]:
    """Render the ``url`` shape used by streamable-http / sse transports.

    The MCP client connects to a *separately-launched* proxy in this mode, so
    no ``command``/``env`` keys are needed here -- the proxy spawns IDA and
    consumes ``IDA_PRO_HOME`` from its own startup environment (the shell that
    ran ``ida-pro-mcp-headless serve``), not from the client config. That's exactly
    why remote configs have no idat-related field at all.
    """
    if transport not in _HTTP_TRANSPORT_PATHS:
        raise ValueError(f"unsupported HTTP transport {transport!r}")
    url = f"http://{host}:{port}{_HTTP_TRANSPORT_PATHS[transport]}"
    return {
        "url": url,
        "timeout": DEFAULT_TIMEOUT_S,
        "disabled": False,
    }


def build_mcp_config(
    env: dict[str, str] | None = None,
    *,
    unsafe: bool = False,
    transport: Transport = "stdio",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_REMOTE_PORT,
    ida_home: str | None = None,
) -> dict[str, Any]:
    """Build a stand-alone ``mcpServers`` entry for the current installation.

    The user is expected to paste this into their MCP client's config file.
    The shape depends on *transport*:

    * ``"stdio"`` (default) -- ``command``/``args``/``env`` so the MCP client
      spawns the proxy as a subprocess. ``env`` always contains
      ``IDA_PRO_HOME`` (real path or placeholder) so users see the slot
      they need to fill in for the AI-driven ``open_file`` tool. *env*
      (typically :func:`.collect_python_env`) is merged in first; existing
      ``IDA_PRO_HOME`` entries from the caller win over the auto-fill so
      explicit overrides remain possible.
    * ``"streamable-http"`` / ``"sse"`` -- a ``url`` pointing at the proxy's
      HTTP listener. The proxy is expected to be running already
      (``ida-pro-mcp-headless serve --transport <T> --host <H> --port <P>``); the MCP
      client just connects, and the proxy reads ``IDA_PRO_HOME`` from its
      own shell environment.
    """
    if transport == "stdio":
        return _build_stdio_config(env, unsafe=unsafe, ida_home=ida_home)
    return _build_http_config(transport=transport, host=host, port=port)


def print_mcp_config(
    *,
    unsafe: bool = False,
    transport: Transport = "stdio",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_REMOTE_PORT,
    ida_home: str | None = None,
) -> None:
    """Print a JSON snippet that the user can paste into an MCP client.

    Diagnostics (warnings, hints) go to **stderr** so ``ida-pro-mcp-headless config |
    clip`` (or ``> mcp.json``) captures only the JSON payload on stdout.
    """
    if transport == "stdio":
        env = collect_python_env()
        if env:
            print("[WARNING] Custom Python environment variables detected", file=sys.stderr)

        resolved_ida_home, ida_is_placeholder = _validated_ida_home(ida_home)
        if ida_is_placeholder:
            print(
                f"[NOTE] {IDA_HOME_ENV_VAR} is not set; the rendered config carries a "
                f"placeholder ({_IDA_HOME_PLACEHOLDER!r}). Replace it with the absolute "
                "path to your IDA install directory (the folder containing idat / "
                f"idat.exe) before pasting into your MCP client config, or export "
                f"{IDA_HOME_ENV_VAR} in this shell and re-run `config` to bake the "
                "path in.",
                file=sys.stderr,
            )

        config = build_mcp_config(env=env, unsafe=unsafe, ida_home=resolved_ida_home)
    else:
        if host == "0.0.0.0":
            print(
                "[NOTE] --host 0.0.0.0 binds every interface; the URL below uses it "
                "verbatim, which is not a routable client address. Replace it with "
                "the IP your MCP client should connect to before pasting.",
                file=sys.stderr,
            )
        if unsafe:
            print(
                "[WARNING] --unsafe over a remote transport exposes mutating "
                "tools (patching, breakpoints) to anyone who can reach this port. "
                "Prefer a tunnel (SSH, Tailscale, WireGuard) over raw exposure.",
                file=sys.stderr,
            )
        serve_argv = build_serve_argv(
            transport=transport,
            host=host,
            port=port,
            unsafe=unsafe,
        )
        print(
            f"[INFO] Start the proxy with:  ida-pro-mcp-headless {' '.join(serve_argv)}",
            file=sys.stderr,
        )

        config = build_mcp_config(transport=transport, host=host, port=port, unsafe=unsafe)

    print(json.dumps({"mcpServers": {MCP_SERVER_NAME: config}}, indent=2))
