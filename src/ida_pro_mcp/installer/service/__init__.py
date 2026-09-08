"""Cross-platform installer for the ida-pro-mcp-headless proxy as a long-running OS service.

Each platform has its own service framework (Windows Scheduled Task, macOS
launchd, Linux systemd ``--user``) and the gory details of XML / plist /
INI / ``systemctl`` invocation live in ``_<platform>.py``. The dispatcher
below reads :data:`sys.platform` once and forwards to the matching backend
or raises :class:`ServiceUnsupportedError` with a message that points at
the README template the user can use until that backend lands.

The public surface is intentionally tiny -- ``install`` / ``uninstall`` /
``status`` -- so adding a new platform later is a self-contained task that
doesn't touch any callers.
"""
from __future__ import annotations

import sys
from typing import Any

from ...plugin.constants import DEFAULT_HOST, DEFAULT_REMOTE_PORT
from ...runtime_args import HTTP_TRANSPORTS, HTTPTransport


class ServiceUnsupportedError(NotImplementedError):
    """Raised when ``--service`` is used on a platform without a backend."""


def _backend():
    """Return the platform-specific service backend module.

    The branches return *modules*, not instances, so each backend can keep
    its public functions module-level (``install``, ``uninstall``, ``status``)
    without forcing a class boundary nobody asked for.
    """
    if sys.platform.startswith("win"):
        from . import _windows as backend

        return backend
    if sys.platform == "darwin":
        raise ServiceUnsupportedError(
            "macOS launchd backend is not implemented yet. Use the README's "
            "LaunchAgent template until --service supports macOS, or run the "
            "proxy from a terminal with `ida-pro-mcp-headless serve --transport ...`."
        )
    if sys.platform.startswith("linux"):
        raise ServiceUnsupportedError(
            "Linux systemd backend is not implemented yet. Use the README's "
            "systemd --user template until --service supports Linux, or run "
            "the proxy from a terminal with `ida-pro-mcp-headless serve --transport ...`."
        )
    raise ServiceUnsupportedError(
        f"--service is not supported on platform {sys.platform!r}. "
        "Run the proxy manually with `ida-pro-mcp-headless serve --transport ...`."
    )


def install_service(
    *,
    transport: HTTPTransport = "streamable-http",
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_REMOTE_PORT,
    unsafe: bool = False,
    ida_home: str | None = None,
) -> dict[str, Any]:
    """Register and start a per-user service that runs the proxy.

    ``transport`` must be an HTTP-style transport; a service with stdio
    transport has no listener and is rejected here as well as by the CLI.
    ``ida_home`` is the IDA install directory stored in the service
    configuration as ``IDA_PRO_HOME``; if ``None``, the value is taken from the
    current shell's ``IDA_PRO_HOME`` (or a placeholder is written and a
    warning is emitted).

    Returns a dict describing the registered service so callers (the CLI
    in particular) can show paths and the URL that the MCP client should
    connect to.
    """
    if transport not in HTTP_TRANSPORTS:
        raise ValueError(
            "service transport must be 'streamable-http' or 'sse', "
            f"got {transport!r}"
        )
    return _backend().install(
        transport=transport,
        host=host,
        port=port,
        unsafe=unsafe,
        ida_home=ida_home,
    )


def uninstall_service() -> dict[str, Any]:
    """Stop and unregister the service. Idempotent (no-op if absent)."""
    return _backend().uninstall()


def service_status() -> dict[str, Any]:
    """Inspect the registered service. Always returns ``installed: bool``."""
    return _backend().status()


__all__ = [
    "ServiceUnsupportedError",
    "install_service",
    "service_status",
    "uninstall_service",
]
