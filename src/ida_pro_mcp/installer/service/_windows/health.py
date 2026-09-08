"""TCP health checks used after starting the Windows background task."""
from __future__ import annotations

import http.client
import socket
import time


class ServiceStartError(RuntimeError):
    """Raised when the registered service does not open its listener in time."""


def probe_host(bind_host: str) -> str:
    """Translate wildcard bind addresses into addresses a client can dial."""
    if bind_host == "0.0.0.0":
        return "127.0.0.1"
    if bind_host == "::":
        return "::1"
    return bind_host


def listener_is_reachable(host: str, port: int, *, timeout: float = 0.25) -> bool:
    """Return whether an HTTP server answers on the configured listener."""
    connection = http.client.HTTPConnection(probe_host(host), port, timeout=timeout)
    try:
        connection.request("GET", "/__ida_pro_mcp_health__")
        response = connection.getresponse()
        response.read()
        return True
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def port_is_available(host: str, port: int) -> bool:
    """Return whether the requested bind address can currently be acquired."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as candidate:
            candidate.bind((host, port))
    except OSError:
        return False
    return True


def wait_for_listener(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
    poll_interval: float = 0.1,
) -> None:
    """Wait for the proxy listener or raise a concise installation error."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if listener_is_reachable(host, port):
            return
        time.sleep(poll_interval)
    target = f"{probe_host(host)}:{port}"
    raise ServiceStartError(f"service was registered but did not listen on {target} within {timeout:g}s")


def wait_for_listener_to_close(
    host: str,
    port: int,
    *,
    timeout: float = 5.0,
    poll_interval: float = 0.1,
) -> None:
    """Wait for a previous task instance to release its listener."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_is_available(host, port):
            return
        time.sleep(poll_interval)
    target = f"{probe_host(host)}:{port}"
    raise ServiceStartError(
        f"{target} is still in use after stopping the previous task; "
        "another proxy or process may own the port"
    )
