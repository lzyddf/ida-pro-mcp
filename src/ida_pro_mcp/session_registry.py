"""Proxy-side directory of live IDA sessions.

The registry sits between the FastMCP bridge and :class:`IDARpcClient`:
when a tool call carries a ``session`` argument we hand back the cached
client for that session; when the argument is omitted we auto-pick the
sole running session, or raise a structured "ambiguous" error.

Discovery is delegated to :mod:`.plugin.session` (sidecar JSON files).
The registry layers two concerns on top:

* **Caching**: keeps one :class:`IDARpcClient` per session id so the
  client's per-instance request-id counter (an ``itertools.count`` in
  :mod:`.client`) survives across calls instead of resetting on every
  dispatch.
* **Liveness**: when a sidecar's port changes (IDA restarted on the
  same IDB), the cached client for that id is replaced transparently.

Errors raised here are deliberately *not* :class:`JSONRPCError` -- those
encode a wire format we send back to clients of the in-IDA server. This
module's errors travel the other direction (proxy -> MCP host) and are
caught by FastMCP, which surfaces them to the LLM as a tool error.
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .client import IDARpcClient
from .plugin.constants import DEFAULT_HTTP_TIMEOUT_S
from .plugin.session import SessionInfo, get, list_all

if TYPE_CHECKING:
    from collections.abc import Callable


class SessionResolutionError(RuntimeError):
    """Base class for "couldn't resolve a session id to a client" failures."""


class SessionNotFoundError(SessionResolutionError):
    """Raised when no live IDA session matches the request.

    The LLM-facing message is intentionally actionable: it tells the
    user/agent how to bring a session into existence.
    """

    def __init__(self, session_id: str | None):
        self.session_id = session_id
        if session_id is None:
            message = (
                "No IDA session is running. Call open_file(path=...) "
                "to spawn a headless IDA, then retry."
            )
        else:
            message = (
                f"No IDA session named {session_id!r} is running. "
                "Call list_ida_sessions to see which sessions are available."
            )
        super().__init__(message)


class SessionAmbiguousError(SessionResolutionError):
    """Raised when more than one session is live and the caller didn't pick one."""

    def __init__(self, available: list[str]):
        self.available_sessions = list(available)
        super().__init__(
            "Multiple IDA sessions are running ("
            + ", ".join(self.available_sessions)
            + "); pass `session=<id>` to pick one. "
            "Call list_ida_sessions for full details."
        )


class SessionRegistry:
    """Maintain a (session_id -> :class:`IDARpcClient`) cache.

    Thread-safe: ``resolve`` may be invoked from FastMCP's worker threads
    concurrently. Cache misses build a fresh client; cache hits validate
    that the recorded port hasn't changed (a restarted IDA on the same
    IDB keeps its session id but rebinds to a new ephemeral port).
    """

    def __init__(self, *, timeout: float = DEFAULT_HTTP_TIMEOUT_S) -> None:
        self._timeout = timeout
        self._clients: dict[str, IDARpcClient] = {}
        self._lock = threading.Lock()

    # --- Public surface ------------------------------------------------------

    def list_sessions(self) -> list[SessionInfo]:
        """Return every live session known on disk."""
        return list_all()

    def get_session_info(self, session_id: str) -> SessionInfo | None:
        return get(session_id)

    def resolve(self, session_id: str | None) -> IDARpcClient:
        """Map *session_id* (or ``None``) to a usable :class:`IDARpcClient`.

        ``None`` works exactly when there is *one* live session. With
        zero we raise :class:`SessionNotFoundError`; with multiple we
        raise :class:`SessionAmbiguousError`. Callers (the bridge proxy
        and ``check_connection``) decide how to surface those errors.
        """
        if session_id is not None:
            return self._get_client(session_id)

        sessions = list_all()
        if not sessions:
            raise SessionNotFoundError(None)
        if len(sessions) > 1:
            raise SessionAmbiguousError([s.session_id for s in sessions])
        return self._get_client(sessions[0].session_id)

    def make_dispatch(self) -> Callable[[str, dict, str | None], object]:
        """Return a session-aware dispatch hook for the FastMCP bridge.

        The bridge proxies pop ``session`` out of the kwargs and pass it
        as the third argument; we resolve to the right client and forward
        the tool call. Exposing it as a closure keeps the bridge ignorant
        of registry internals.
        """
        def dispatch(method: str, params: dict, session_id: str | None) -> object:
            return self.resolve(session_id).call(method, params)
        return dispatch

    def invalidate(self, session_id: str) -> None:
        """Drop the cached client for *session_id* (e.g. after an explicit close)."""
        with self._lock:
            self._clients.pop(session_id, None)

    # --- Internals -----------------------------------------------------------

    def _get_client(self, session_id: str) -> IDARpcClient:
        info = get(session_id)
        if info is None:
            with self._lock:
                self._clients.pop(session_id, None)
            raise SessionNotFoundError(session_id)

        with self._lock:
            cached = self._clients.get(session_id)
            if cached is not None and cached.host == info.host and cached.port == info.port:
                return cached
            client = IDARpcClient(host=info.host, port=info.port, timeout=self._timeout)
            self._clients[session_id] = client
            return client
