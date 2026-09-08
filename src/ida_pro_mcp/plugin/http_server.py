"""JSON-RPC over HTTP server hosted inside headless IDA Pro.

Listens on a localhost-only socket and dispatches requests to the
``rpc_registry``. The server runs single-threaded on the IDA main
thread that called :meth:`Server.serve_in_current_thread`: ``idat -A``
has no Qt event loop, so a worker-thread server would deadlock the
moment any ``@idaread`` / ``@idawrite`` handler trampolined through
``execute_sync`` (the main thread, blocked in ``serve_forever``, would
never service the queued callback). Running the request loop on the
IDA main thread itself lets those handlers short-circuit ``execute_sync``
to a direct call.

The default port is ``0`` (kernel-assigned ephemeral); the proxy CLI
discovers the actual port through the per-session sidecar files written
by :mod:`.session`. This intentionally lets multiple IDA processes run
concurrently without colliding on a single hardcoded port.
"""
from __future__ import annotations

import http.server
import json
import logging
import threading
from typing import Any
from urllib.parse import urlparse

from .constants import DEFAULT_HOST, HTTP_ENDPOINT_PATH
from .errors import (
    JSONRPCError,
    JSONRPCErrorCode,
    code_for_exception,
    exception_classes,
)
from .jsonrpc import (
    make_error_response,
    make_success_response,
    validate_request_envelope,
)
from .registry import RPCRegistry
from .registry import rpc_registry as default_registry

logger = logging.getLogger(__name__)

# Snapshot the registered tool-side exception classes once at import. The
# table is static for the lifetime of the process, so rebuilding the tuple
# on every request would just be wasted allocation.
_TOOL_EXCEPTIONS: tuple[type[BaseException], ...] = exception_classes()

# Hard ceiling on accepted request bodies. We listen on localhost only, but
# malformed / malicious clients should not be able to make us allocate
# unbounded memory just by lying in ``Content-Length``. 32 MiB is well above
# anything a real RPC payload needs (the largest dump tools we ship cap out
# in the low MiB range) but small enough that an accidental
# ``Content-Length: 99999999999`` is rejected before ``rfile.read`` allocates
# a buffer.
_MAX_REQUEST_BYTES = 32 * 1024 * 1024

# Chunk size for best-effort discards of unread POST bodies. When we reject a
# request *before* ``rfile.read(content_length)``, bytes the client already
# pushed remain in the TCP stream. If ``BaseHTTPRequestHandler`` then re-enters
# ``handle_one_request`` for keep-alive, those bytes look like the next HTTP
# preamble → protocol corruption and an abrupt close (``WinError 10053`` on the
# client while reading the real response). Draining caps work at
# ``_MAX_REQUEST_BYTES`` so a malicious ``Content-Length`` cannot make us loop
# forever.
_READ_DISCARD_CHUNK = 64 * 1024


class _RPCHTTPServer(http.server.HTTPServer):
    """Single-threaded HTTPServer carrying the registry the handler dispatches to.

    Single-threaded by design: see the module docstring -- a worker-thread
    server would deadlock ``@idaread`` handlers in headless mode.
    """

    def __init__(self, server_address, registry: RPCRegistry):
        super().__init__(server_address, JSONRPCRequestHandler)
        self.registry = registry


class JSONRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    """Dispatches POST /mcp requests to the registry held by the parent server."""

    server: _RPCHTTPServer  # type: ignore[assignment]

    def _discard_unread_body(self, nbytes: int) -> None:
        """Skip up to *nbytes* of request body already sitting on ``rfile``.

        *nbytes* is capped internally so callers can pass an advertised
        ``Content-Length`` larger than :data:`_MAX_REQUEST_BYTES` without
        reading gigabytes from a hostile peer.

        Uses a short per-read timeout so we do not block forever when the
        client already finished sending (e.g. bogus ``Content-Length`` but a
        small real payload, or an oversized header with an empty body).
        """
        if nbytes <= 0:
            return
        limit = min(nbytes, _MAX_REQUEST_BYTES)
        sock = self.connection
        old_timeout = sock.gettimeout()
        try:
            sock.settimeout(0.05)
            remaining = limit
            while remaining > 0:
                try:
                    chunk = self.rfile.read(min(_READ_DISCARD_CHUNK, remaining))
                except TimeoutError:
                    break
                if not chunk:
                    break
                remaining -= len(chunk)
        finally:
            sock.settimeout(old_timeout)

    def _discard_body_best_effort_unknown_len(self) -> None:
        """Discard when ``Content-Length`` is missing or not parseable.

        We cannot trust the numeric header, so pull up to
        :data:`_MAX_REQUEST_BYTES` from the wire using short reads with a
        bounded wait -- enough for legitimate localhost tests (bad
        ``Content-Length`` + real JSON payload) without deadlocking against
        a keep-alive peer that is already waiting for our HTTP response.
        """
        self._discard_unread_body(_MAX_REQUEST_BYTES)

    def _send_json(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_jsonrpc_error(self, code: int, message: str, request_id: Any = None) -> None:
        self._send_json(make_error_response(code, message, request_id=request_id))

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path_ok = parsed.path == HTTP_ENDPOINT_PATH

        # Parse ``Content-Length`` before branching on path so wrong-endpoint
        # replies still discard any body the client already sent.
        raw_length = self.headers.get("Content-Length")
        content_length: int | None = None
        cl_parseable = False
        if raw_length is not None:
            try:
                content_length = int(raw_length)
                cl_parseable = True
            except ValueError:
                content_length = None

        if not path_ok:
            if not cl_parseable and raw_length is not None:
                self._discard_body_best_effort_unknown_len()
            elif cl_parseable and content_length is not None and content_length > 0:
                self._discard_unread_body(content_length)
            elif raw_length is None:
                self._discard_body_best_effort_unknown_len()
            self._send_jsonrpc_error(JSONRPCErrorCode.INVALID_ENDPOINT, "Invalid endpoint")
            return

        # ``Content-Length`` may be absent, non-numeric, negative, or absurdly
        # large; defend against all four before allocating a buffer in
        # ``rfile.read``. We map every failure to a JSON-RPC ``Invalid Request``
        # so clients get a structured response instead of a bare HTTP error.
        if raw_length is None:
            self._send_jsonrpc_error(JSONRPCErrorCode.INVALID_REQUEST, "Missing Content-Length header")
            return
        if not cl_parseable:
            self._discard_body_best_effort_unknown_len()
            self._send_jsonrpc_error(JSONRPCErrorCode.INVALID_REQUEST, "Invalid Content-Length header")
            return
        assert content_length is not None
        if content_length <= 0:
            self._send_jsonrpc_error(JSONRPCErrorCode.PARSE_ERROR, "Parse error: missing request body")
            return
        if content_length > _MAX_REQUEST_BYTES:
            self._discard_unread_body(content_length)
            self._send_jsonrpc_error(
                JSONRPCErrorCode.INVALID_REQUEST,
                f"Request body too large ({content_length} bytes; max {_MAX_REQUEST_BYTES})",
            )
            return

        try:
            request = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError:
            self._send_jsonrpc_error(JSONRPCErrorCode.PARSE_ERROR, "Parse error: invalid JSON")
            return

        request_id = request.get("id") if isinstance(request, dict) else None

        try:
            envelope = validate_request_envelope(request)
            result = self.server.registry.dispatch(envelope["method"], envelope.get("params", {}))
            self._send_json(make_success_response(result, request_id))
        except JSONRPCError as e:
            self._send_json(make_error_response(e.code, e.message, request_id=request_id, data=e.data))
        except _TOOL_EXCEPTIONS as e:
            code = code_for_exception(e)
            message = getattr(e, "message", str(e))
            # ``kind`` (when present) lets clients branch on a stable string
            # instead of fuzzy-matching the human-readable message.
            kind = getattr(e, "kind", None)
            data = {"kind": kind.value} if kind is not None and hasattr(kind, "value") else None
            self._send_json(make_error_response(code, message, request_id=request_id, data=data))
        except Exception:
            logger.exception("internal error while dispatching JSON-RPC request")
            try:
                self._send_json(make_error_response(
                    JSONRPCErrorCode.INTERNAL_ERROR,
                    "Internal error (please report a bug)",
                    request_id=request_id,
                ))
            except Exception:
                logger.exception("failed to send JSON-RPC response")

    def log_message(self, format: str, *args: Any) -> None:
        return  # silence the default access log


class Server:
    """HTTP server that exposes the RPC registry on a localhost port.

    The serve loop runs on the *calling* thread (the headless bootstrap's
    main thread). Each request is handled inline on that thread so
    ``@idaread`` / ``@idawrite`` decorated handlers see ``execute_sync``
    running them without trampolining -- there is no Qt loop in
    ``idat -A`` to drain the queue otherwise. :meth:`stop` from any
    thread (e.g. the kill-switch watcher / signal handler) wakes
    ``serve_forever`` cleanly on its next ``select`` poll.

    The socket is bound synchronously by :meth:`bind`; port conflicts
    surface as :class:`OSError` so the caller can react before publishing
    a sidecar with port 0.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = 0,
        registry: RPCRegistry | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.registry = registry or default_registry
        self._server: _RPCHTTPServer | None = None
        # ``True`` while ``serve_forever`` is running. We need this because
        # ``HTTPServer.shutdown`` blocks on an internal ``Event`` that is
        # only set by ``serve_forever`` on exit -- calling ``shutdown``
        # before ``serve_forever`` ever started would block forever.
        self._serving = False
        # Serialises ``stop()``: the kill-switch watcher and the main
        # thread's ``finally`` cleanup both race to clear ``_server``;
        # the lock makes the second caller a no-op rather than a double
        # ``server_close``.
        self._stop_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def bound_port(self) -> int | None:
        """Actual TCP port the server is listening on, or ``None`` when stopped.

        Differs from :attr:`port` when the server was constructed with
        ``port=0`` (ephemeral binding), e.g. in tests.
        """
        if self._server is None:
            return None
        return self._server.server_address[1]

    def bind(self) -> None:
        """Create and bind the underlying ``HTTPServer``; idempotent.

        Public so callers that need the bound port *before* the serve
        loop starts (notably the headless bootstrap, which writes the
        port into the session sidecar so the proxy can find us) can
        bind first and then call :meth:`serve_in_current_thread` once
        all advertisement is in place.

        Failure leaves ``_server`` ``None`` so a retry doesn't see a
        half-initialised instance.
        """
        if self._server is not None:
            return
        try:
            self._server = _RPCHTTPServer((self.host, self.port), self.registry)
        except OSError as e:
            logger.error("Failed to bind MCP server to %s:%d: %s", self.host, self.port, e)
            self._server = None
            raise
        logger.info("MCP server listening at http://%s:%d", self.host, self.bound_port)

    def serve_in_current_thread(self) -> None:
        """Bind (if needed) and run ``serve_forever`` inline on this thread.

        Returns when another thread calls :meth:`stop` (the kill-switch
        watcher / signal handler in headless mode). Any exception raised
        during serving is logged and swallowed so the caller's ``finally``
        cleanup runs reliably; we do *not* re-raise because that would
        skip ``server_close`` and leak the listening socket.
        """
        self.bind()
        if self._server is None:
            raise RuntimeError("Server worker started before socket bind")
        self._serving = True
        try:
            self._server.serve_forever()
        except Exception:
            logger.exception("MCP server crashed; the headless session will exit")
        finally:
            self._serving = False

    def stop(self) -> None:
        """Stop the server; safe to call from any thread, idempotent.

        ``HTTPServer.shutdown`` blocks on an internal ``Event`` that
        ``serve_forever`` only sets on exit, so calling it before the
        loop ever started would deadlock. We therefore only shut down
        when ``_serving`` is set; otherwise we close the socket directly
        (covers the bind-but-never-serve cleanup path used by tests and
        bind-failure handling).

        Idempotent under concurrent callers: both the watcher thread
        and the main thread's cleanup routine race to call ``stop``;
        ``_stop_lock`` serialises them so the second caller observes
        ``_server is None`` and exits without attempting a double
        ``server_close``.
        """
        with self._stop_lock:
            srv = self._server
            if srv is None:
                return
            self._server = None
            if self._serving:
                srv.shutdown()
            srv.server_close()
        logger.info("MCP server stopped")
