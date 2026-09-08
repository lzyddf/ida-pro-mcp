"""Integration tests for the HTTP server (round-trip via IDARpcClient)."""
from __future__ import annotations

import contextlib
import http.client
import json
import sys
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest

from ida_pro_mcp.client import IDARpcClient
from ida_pro_mcp.plugin.constants import HTTP_ENDPOINT_PATH
from ida_pro_mcp.plugin.errors import IDAError, IDAErrorKind, JSONRPCErrorCode
from ida_pro_mcp.plugin.http_server import Server
from ida_pro_mcp.plugin.jsonrpc import RemoteJSONRPCError
from ida_pro_mcp.plugin.registry import RPCRegistry


@contextlib.contextmanager
def _serve(registry: RPCRegistry, *, host: str = "127.0.0.1", port: int = 0) -> Iterator[Server]:
    """Bind a :class:`Server` and run its loop on a worker thread.

    The server's ``serve_in_current_thread`` runs single-threaded by design
    (so ``@idaread`` handlers can short-circuit ``execute_sync``); tests
    that need a live listener wrap it in a daemon thread and join on
    teardown.
    """
    server = Server(host=host, port=port, registry=registry)
    server.bind()
    thread = threading.Thread(target=server.serve_in_current_thread, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stop()
        thread.join(timeout=3)


@pytest.fixture()
def server_with_registry() -> Iterator[IDARpcClient]:
    registry = RPCRegistry()

    def echo(message: str) -> str:
        return f"hi {message}"

    def boom() -> None:
        raise IDAError("kaboom")

    def crash() -> None:
        raise RuntimeError("internal explosion")

    registry.register(echo)
    registry.register(boom)
    registry.register(crash)

    with _serve(registry) as server:
        assert server.bound_port is not None
        yield IDARpcClient(host="127.0.0.1", port=server.bound_port, timeout=5)


class TestSuccess:
    def test_round_trip_success(self, server_with_registry):
        assert server_with_registry.call("echo", {"message": "world"}) == "hi world"


class TestErrors:
    def test_ida_error_mapped(self, server_with_registry):
        with pytest.raises(RemoteJSONRPCError) as exc:
            server_with_registry.call("boom", {})
        assert exc.value.code == JSONRPCErrorCode.IDA_ERROR
        assert exc.value.message == "kaboom"

    def test_ida_error_kind_propagated(self):
        registry = RPCRegistry()

        def missing() -> None:
            raise IDAError("not here", IDAErrorKind.NOT_FOUND)

        registry.register(missing)
        with _serve(registry) as server:
            assert server.bound_port is not None
            client = IDARpcClient(host="127.0.0.1", port=server.bound_port, timeout=5)
            with pytest.raises(RemoteJSONRPCError) as exc:
                client.call("missing", {})
            assert exc.value.code == JSONRPCErrorCode.IDA_ERROR
            assert exc.value.data == {"kind": "not_found"}

    def test_ida_error_default_kind_propagates_unknown(self):
        registry = RPCRegistry()

        def legacy() -> None:
            raise IDAError("just a message")  # no kind

        registry.register(legacy)
        with _serve(registry) as server:
            assert server.bound_port is not None
            client = IDARpcClient(host="127.0.0.1", port=server.bound_port, timeout=5)
            with pytest.raises(RemoteJSONRPCError) as exc:
                client.call("legacy", {})
            # ``UNKNOWN`` still propagates so clients see *something* consistent.
            assert exc.value.data == {"kind": "unknown"}

    def test_internal_error_does_not_leak_traceback(self, server_with_registry):
        with pytest.raises(RemoteJSONRPCError) as exc:
            server_with_registry.call("crash", {})
        assert exc.value.code == JSONRPCErrorCode.INTERNAL_ERROR
        assert exc.value.data is None  # tracebacks always logged, never on the wire

    def test_method_not_found(self, server_with_registry):
        with pytest.raises(RemoteJSONRPCError) as exc:
            server_with_registry.call("nope", {})
        assert exc.value.code == JSONRPCErrorCode.METHOD_NOT_FOUND


class TestSubclassMapping:
    """Subclasses of registered exceptions must route through the dispatch table."""

    def test_subclass_of_ida_error_maps_to_ida_error_code(self):
        class _SpecialIDAError(IDAError):
            pass

        registry = RPCRegistry()

        def custom() -> None:
            raise _SpecialIDAError("subclass kaboom")

        registry.register(custom)
        with _serve(registry) as server:
            assert server.bound_port is not None
            client = IDARpcClient(host="127.0.0.1", port=server.bound_port, timeout=5)
            with pytest.raises(RemoteJSONRPCError) as exc:
                client.call("custom", {})
            assert exc.value.code == JSONRPCErrorCode.IDA_ERROR
            assert exc.value.message == "subclass kaboom"


class TestContentLengthDefenses:
    """Defenses against malformed / hostile ``Content-Length`` headers.

    The server listens on localhost only, but a buggy or malicious client must
    not be able to make us allocate unbounded memory or trip ``int(...)`` on
    a non-numeric header. Each case here drives the explicit branches in
    :meth:`JSONRPCRequestHandler.do_POST`.
    """

    @staticmethod
    def _post_raw(port: int, headers: dict[str, str], body: bytes) -> tuple[int, dict]:
        """POST *body* with caller-controlled headers; return (status, json_body).

        Bypasses :class:`IDARpcClient` so we can inject the broken headers a
        well-formed client would never produce.
        """
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request("POST", HTTP_ENDPOINT_PATH, body, headers)
            resp = conn.getresponse()
            payload = json.loads(resp.read().decode("utf-8"))
            return resp.status, payload
        finally:
            conn.close()

    def test_non_numeric_content_length_rejected(self, server_with_registry):
        status, payload = self._post_raw(
            server_with_registry.port,
            {"Content-Type": "application/json", "Content-Length": "abc"},
            b'{"jsonrpc":"2.0","method":"echo","params":{"message":"x"},"id":1}',
        )
        assert status == 200
        assert payload["error"]["code"] == JSONRPCErrorCode.INVALID_REQUEST
        assert "Content-Length" in payload["error"]["message"]

    def test_oversized_content_length_rejected(self, server_with_registry):
        # Send a small actual body but advertise a body that exceeds the cap.
        # The server must refuse before reading anything from the socket.
        oversized = 64 * 1024 * 1024  # > _MAX_REQUEST_BYTES (32 MiB)
        status, payload = self._post_raw(
            server_with_registry.port,
            {"Content-Type": "application/json", "Content-Length": str(oversized)},
            b"",
        )
        assert status == 200
        assert payload["error"]["code"] == JSONRPCErrorCode.INVALID_REQUEST
        assert "too large" in payload["error"]["message"]

    def test_negative_content_length_rejected(self, server_with_registry):
        status, payload = self._post_raw(
            server_with_registry.port,
            {"Content-Type": "application/json", "Content-Length": "-1"},
            b"",
        )
        assert status == 200
        assert payload["error"]["code"] == JSONRPCErrorCode.PARSE_ERROR


def test_double_bind_is_idempotent():
    server = Server(host="127.0.0.1", port=0)
    server.bind()
    try:
        first_port = server.bound_port
        server.bind()  # should be a no-op
        assert server.bound_port == first_port
        assert server.running
    finally:
        server.stop()


def test_bound_port_is_none_when_stopped():
    server = Server(host="127.0.0.1", port=0)
    assert server.bound_port is None
    server.bind()
    assert server.bound_port is not None
    server.stop()
    assert server.bound_port is None


@pytest.mark.skipif(
    sys.platform == "win32",
    reason=(
        "Windows AF_INET sockets default to non-exclusive binding "
        "(SO_REUSEADDR semantics differ from POSIX); two servers can bind "
        "the same port without raising. The path is still exercised on "
        "POSIX where it matters."
    ),
)
def test_bind_failure_raises_on_port_collision():
    """Binding two servers to the same port surfaces OSError to the caller."""
    server_a = Server(host="127.0.0.1", port=0)
    server_a.bind()
    try:
        assert server_a.bound_port is not None
        server_b = Server(host="127.0.0.1", port=server_a.bound_port)
        with pytest.raises(OSError):
            server_b.bind()
    finally:
        server_a.stop()


class TestForegroundLoop:
    """Coverage for the headless ``serve_in_current_thread`` execution path.

    ``idat -A`` has no Qt event loop, so a worker-thread server would
    deadlock the moment any ``@idaread`` handler trampolined through
    ``execute_sync`` (the main thread, blocked in ``serve_forever``,
    would never service the queued callback). The foreground server
    runs on the IDA main thread itself, processing each request inline.
    These tests exercise the contract that mode relies on: bind-then-
    serve, in-thread dispatch, and concurrent-safe ``stop`` from a
    watcher thread.
    """

    def test_handler_runs_on_serve_thread(self):
        """Handlers execute on the *thread that called serve*.

        That property is what lets ``execute_sync`` short-circuit:
        the same thread runs both ``serve_forever`` and the handler,
        so ``@idaread`` / ``@idawrite`` decorators do not need to
        post into a Qt event loop.
        """
        registry = RPCRegistry()

        def whoami() -> int:
            return threading.get_ident()

        registry.register(whoami)

        server = Server(host="127.0.0.1", port=0, registry=registry)
        server.bind()
        assert server.bound_port is not None
        port = server.bound_port

        serve_tid: list[int] = []

        def serve() -> None:
            serve_tid.append(threading.get_ident())
            server.serve_in_current_thread()

        serve_thread = threading.Thread(target=serve, daemon=True)
        serve_thread.start()
        try:
            client = IDARpcClient(host="127.0.0.1", port=port, timeout=5)
            handler_tid = client.call("whoami", {})
            assert handler_tid == serve_tid[0]
        finally:
            server.stop()
            serve_thread.join(timeout=3)

    def test_stop_from_other_thread_wakes_serve(self):
        server = Server(host="127.0.0.1", port=0)
        server.bind()
        serve_thread = threading.Thread(target=server.serve_in_current_thread, daemon=True)
        serve_thread.start()
        # Give the loop a moment to enter ``serve_forever``; without this,
        # racing ``stop()`` against an un-entered loop is what
        # ``shutdown()`` cannot recover from.
        time.sleep(0.1)
        server.stop()
        serve_thread.join(timeout=3)
        assert not serve_thread.is_alive()

    def test_concurrent_stop_is_idempotent(self):
        """Both the watcher and the main thread call ``stop`` -- no double close."""
        server = Server(host="127.0.0.1", port=0)
        server.bind()
        serve_thread = threading.Thread(target=server.serve_in_current_thread, daemon=True)
        serve_thread.start()
        time.sleep(0.1)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(server.stop) for _ in range(4)]
            for f in futures:
                f.result(timeout=3)
        serve_thread.join(timeout=3)
        assert not serve_thread.is_alive()
        assert server.bound_port is None
