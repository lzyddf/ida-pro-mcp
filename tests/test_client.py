"""Round-trip test for IDARpcClient against an in-memory HTTP server."""
from __future__ import annotations

import http.server
import json
import threading
from contextlib import contextmanager

import pytest

from ida_pro_mcp.client import IDARpcClient
from ida_pro_mcp.plugin.errors import JSONRPCErrorCode
from ida_pro_mcp.plugin.jsonrpc import (
    RemoteJSONRPCError,
    make_error_response,
    make_success_response,
)


class _FakeServer:
    def __init__(self, behavior):
        self.behavior = behavior  # callable: dict -> dict response payload
        self.calls: list[dict] = []
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), self._make_handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _make_handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):  # silence
                return

            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = json.loads(self.rfile.read(length))
                outer.calls.append(body)
                resp = json.dumps(outer.behavior(body)).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

        return Handler

    @property
    def port(self):
        return self.httpd.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()


@contextmanager
def _client_with(behavior):
    with _FakeServer(behavior) as server:
        client = IDARpcClient(host="127.0.0.1", port=server.port, timeout=2)
        yield client, server


class TestSuccessfulCall:
    def test_returns_result(self):
        with _client_with(lambda req: make_success_response({"v": 1}, request_id=req["id"])) as (client, _):
            assert client.call("foo", {"x": 1}) == {"v": 1}

    def test_sends_jsonrpc_envelope(self):
        with _client_with(lambda req: make_success_response("ok", request_id=req["id"])) as (client, server):
            client.call("greet", {"name": "world"})
        sent = server.calls[0]
        assert sent["method"] == "greet"
        assert sent["params"] == {"name": "world"}
        assert sent["jsonrpc"] == "2.0"
        assert isinstance(sent["id"], int)

    def test_request_ids_are_unique_and_increasing(self):
        with _client_with(lambda req: make_success_response("ok", request_id=req["id"])) as (client, server):
            client.call("a", {})
            client.call("b", {})
            client.call("c", {})
        ids = [call["id"] for call in server.calls]
        assert ids == sorted(set(ids))
        assert len(ids) == 3

    def test_none_result_passes_through(self):
        # The transport layer keeps the wire contract clean; ``None`` -> "success"
        # substitution lives in the FastMCP bridge (see test_tool_bridge).
        with _client_with(lambda req: make_success_response(None, request_id=req["id"])) as (client, _):
            assert client.call("foo", {}) is None


class TestErrorPropagation:
    def test_remote_error_raises_with_code(self):
        with _client_with(
            lambda req: make_error_response(
                JSONRPCErrorCode.IDA_ERROR, "no func", request_id=req["id"]
            )
        ) as (client, _):
            with pytest.raises(RemoteJSONRPCError) as exc:
                client.call("foo", {})
            assert exc.value.code == JSONRPCErrorCode.IDA_ERROR
            assert exc.value.message == "no func"
