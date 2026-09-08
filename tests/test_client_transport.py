"""Transport-failure tests for IDARpcClient.

Connection refusal, HTTP 5xx, malformed JSON and non-UTF8 payloads must all
raise :class:`IDARpcTransportError` rather than RuntimeError or
RemoteJSONRPCError so callers can branch on transport vs RPC failures.
"""
from __future__ import annotations

import http.server
import threading

import pytest

from ida_pro_mcp.client import IDARpcClient
from ida_pro_mcp.plugin.errors import IDARpcTransportError


class _BadServer:
    """Tiny HTTP server that always responds with ``status_code`` and ``body``."""

    def __init__(self, status_code: int, body: bytes, content_type: str = "application/json"):
        self.status_code = status_code
        self.body = body
        self.content_type = content_type
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), self._make_handler())
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _make_handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a, **_k):
                return

            def do_POST(self):
                _ = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(outer.status_code)
                self.send_header("Content-Type", outer.content_type)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

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


def test_connection_refused_raises_transport_error():
    # Port 1 is reserved and will refuse connections.
    client = IDARpcClient(host="127.0.0.1", port=1, timeout=2)
    with pytest.raises(IDARpcTransportError):
        client.call("foo", {})


def test_http_500_raises_transport_error():
    with _BadServer(500, b'{"error":"oops"}') as server:
        client = IDARpcClient(host="127.0.0.1", port=server.port, timeout=2)
        with pytest.raises(IDARpcTransportError):
            client.call("foo", {})


def test_malformed_json_raises_transport_error():
    with _BadServer(200, b"not json") as server:
        client = IDARpcClient(host="127.0.0.1", port=server.port, timeout=2)
        with pytest.raises(IDARpcTransportError):
            client.call("foo", {})


def test_non_utf8_body_raises_transport_error():
    with _BadServer(200, b"\xff\xfe") as server:
        client = IDARpcClient(host="127.0.0.1", port=server.port, timeout=2)
        with pytest.raises(IDARpcTransportError):
            client.call("foo", {})
