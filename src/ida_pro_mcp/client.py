"""HTTP / JSON-RPC client used by the MCP proxy server.

Lives at the package root rather than under :mod:`ida_pro_mcp.plugin` because
the plugin namespace conceptually represents code that runs *inside* IDA.
The client runs in the proxy process that talks to a running IDA instance
over a local socket.

Each :class:`IDARpcClient` instance targets *one* IDA process. The proxy's
session registry (see :mod:`.session_registry`) owns one client per live
session and looks up the right one based on the ``session`` parameter the
LLM passes to a tool call.
"""
from __future__ import annotations

import contextlib
import http.client
import itertools
import json
from typing import Any

from .plugin.constants import DEFAULT_HTTP_TIMEOUT_S, HTTP_ENDPOINT_PATH
from .plugin.errors import IDARpcTransportError
from .plugin.jsonrpc import make_request, parse_response


class IDARpcClient:
    """Thread-safe JSON-RPC client targeting one IDA plugin's HTTP server.

    Each ``call`` opens its own short-lived connection; ``itertools.count`` is
    atomic in CPython so the request id counter does not need an explicit lock.

    *host* and *port* are mandatory: every real call site (the session
    registry, every test, every embedder) already supplies both, and a
    ``host=DEFAULT_HOST, port=0`` default would silently target a port the
    kernel never assigns to a listener -- a crash-once footgun. Requiring
    them at construction means a typo fails at the call site instead.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        timeout: float = DEFAULT_HTTP_TIMEOUT_S,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._id_counter = itertools.count(1)

    def call(self, method: str, params: dict[str, Any]) -> Any:
        """Issue an RPC request and return the unwrapped result.

        Raises :class:`RemoteJSONRPCError` for server-reported errors and
        :class:`IDARpcTransportError` for everything else (HTTP, socket,
        decoding). Returns the literal ``result`` value from the server,
        including ``None``; LLM-friendly substitution happens one layer up
        in the FastMCP bridge.
        """
        request_id = next(self._id_counter)
        payload = json.dumps(make_request(method, params, request_id))

        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        except OSError as exc:
            raise IDARpcTransportError(f"Failed to connect to IDA RPC server: {exc}") from exc

        with contextlib.closing(conn):
            try:
                conn.request(
                    "POST", HTTP_ENDPOINT_PATH, payload, {"Content-Type": "application/json"}
                )
                response = conn.getresponse()
                body = response.read()
            except OSError as exc:
                raise IDARpcTransportError(f"IDA RPC request failed: {exc}") from exc

            if response.status != 200:
                raise IDARpcTransportError(
                    f"Unexpected HTTP {response.status} from IDA RPC server: {body[:200]!r}"
                )
            try:
                data = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise IDARpcTransportError(f"Malformed JSON response: {exc}") from exc

            return parse_response(data)
