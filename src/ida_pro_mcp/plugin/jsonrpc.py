"""JSON-RPC 2.0 protocol primitives shared between client and server.

This module is the single source of truth for the wire format. Both the
in-IDA HTTP server (:mod:`ida_pro_mcp.plugin.http_server`) and the proxy-side
client (:mod:`ida_pro_mcp.client`) build / parse messages through these
helpers so the shape stays consistent and the JSON-RPC error code semantics
stay symmetric.

Specification: https://www.jsonrpc.org/specification
"""
from __future__ import annotations

from typing import Any, Final

from .errors import JSONRPCError, JSONRPCErrorCode

JSONRPC_VERSION: Final = "2.0"


def make_request(method: str, params: Any, request_id: int) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "method": method,
        "params": params,
        "id": request_id,
    }


def make_error_object(code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return error


def make_success_response(result: Any, request_id: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def make_error_response(
    code: int,
    message: str,
    *,
    request_id: Any = None,
    data: Any = None,
) -> dict[str, Any]:
    response: dict[str, Any] = {
        "jsonrpc": JSONRPC_VERSION,
        "error": make_error_object(code, message, data),
    }
    if request_id is not None:
        response["id"] = request_id
    return response


class RemoteJSONRPCError(RuntimeError):
    """Raised on the client side when the server returns a JSON-RPC error.

    Carries the structured ``code`` / ``message`` / ``data`` triplet so callers
    can branch on the JSON-RPC error code rather than parse a string.
    """

    def __init__(self, code: int, message: str, data: Any = None):
        rendered = f"JSON-RPC error {code}: {message}"
        if data is not None:
            rendered += f"\n{data}"
        super().__init__(rendered)
        self.code = code
        self.message = message
        self.data = data


def parse_response(payload: dict[str, Any]) -> Any:
    """Validate a JSON-RPC response payload and return its ``result``.

    Raises :class:`RemoteJSONRPCError` for server-reported errors and
    :class:`ValueError` for malformed envelopes.
    """
    if not isinstance(payload, dict):
        raise ValueError(f"JSON-RPC response is not an object: {type(payload).__name__}")
    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise ValueError(f"Unsupported JSON-RPC version: {payload.get('jsonrpc')!r}")
    if "error" in payload:
        err = payload["error"]
        if not isinstance(err, dict):
            raise ValueError("JSON-RPC error object must be a dict")
        raise RemoteJSONRPCError(
            code=int(err.get("code", JSONRPCErrorCode.INTERNAL_ERROR)),
            message=str(err.get("message", "")),
            data=err.get("data"),
        )
    if "result" not in payload:
        raise ValueError("JSON-RPC response missing both 'result' and 'error'")
    return payload["result"]


def validate_request_envelope(payload: Any) -> dict[str, Any]:
    """Validate a server-side request envelope; raises :class:`JSONRPCError` on failure."""
    if not isinstance(payload, dict):
        raise JSONRPCError(JSONRPCErrorCode.INVALID_REQUEST, "Invalid Request")
    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise JSONRPCError(JSONRPCErrorCode.INVALID_REQUEST, "Invalid JSON-RPC version")
    if "method" not in payload:
        raise JSONRPCError(JSONRPCErrorCode.INVALID_REQUEST, "Method not specified")
    return payload
