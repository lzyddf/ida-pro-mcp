"""Tests for the JSON-RPC protocol primitives."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin.errors import JSONRPCError, JSONRPCErrorCode
from ida_pro_mcp.plugin.jsonrpc import (
    JSONRPC_VERSION,
    RemoteJSONRPCError,
    make_error_response,
    make_request,
    make_success_response,
    parse_response,
    validate_request_envelope,
)


class TestMakeRequest:
    def test_basic_envelope(self):
        req = make_request("foo", {"x": 1}, 7)
        assert req == {"jsonrpc": JSONRPC_VERSION, "method": "foo", "params": {"x": 1}, "id": 7}


class TestMakeSuccessResponse:
    def test_round_trip(self):
        resp = make_success_response(42, request_id=3)
        assert parse_response(resp) == 42

    def test_none_result_preserved(self):
        resp = make_success_response(None, request_id=1)
        assert parse_response(resp) is None


class TestMakeErrorResponse:
    def test_includes_data_when_set(self):
        resp = make_error_response(-32000, "boom", request_id=9, data="trace")
        assert resp["error"] == {"code": -32000, "message": "boom", "data": "trace"}

    def test_omits_data_when_none(self):
        resp = make_error_response(-32000, "boom", request_id=9)
        assert "data" not in resp["error"]

    def test_omits_id_when_none(self):
        resp = make_error_response(-32700, "parse", request_id=None)
        assert "id" not in resp


class TestParseResponse:
    def test_raises_remote_error_with_code(self):
        resp = make_error_response(JSONRPCErrorCode.IDA_ERROR, "no func", request_id=1)
        with pytest.raises(RemoteJSONRPCError) as exc:
            parse_response(resp)
        assert exc.value.code == JSONRPCErrorCode.IDA_ERROR
        assert exc.value.message == "no func"

    def test_rejects_wrong_jsonrpc_version(self):
        with pytest.raises(ValueError, match="version"):
            parse_response({"jsonrpc": "1.0", "result": 1, "id": 1})

    def test_rejects_non_dict(self):
        with pytest.raises(ValueError):
            parse_response([1, 2, 3])  # type: ignore[arg-type]

    def test_rejects_missing_result_and_error(self):
        with pytest.raises(ValueError, match="missing"):
            parse_response({"jsonrpc": JSONRPC_VERSION, "id": 1})

    def test_rejects_non_dict_error_object(self):
        with pytest.raises(ValueError, match="dict"):
            parse_response({"jsonrpc": JSONRPC_VERSION, "id": 1, "error": "boom"})

    def test_tolerates_error_missing_code_and_message(self):
        # Defensively fall back to INTERNAL_ERROR + empty message rather than
        # crashing on a malformed server.
        with pytest.raises(RemoteJSONRPCError) as exc:
            parse_response({"jsonrpc": JSONRPC_VERSION, "id": 1, "error": {}})
        assert exc.value.code == JSONRPCErrorCode.INTERNAL_ERROR
        assert exc.value.message == ""


class TestValidateRequestEnvelope:
    def test_accepts_valid(self):
        env = validate_request_envelope({"jsonrpc": "2.0", "method": "x"})
        assert env["method"] == "x"

    def test_rejects_non_dict(self):
        with pytest.raises(JSONRPCError) as exc:
            validate_request_envelope("nope")
        assert exc.value.code == JSONRPCErrorCode.INVALID_REQUEST

    def test_rejects_missing_method(self):
        with pytest.raises(JSONRPCError):
            validate_request_envelope({"jsonrpc": "2.0"})

    def test_rejects_wrong_version(self):
        with pytest.raises(JSONRPCError):
            validate_request_envelope({"jsonrpc": "1.0", "method": "x"})
