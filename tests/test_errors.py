"""Tests for the error types and JSON-RPC error code enum."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin.errors import (
    IDAError,
    IDAErrorKind,
    IDARpcTransportError,
    JSONRPCError,
    JSONRPCErrorCode,
    ensure_ok,
)


class TestJSONRPCErrorCode:
    def test_int_compatibility(self):
        # IntEnum members compare equal to their underlying int.
        assert JSONRPCErrorCode.IDA_ERROR == -32000
        assert JSONRPCErrorCode.PARSE_ERROR == -32700

    def test_distinct_values(self):
        values = {member.value for member in JSONRPCErrorCode}
        assert len(values) == len(list(JSONRPCErrorCode))


class TestJSONRPCError:
    def test_carries_code_and_message(self):
        err = JSONRPCError(JSONRPCErrorCode.INVALID_PARAMS, "bad", data="ctx")
        assert err.code == int(JSONRPCErrorCode.INVALID_PARAMS)
        assert err.message == "bad"
        assert err.data == "ctx"

    def test_int_code_argument_works(self):
        err = JSONRPCError(-32000, "boom")
        assert err.code == -32000


class TestIDAError:
    def test_message_attribute(self):
        err = IDAError("nope")
        assert err.message == "nope"
        assert str(err) == "nope"

    def test_default_kind_is_unknown(self):
        # Backward compatibility: existing ``raise IDAError("...")`` callers
        # must keep working without specifying a kind.
        err = IDAError("nope")
        assert err.kind is IDAErrorKind.UNKNOWN

    def test_kind_round_trips(self):
        err = IDAError("missing", IDAErrorKind.NOT_FOUND)
        assert err.kind is IDAErrorKind.NOT_FOUND
        assert err.kind.value == "not_found"


class TestTransportError:
    def test_is_runtime_error(self):
        err = IDARpcTransportError("connection refused")
        assert isinstance(err, RuntimeError)
        assert str(err) == "connection refused"


class TestEnsureOk:
    def test_truthy_passes(self):
        # Returns ``None`` and does not raise for any truthy value.
        ensure_ok(True, "should not raise")
        ensure_ok(1, "should not raise")
        ensure_ok([0], "should not raise")
        ensure_ok("hi", "should not raise")

    def test_falsy_raises_default_kind(self):
        with pytest.raises(IDAError) as exc:
            ensure_ok(False, "boom")
        assert exc.value.message == "boom"
        assert exc.value.kind is IDAErrorKind.OPERATION_FAILED

    def test_explicit_kind_round_trips(self):
        with pytest.raises(IDAError) as exc:
            ensure_ok(0, "missing", IDAErrorKind.NOT_FOUND)
        assert exc.value.kind is IDAErrorKind.NOT_FOUND

    def test_none_is_falsy(self):
        with pytest.raises(IDAError):
            ensure_ok(None, "nope")
