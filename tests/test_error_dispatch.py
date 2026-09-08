"""Tests for the error-class -> JSON-RPC code dispatch table."""
from __future__ import annotations

from ida_pro_mcp.plugin.errors import (
    EXCEPTION_TO_CODE,
    IDAError,
    JSONRPCErrorCode,
    code_for_exception,
    exception_classes,
)


class TestExceptionToCode:
    def test_ida_error_maps_to_ida_error_code(self):
        assert code_for_exception(IDAError("boom")) == JSONRPCErrorCode.IDA_ERROR

    def test_subclass_routes_to_parent_code(self):
        class _Specialised(IDAError):
            pass

        assert code_for_exception(_Specialised("boom")) == JSONRPCErrorCode.IDA_ERROR

    def test_unknown_exception_falls_back_to_internal(self):
        assert code_for_exception(RuntimeError("?")) == JSONRPCErrorCode.INTERNAL_ERROR

    def test_exception_classes_includes_ida_error(self):
        assert IDAError in exception_classes()

    def test_table_is_a_sequence_of_pairs(self):
        # Sanity-check the public surface stays a sequence of (cls, code) pairs.
        assert all(isinstance(cls, type) for cls, _ in EXCEPTION_TO_CODE)
        assert all(isinstance(code, JSONRPCErrorCode) for _, code in EXCEPTION_TO_CODE)
