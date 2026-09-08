"""Tests for the ``Doc`` -> ``pydantic.Field`` schema translation.

IDA-side signatures carry :class:`~ida_pro_mcp.plugin.doc.Doc`; FastMCP only
understands pydantic fields. These tests pin the bridge that keeps parameter
descriptions and numeric bounds visible in ``tools/list``.
"""
from __future__ import annotations

import inspect
from typing import Annotated, Any, get_args

import pytest
from annotated_types import Ge, Gt
from pydantic.fields import FieldInfo

from ida_pro_mcp._schema import apply_param_docs, translate_annotation, translate_signature
from ida_pro_mcp.plugin._typing import resolved_signature
from ida_pro_mcp.plugin.doc import Doc


def _field_metadata(annotation: Any) -> FieldInfo:
    """Return the first :class:`FieldInfo` inside *annotation*'s metadata."""
    for item in get_args(annotation)[1:]:
        if isinstance(item, FieldInfo):
            return item
    raise AssertionError(f"no FieldInfo in {annotation!r}")


class TestTranslateAnnotation:
    def test_doc_becomes_field_with_description(self):
        translated = translate_annotation(Annotated[int, Doc("the offset", ge=0)])
        assert _field_metadata(translated).description == "the offset"

    def test_ge_becomes_annotated_types_constraint(self):
        translated = translate_annotation(Annotated[int, Doc("x", ge=0)])
        assert Ge(0) in _field_metadata(translated).metadata

    def test_gt_becomes_annotated_types_constraint(self):
        translated = translate_annotation(Annotated[int, Doc("x", gt=0)])
        assert Gt(0) in _field_metadata(translated).metadata

    def test_base_type_is_preserved(self):
        translated = translate_annotation(Annotated[int, Doc("x", ge=0)])
        assert get_args(translated)[0] is int

    def test_plain_annotation_is_untouched(self):
        assert translate_annotation(int) is int
        assert translate_annotation(str | None) == str | None

    def test_absent_bounds_produce_no_constraints(self):
        translated = translate_annotation(Annotated[str, Doc("just text")])
        assert list(_field_metadata(translated).metadata) == []


class TestApplyParamDocs:
    def test_convert_number_description_survives(self):
        from ida_pro_mcp.number_conversion import convert_number

        apply_param_docs(convert_number)
        sig = inspect.signature(convert_number)
        field = _field_metadata(sig.parameters["text"].annotation)
        assert field.description.startswith("Number to convert")

    def test_convert_number_gt_bound_survives(self):
        """``size`` is ``int | None`` carrying ``gt=0`` -- the nested case."""
        from ida_pro_mcp.number_conversion import convert_number

        apply_param_docs(convert_number)
        sig = inspect.signature(convert_number)
        assert Gt(0) in _field_metadata(sig.parameters["size"].annotation).metadata

    def test_returns_the_same_function(self):
        def _op(value: Annotated[int, Doc("x", ge=0)]) -> int:
            return value

        assert apply_param_docs(_op) is _op


class TestTranslateSignature:
    def test_return_annotation_is_translated(self):
        def _op() -> Annotated[str, Doc("result")]:
            return "x"

        sig, hints = resolved_signature(_op)
        translated = translate_signature(sig, hints)
        assert _field_metadata(translated.return_annotation).description == "result"

    def test_parameters_without_metadata_are_preserved(self):
        def _op(name: str, count: int = 1) -> str:
            return name

        sig, hints = resolved_signature(_op)
        translated = translate_signature(sig, hints)
        assert translated.parameters["name"].annotation is str
        assert translated.parameters["count"].annotation is int


class TestProxySchema:
    """The RPC proxy path must expose the same metadata as local tools."""

    @pytest.fixture()
    def registry(self):
        from ida_pro_mcp.plugin.registry import RPCRegistry
        from ida_pro_mcp.plugin.tools import load_tools

        load_tools()
        return RPCRegistry()

    def test_proxy_signature_keeps_descriptions(self):
        from ida_pro_mcp._tool_bridge import _build_proxy
        from ida_pro_mcp.plugin.registry import rpc_registry

        original = rpc_registry.methods["read_bytes"]
        proxy = _build_proxy("read_bytes", original, lambda *_: None)
        sig = inspect.signature(proxy)
        field = _field_metadata(sig.parameters["size"].annotation)
        assert field.description == "Number of bytes to read"
        assert Gt(0) in field.metadata

    def test_proxy_still_appends_the_session_parameter(self):
        from ida_pro_mcp._tool_bridge import _build_proxy
        from ida_pro_mcp.plugin.registry import rpc_registry

        original = rpc_registry.methods["read_bytes"]
        proxy = _build_proxy("read_bytes", original, lambda *_: None)
        params = list(inspect.signature(proxy).parameters)
        assert params[-1] == "session"
