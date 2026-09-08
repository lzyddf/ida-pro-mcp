"""Tests for the stdlib coercion engine, including parity with pydantic.

The IDA side converts JSON-RPC arguments with :mod:`ida_pro_mcp.plugin.coerce`
instead of pydantic, because a compiled extension cannot be shared between the
proxy interpreter and IDAPython. The parity tests below pin the two
implementations to the same observable behaviour for every shape the tool
signatures actually use, so the swap stays invisible on the wire.
"""
from __future__ import annotations

from typing import Annotated, Literal

import pytest
from pydantic import Field, TypeAdapter, ValidationError

from ida_pro_mcp.plugin.coerce import CoercionError, coerce
from ida_pro_mcp.plugin.doc import Doc


class TestScalars:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [(31, 31), (True, 1), (31.0, 31), ("31", 31), (" 31 ", 31)],
    )
    def test_int_accepted(self, value, expected):
        assert coerce(value, int) == expected

    @pytest.mark.parametrize("value", ["0x1f", "abc", "", None, 31.5, [31]])
    def test_int_rejected(self, value):
        with pytest.raises(CoercionError):
            coerce(value, int)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, True),
            (False, False),
            (1, True),
            (0, False),
            (1.0, True),
            (0.0, False),
            ("true", True),
            ("FALSE", False),
            ("t", True),
            ("n", False),
            ("yes", True),
            ("off", False),
            ("On", True),
        ],
    )
    def test_bool_accepted(self, value, expected):
        assert coerce(value, bool) is expected

    @pytest.mark.parametrize("value", ["2", "", "maybe", 2, 2.0, None])
    def test_bool_rejected(self, value):
        with pytest.raises(CoercionError):
            coerce(value, bool)

    @pytest.mark.parametrize("value", ["x", "", "31"])
    def test_str_accepted(self, value):
        assert coerce(value, str) == value

    def test_str_accepts_bytes(self):
        assert coerce(b"abc", str) == "abc"

    @pytest.mark.parametrize("value", [31, 3.5, True, None, [1]])
    def test_str_rejected(self, value):
        with pytest.raises(CoercionError):
            coerce(value, str)

    @pytest.mark.parametrize(("value", "expected"), [("1.5", 1.5), (1, 1.0), ("1e3", 1000.0)])
    def test_float_accepted(self, value, expected):
        assert coerce(value, float) == expected

    @pytest.mark.parametrize("value", ["x", None, [1]])
    def test_float_rejected(self, value):
        with pytest.raises(CoercionError):
            coerce(value, float)


class TestComposites:
    def test_literal_accepts_member(self):
        annotation = Literal["byte", "word"]
        assert coerce("byte", annotation) == "byte"

    @pytest.mark.parametrize("value", ["dword", 1, None])
    def test_literal_rejects_non_member(self, value):
        with pytest.raises(CoercionError):
            coerce(value, Literal["byte", "word"])

    def test_optional_passes_none_through(self):
        assert coerce(None, int | None) is None

    def test_optional_coerces_when_present(self):
        assert coerce("5", int | None) == 5

    def test_optional_rejects_bad_value(self):
        with pytest.raises(CoercionError):
            coerce("x", int | None)

    def test_list_coerces_elements(self):
        assert coerce(["1", 2], list[int]) == [1, 2]

    @pytest.mark.parametrize("value", ["ab", 1, None])
    def test_list_rejects_non_list(self, value):
        with pytest.raises(CoercionError):
            coerce(value, list[str])

    @pytest.mark.parametrize("annotation", [None, object, str])
    def test_unknown_annotations_pass_through(self, annotation):
        assert coerce("anything", annotation) == "anything"


class TestBounds:
    def test_ge_accepts_boundary(self):
        assert coerce(0, Annotated[int, Doc("offset", ge=0)]) == 0

    def test_ge_rejects_below(self):
        with pytest.raises(CoercionError, match="greater than or equal to 0"):
            coerce(-1, Annotated[int, Doc("offset", ge=0)])

    def test_gt_rejects_boundary(self):
        with pytest.raises(CoercionError, match="greater than 0"):
            coerce(0, Annotated[int, Doc("size", gt=0)])

    def test_bounds_apply_after_coercion(self):
        assert coerce("5", Annotated[int, Doc("size", gt=0)]) == 5

    def test_bounds_ignored_for_non_numeric(self):
        assert coerce("x", Annotated[str, Doc("name", ge=0)]) == "x"


# --- parity with pydantic ----------------------------------------------------
#
# Each case pairs the same logical constraint expressed both ways. ``coerce``
# must agree with pydantic on accept/reject *and* on the converted value.

_PARITY_CASES: list[tuple[str, object, object, object]] = [
    # (label, base type, Doc kwargs, sample values)
    ("int", int, {}, [31, "31", " 31 ", 31.0, True, "0x1f", "abc", "", None, 31.5]),
    (
        "int ge=0",
        int,
        {"ge": 0},
        [0, 1, -1, "5", "-3"],
    ),
    (
        "int gt=0",
        int,
        {"gt": 0},
        [0, 1, -1, "5"],
    ),
    (
        "bool",
        bool,
        {},
        [True, False, 1, 0, 1.0, 0.0, 2, 2.0, "true", "FALSE", "t", "n", "yes", "off", "On", "2", "", None],
    ),
    ("str", str, {}, ["x", "", "31", 31, 3.5, True, None, b"abc"]),
    ("float", float, {}, ["1.5", 1, "1e3", "x", True, None]),
    ("literal", Literal["byte", "word"], {}, ["byte", "word", "dword", 1, None]),
    ("optional int", int | None, {}, [None, "5", 5, "x"]),
    ("optional str", str | None, {}, [None, "x", 5]),
    ("list[int]", list[int], {}, [["1", 2], [], "ab", [1.5]]),
]


def _pydantic_annotation(base, kwargs):
    if kwargs:
        return Annotated[base, Field(**kwargs)]
    return base


@pytest.mark.parametrize(
    ("label", "base", "doc_kwargs", "values"),
    _PARITY_CASES,
    ids=[case[0] for case in _PARITY_CASES],
)
def test_coerce_matches_pydantic(label, base, doc_kwargs, values):
    doc_annotation = (
        Annotated[base, Doc("parity", **doc_kwargs)] if doc_kwargs else base
    )
    adapter = TypeAdapter(_pydantic_annotation(base, doc_kwargs))

    for value in values:
        try:
            expected = adapter.validate_python(value)
        except ValidationError:
            with pytest.raises(CoercionError):
                coerce(value, doc_annotation)
        else:
            assert coerce(value, doc_annotation) == expected, f"{label}: {value!r}"
