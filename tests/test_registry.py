"""Tests for the JSON-RPC method registry and parameter coercion."""
from __future__ import annotations

from typing import Annotated, Literal, Union

import pytest

from ida_pro_mcp.plugin.doc import Doc
from ida_pro_mcp.plugin.errors import JSONRPCError, JSONRPCErrorCode
from ida_pro_mcp.plugin.registry import VOID_RESULT_MARKER, RPCRegistry

# Module-level alias so ``from __future__ import annotations`` doesn't trap
# the type inside a nested scope where ``get_type_hints`` cannot resolve it,
# and so ruff doesn't rewrite ``Union[..., None]`` into ``X | None`` (which
# would defeat the legacy-path coverage in ``TestNullableResult``).
_MaybeStr = Union[str, None]  # noqa: UP007 -- testing legacy Union path


def _fixture_registry() -> RPCRegistry:
    reg = RPCRegistry()

    def add(a: int, b: int) -> int:
        return a + b

    def greet(name: str, prefix: str = "hi") -> str:
        return f"{prefix} {name}"

    def maybe(x: int | None = None) -> str:
        return "none" if x is None else str(x)

    reg.register(add)
    reg.register(greet)
    reg.register(maybe)
    return reg


class TestRegister:
    def test_register_unique(self):
        reg = RPCRegistry()
        def f(): ...
        reg.register(f)
        assert "f" in reg.methods

    def test_register_duplicate_raises(self):
        reg = RPCRegistry()
        def f(): ...
        reg.register(f)
        with pytest.raises(ValueError, match="Duplicate"):
            reg.register(f)

    def test_rejects_var_positional(self):
        reg = RPCRegistry()
        def f(*args): ...
        with pytest.raises(ValueError, match="unsupported parameter"):
            reg.register(f)

    def test_rejects_var_keyword(self):
        reg = RPCRegistry()
        def f(**kwargs): ...
        with pytest.raises(ValueError, match="unsupported parameter"):
            reg.register(f)

    def test_rejects_positional_only(self):
        reg = RPCRegistry()

        def f(value, /): ...

        with pytest.raises(ValueError, match="use named parameters only"):
            reg.register(f)

    def test_rejects_unresolved_string_annotation(self):
        """Forward refs to types not visible at module scope must fail loudly.

        We hand-craft ``__annotations__`` (rather than declaring the function
        with a quoted annotation in source) so the test stays robust against
        ``ruff UP037`` auto-rewriting the quotes away.
        """
        reg = RPCRegistry()

        def f(x):
            return x

        f.__annotations__ = {"x": "TotallyUndefinedType"}

        with pytest.raises(ValueError, match="unresolved string annotation"):
            reg.register(f)


class TestUnsafe:
    def test_safe_methods_excludes_unsafe(self):
        reg = RPCRegistry()
        def safe_one(): ...
        def unsafe_one(): ...
        reg.register(safe_one)
        reg.register(unsafe_one)
        reg.mark_unsafe(unsafe_one)
        assert reg.safe_methods() == ["safe_one"]
        assert reg.is_unsafe("unsafe_one")
        assert not reg.is_unsafe("safe_one")


class TestDispatchKeyword:
    def test_call_with_kwargs(self):
        reg = _fixture_registry()
        assert reg.dispatch("greet", {"name": "world"}) == "hi world"

    def test_unknown_field_raises(self):
        reg = _fixture_registry()
        with pytest.raises(JSONRPCError, match="unexpected"):
            reg.dispatch("greet", {"name": "x", "bogus": 1})

    def test_missing_required_raises(self):
        reg = _fixture_registry()
        with pytest.raises(JSONRPCError, match="missing"):
            reg.dispatch("greet", {})


class TestCoercion:
    def test_string_coerced_to_int(self):
        reg = _fixture_registry()
        assert reg.dispatch("add", {"a": "10", "b": "20"}) == 30

    def test_invalid_int_raises_invalid_params(self):
        reg = _fixture_registry()
        with pytest.raises(JSONRPCError) as exc:
            reg.dispatch("add", {"a": "abc", "b": "1"})
        assert exc.value.code == JSONRPCErrorCode.INVALID_PARAMS

    def test_none_passed_through_for_optional(self):
        reg = _fixture_registry()
        assert reg.dispatch("maybe", {"x": None}) == "none"

    def test_optional_string_coerced(self):
        reg = _fixture_registry()
        assert reg.dispatch("maybe", {"x": "5"}) == "5"


class TestUnknownMethod:
    def test_method_not_found(self):
        reg = _fixture_registry()
        with pytest.raises(JSONRPCError) as exc:
            reg.dispatch("nope", {})
        assert exc.value.code == JSONRPCErrorCode.METHOD_NOT_FOUND


class TestVoidResultMarker:
    """``None`` returns are substituted by ``VOID_RESULT_MARKER`` at dispatch time."""

    def test_none_becomes_marker(self):
        reg = RPCRegistry()
        def void_op() -> None:
            return None
        reg.register(void_op)
        assert reg.dispatch("void_op", {}) == VOID_RESULT_MARKER

    def test_string_passes_through_untouched(self):
        reg = RPCRegistry()
        def hello() -> str:
            return "success"
        reg.register(hello)
        assert reg.dispatch("hello", {}) == "success"

    def test_zero_passes_through_untouched(self):
        """Falsy-but-not-None returns must reach the wire intact."""
        reg = RPCRegistry()
        def zero() -> int:
            return 0
        reg.register(zero)
        assert reg.dispatch("zero", {}) == 0

    def test_no_annotation_falls_back_to_marker(self):
        """Legacy / un-annotated tools keep the void substitution."""
        reg = RPCRegistry()
        def legacy():
            return None
        reg.register(legacy)
        assert reg.dispatch("legacy", {}) == VOID_RESULT_MARKER


class TestNullableResult:
    """Explicitly-nullable return types preserve ``None`` on the wire.

    Tools that legitimately may have nothing to report declare ``-> X | None``
    and rely on ``None`` being forwarded so the JSON Schema's ``Optional``
    shape lines up.
    """

    def test_pep604_optional_preserves_none(self):
        reg = RPCRegistry()
        def maybe_pep604() -> int | None:
            return None
        reg.register(maybe_pep604)
        assert reg.dispatch("maybe_pep604", {}) is None
        assert "maybe_pep604" in reg.nullable_result

    def test_pep604_optional_value_passes_through(self):
        reg = RPCRegistry()
        def maybe_pep604() -> int | None:
            return 7
        reg.register(maybe_pep604)
        assert reg.dispatch("maybe_pep604", {}) == 7

    def test_typing_union_preserves_none(self):
        """The legacy ``typing.Union[X, None]`` path is treated identically.

        We funnel the annotation through a module-level alias so ruff's
        UP007 / UP045 don't auto-rewrite the test fixture into PEP 604.
        """
        reg = RPCRegistry()
        def maybe_union() -> _MaybeStr:
            return None
        reg.register(maybe_union)
        assert reg.dispatch("maybe_union", {}) is None
        assert "maybe_union" in reg.nullable_result

    def test_bare_none_return_is_still_void(self):
        """``-> None`` is "this tool produces no value" -- keep the marker."""
        reg = RPCRegistry()
        def void_op() -> None:
            return None
        reg.register(void_op)
        assert "void_op" not in reg.nullable_result
        assert reg.dispatch("void_op", {}) == VOID_RESULT_MARKER


class TestInvalidRequest:
    @pytest.mark.parametrize("params", [[1, 2], "not a thing", None])
    def test_params_must_be_object(self, params):
        reg = _fixture_registry()
        with pytest.raises(JSONRPCError) as exc:
            reg.dispatch("add", params)
        assert exc.value.code == JSONRPCErrorCode.INVALID_REQUEST


# Module-level alias so ``from __future__ import annotations`` doesn't trap
# the type inside a nested scope where ``get_type_hints`` cannot resolve it.
_Mode = Literal["read", "write"]


def _op(mode: _Mode) -> str:
    return f"mode={mode}"


class TestLiteralValidation:
    """pydantic-backed validation must reject values outside ``Literal``."""

    def _make(self):
        reg = RPCRegistry()
        reg.register(_op)
        return reg

    def test_accepts_valid_literal(self):
        assert self._make().dispatch("_op", {"mode": "read"}) == "mode=read"

    def test_rejects_invalid_literal(self):
        with pytest.raises(JSONRPCError) as exc:
            self._make().dispatch("_op", {"mode": "delete"})
        assert exc.value.code == JSONRPCErrorCode.INVALID_PARAMS


def _page(offset: Annotated[int, Doc("Offset to start listing from", ge=0)]) -> int:
    return offset


class TestAnnotatedValidation:
    """``Annotated[..., Doc]`` constraints (e.g. ``ge=0``) are honoured."""

    def _make(self):
        reg = RPCRegistry()
        reg.register(_page)
        return reg

    def test_accepts_zero(self):
        assert self._make().dispatch("_page", {"offset": 0}) == 0

    def test_rejects_negative(self):
        with pytest.raises(JSONRPCError) as exc:
            self._make().dispatch("_page", {"offset": -1})
        assert exc.value.code == JSONRPCErrorCode.INVALID_PARAMS


def _sum_list(values: list[int]) -> int:
    return sum(values)


class TestComplexTypes:
    """List / dict parameter types must round-trip correctly."""

    def _make(self):
        reg = RPCRegistry()
        reg.register(_sum_list)
        return reg

    def test_accepts_int_list(self):
        assert self._make().dispatch("_sum_list", {"values": [1, 2, 3]}) == 6

    def test_coerces_string_elements(self):
        # pydantic lax mode handles "1" -> 1.
        assert self._make().dispatch("_sum_list", {"values": ["1", "2"]}) == 3

    def test_rejects_non_list(self):
        with pytest.raises(JSONRPCError) as exc:
            self._make().dispatch("_sum_list", {"values": "nope"})
        assert exc.value.code == JSONRPCErrorCode.INVALID_PARAMS
