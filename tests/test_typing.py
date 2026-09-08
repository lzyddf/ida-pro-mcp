"""Tests for the shared type-hint resolver."""
from __future__ import annotations

from typing import Annotated

from ida_pro_mcp.plugin._typing import resolve_hints
from ida_pro_mcp.plugin.doc import Doc


def _public(name: str, age: int = 0) -> str:
    return f"{name}/{age}"


def _annotated(value: Annotated[int, Doc("a bounded integer", ge=0)]) -> int:
    return value


class TestResolveHints:
    def test_basic_resolution(self):
        hints = resolve_hints(_public)
        assert hints["name"] is str
        assert hints["age"] is int
        assert hints["return"] is str

    def test_includes_extras_for_annotated(self):
        hints = resolve_hints(_annotated)
        # Annotated metadata must come through when include_extras=True.
        ann = hints["value"]
        assert getattr(ann, "__origin__", None) is None or hasattr(ann, "__metadata__")
        # We rely on the metadata being present rather than the exact shape.
        assert hasattr(ann, "__metadata__")

    def test_skipped_extras_returns_bare_type(self):
        hints = resolve_hints(_annotated, include_extras=False)
        assert hints["value"] is int

    def test_module_globals_path_does_not_explode(self):
        # use_module_globals=True merges module globals; the call must succeed.
        hints = resolve_hints(_public, use_module_globals=True)
        assert hints["name"] is str

    def test_unresolvable_hints_fall_back(self):
        # The fallback path activates when ``get_type_hints`` raises. With
        # ``from __future__ import annotations`` every annotation is a string
        # at runtime, so we build the function dynamically (no PEP 563) to
        # keep one annotation pre-resolved while another is an unresolvable
        # forward reference.
        def broken() -> int: ...
        broken.__annotations__["return"] = int
        broken.__annotations__["x"] = "ThisDoesNotExist"
        hints = resolve_hints(broken)
        # The unresolvable string is dropped; the resolved one survives.
        assert "x" not in hints or not isinstance(hints["x"], str)
        assert hints.get("return") is int
