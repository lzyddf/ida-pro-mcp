"""Tests for the cache invalidation registry."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin import caches


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch):
    """Each test gets a fresh invalidator list."""
    monkeypatch.setattr(caches, "_invalidators", [])


class TestRegisterInvalidator:
    def test_returns_function_unchanged(self):
        def f() -> None: ...
        assert caches.register_invalidator(f) is f

    def test_callable_added_to_registry(self):
        def f() -> None: ...
        caches.register_invalidator(f)
        assert f in caches._invalidators


class TestInvalidateAll:
    def test_runs_every_registered_invalidator(self):
        called: list[str] = []
        caches.register_invalidator(lambda: called.append("a"))
        caches.register_invalidator(lambda: called.append("b"))
        caches.invalidate_all()
        assert called == ["a", "b"]

    def test_failure_does_not_stop_remaining(self):
        # If one invalidator misbehaves we must still run the others;
        # otherwise a buggy cache could leave the rest stale.
        called: list[str] = []

        def boom() -> None:
            raise RuntimeError("explode")

        caches.register_invalidator(boom)
        caches.register_invalidator(lambda: called.append("ok"))
        caches.invalidate_all()
        assert called == ["ok"]
