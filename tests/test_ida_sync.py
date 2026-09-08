"""Tests for ``plugin.ida_sync._sync_call`` semantics.

The real ``idaapi.execute_sync`` is replaced with a synchronous stub that
just calls the runner inline -- enough to exercise the result handling and
re-entrancy guard.
"""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin import ida_sync
from ida_pro_mcp.plugin.errors import IDASyncError


@pytest.fixture(autouse=True)
def _inline_execute_sync(monkeypatch):
    """Run the runner immediately on the calling thread for testability."""
    def _inline(runner, _safety):
        runner()
        return 1

    monkeypatch.setattr(ida_sync.idaapi, "execute_sync", _inline)
    # Clear any ContextVar state leaked from previous tests.
    token = ida_sync._active_call.set(None)
    yield
    ida_sync._active_call.reset(token)


class TestSafetyGuard:
    def test_unsupported_safety_raises(self):
        def _f() -> int:
            return 0

        with pytest.raises(IDASyncError, match="Invalid safety mode"):
            ida_sync._sync_call(_f, ida_sync.IDASafety.SAFE_NONE)


class TestReturnSemantics:
    def test_returns_value(self):
        assert ida_sync._sync_call(lambda: 42, ida_sync.IDASafety.SAFE_READ) == 42

    def test_returns_none_value_unchanged(self):
        # Critical: the previous Queue-based implementation could not
        # distinguish a normal ``None`` return from "no value yet". The new
        # outcome envelope makes the distinction crisp.
        assert ida_sync._sync_call(lambda: None, ida_sync.IDASafety.SAFE_READ) is None

    def test_propagates_exception(self):
        def _f() -> int:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            ida_sync._sync_call(_f, ida_sync.IDASafety.SAFE_READ)

    def test_exception_value_is_returned_not_raised(self):
        # ``ValueError`` *returned* (not raised) must come back unchanged --
        # the old isinstance(result, Exception) sniff was a foot-gun here.
        sentinel = ValueError("just a value")
        result = ida_sync._sync_call(lambda: sentinel, ida_sync.IDASafety.SAFE_READ)
        assert result is sentinel


class TestCallableNaming:
    """``_sync_call`` must surface a sensible name for its argument.

    The decorator path wraps each handler in ``functools.partial`` to
    capture ``args`` / ``kwargs``; ``partial`` objects have no
    ``__name__`` attribute, so an earlier implementation that read
    ``func.__name__`` directly raised ``AttributeError`` from inside
    the runner -- which surfaced as a generic JSON-RPC internal error
    on every tool call. ``_callable_name`` peels back partials to the
    real callable so error messages and the active-call ContextVar
    record the original function name.
    """

    def test_plain_function_name(self):
        def my_handler() -> int:
            return 0

        assert ida_sync._callable_name(my_handler) == "my_handler"

    def test_partial_unwraps_to_inner_name(self):
        import functools

        def my_handler(a, b) -> int:
            return a + b

        wrapped = functools.partial(my_handler, 1, 2)
        assert ida_sync._callable_name(wrapped) == "my_handler"

    def test_nested_partial_unwraps_fully(self):
        import functools

        def my_handler(a, b, c) -> int:
            return a + b + c

        wrapped = functools.partial(functools.partial(my_handler, 1), 2)
        assert ida_sync._callable_name(wrapped) == "my_handler"

    def test_partial_through_decorator_path(self):
        """The realistic call shape: a partial wrapping a real handler.

        The bug surfaced via ``idaread`` / ``idawrite`` decorators
        which always wrap the body in ``functools.partial`` -- this
        replays that exact shape end-to-end so a regression on the
        unwrapping helper would be caught.
        """
        @ida_sync.idaread
        def read_handler(arg: int) -> int:
            return arg * 2

        # Without the fix this raised
        # ``AttributeError: 'functools.partial' object has no attribute '__name__'``
        # from inside the runner, before the body even ran.
        assert read_handler(21) == 42


class TestNestingGuard:
    def test_nested_call_is_rejected(self):
        # Outer call holds the slot; the runner's inner call should refuse.
        def outer() -> int:
            ida_sync._sync_call(lambda: 1, ida_sync.IDASafety.SAFE_READ)
            return 0

        with pytest.raises(IDASyncError, match="Refusing to nest"):
            ida_sync._sync_call(outer, ida_sync.IDASafety.SAFE_READ)

    def test_active_slot_cleared_after_call(self):
        ida_sync._sync_call(lambda: 1, ida_sync.IDASafety.SAFE_READ)
        assert ida_sync._active_call.get() is None

    def test_active_slot_cleared_after_failure(self):
        def boom():
            raise RuntimeError("x")

        with pytest.raises(RuntimeError):
            ida_sync._sync_call(boom, ida_sync.IDASafety.SAFE_READ)
        assert ida_sync._active_call.get() is None

    def test_threads_have_independent_active_slots(self):
        # ``ContextVar`` decouples threads: a "stuck" outer call on one thread
        # must not leak into another thread's nesting check.
        import threading

        results: list[Exception | None] = []

        def hold_then_run() -> None:
            def outer() -> int:
                # Inside the runner the slot is set; spawn a sibling thread
                # which gets a fresh context and can take its own slot.
                worker_result: list[Exception | None] = []

                def child() -> None:
                    try:
                        ida_sync._sync_call(lambda: 1, ida_sync.IDASafety.SAFE_READ)
                        worker_result.append(None)
                    except Exception as exc:
                        worker_result.append(exc)

                t = threading.Thread(target=child)
                t.start()
                t.join()
                results.extend(worker_result)
                return 0

            ida_sync._sync_call(outer, ida_sync.IDASafety.SAFE_READ)

        hold_then_run()
        assert results == [None]
