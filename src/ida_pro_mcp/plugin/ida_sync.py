"""Helpers to run code on IDA's main thread safely.

IDA's SDK is not thread-safe: any call that touches the IDB must be marshalled
to the main UI thread via ``execute_sync``. ``idaread`` / ``idawrite`` decorate
RPC handlers so each invocation is dispatched with the appropriate safety
level.

Re-entrant sync calls (e.g. an ``@idawrite`` handler invoking another) would
deadlock or corrupt state, so we track the active call name and refuse a
nested entry. ``ContextVar`` is the right primitive here:

* it inherits across the call chain (the runner sees what the caller set);
* it has independent values per thread / asyncio task, so the check stays
  correct even if IDA's threading model changes in the future;
* setting it inside ``runner`` and resetting via ``Token`` guarantees the
  slot is cleared on every exit path.
"""
from __future__ import annotations

import contextvars
import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, TypeVar

import ida_kernwin
import idaapi

from .errors import IDASyncError

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


class IDASafety(IntEnum):
    """Safety modes accepted by ``idaapi.execute_sync``. Higher is safer."""
    SAFE_NONE = ida_kernwin.MFF_FAST
    SAFE_READ = ida_kernwin.MFF_READ
    SAFE_WRITE = ida_kernwin.MFF_WRITE


# Use the explicit generic form on the constructor so ``ContextVar(default=None)``
# isn't narrowed to ``ContextVar[None]`` by type checkers (which would forbid
# storing a string later).
_active_call: contextvars.ContextVar[str | None] = contextvars.ContextVar[str | None](
    "ida_pro_mcp.active_call", default=None,
)


@dataclass(slots=True)
class _Outcome:
    """Result envelope: exactly one of ``value`` / ``exc`` is meaningful.

    Using a sentinel object avoids the ``isinstance(result, Exception)`` smell
    where a normal return value happens to be an exception instance.
    """
    value: Any = None
    exc: BaseException | None = None


def _callable_name(func: Callable[..., Any]) -> str:
    """Return a human-readable name for *func* even when it's a ``partial``.

    ``functools.partial`` objects do not expose ``__name__`` (only the
    wrapped callable does, via ``func.func``), and falling through to
    ``getattr(func, "__name__", ...)`` would silently lose the original
    method name in our diagnostics. We dig through ``partial.func``
    until we reach a real callable, then fall back to ``repr`` so we
    never raise from inside the trampoline -- a missing name in a
    re-entrancy diagnostic must not crash the request.
    """
    target = func
    while isinstance(target, functools.partial):
        target = target.func
    name = getattr(target, "__name__", None)
    if name:
        return name
    qualname = getattr(target, "__qualname__", None)
    if qualname:
        return qualname
    return repr(target)


def _sync_call(func: Callable[[], Any], safety: IDASafety) -> Any:
    if safety not in (IDASafety.SAFE_READ, IDASafety.SAFE_WRITE):
        raise IDASyncError(f"Invalid safety mode {safety} for {_callable_name(func)}")

    outcome = _Outcome()
    func_name = _callable_name(func)

    def runner() -> int:
        # Detect re-entrant sync calls on the IDA UI thread (bug magnet: would
        # deadlock or corrupt state). The check runs *inside* the runner so it
        # observes the actual main-thread call stack. ``execute_sync`` is
        # synchronous, so ``outcome`` is fully populated before it returns and
        # we never need a thread-safe queue.
        active = _active_call.get()
        if active is not None:
            outcome.exc = IDASyncError(
                f"Refusing to nest sync call '{func_name}' inside '{active}'"
            )
            return 1
        token = _active_call.set(func_name)
        try:
            outcome.value = func()
        except BaseException as exc:
            # Re-raised on the caller thread; preserves KeyboardInterrupt etc.
            outcome.exc = exc
        finally:
            _active_call.reset(token)
        return 1

    idaapi.execute_sync(runner, safety)
    if outcome.exc is not None:
        raise outcome.exc
    return outcome.value


def idawrite(f: F) -> F:
    """Decorator: run *f* on the IDA main thread with write-safety."""
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _sync_call(functools.partial(f, *args, **kwargs), IDASafety.SAFE_WRITE)

    return wrapper  # type: ignore[return-value]


def idaread(f: F) -> F:
    """Decorator: run *f* on the IDA main thread with read-safety."""
    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return _sync_call(functools.partial(f, *args, **kwargs), IDASafety.SAFE_READ)

    return wrapper  # type: ignore[return-value]
