"""Registry of cache invalidation hooks.

Helpers across the plugin keep per-IDB caches (e.g. demangled-name lookup).
When IDA closes / reopens the IDB or a name changes, every cache must be
flushed. Using a tiny registry instead of hard-coded calls means new caches
only need to register themselves; consumers (``idb_hooks``) keep one entry
point: :func:`invalidate_all`.
"""
from __future__ import annotations

import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)

Invalidator = Callable[[], None]
_invalidators: list[Invalidator] = []


def register_invalidator(func: Invalidator) -> Invalidator:
    """Register *func* to run on every :func:`invalidate_all` call.

    Returns the function unchanged so it can be used as a decorator.
    """
    _invalidators.append(func)
    return func


def invalidate_all() -> None:
    """Run every registered invalidator. Failures are logged, not propagated."""
    for func in _invalidators:
        try:
            func()
        except Exception:
            logger.exception("cache invalidator %s raised", func)
