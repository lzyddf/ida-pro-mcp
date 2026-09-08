"""IDB lifecycle hooks: keep helper-level caches honest.

When IDA opens a different database, renames a function, or closes the
current IDB, any per-IDB cache holds stale data. The plugin's caches
register themselves with :mod:`plugin.caches`; we install one ``IDB_Hooks``
listener that calls :func:`invalidate_all` on every relevant event.

Subclassing ``ida_idp.IDB_Hooks`` must happen at runtime: constructing
:class:`_Listener` *outside* IDA would touch SWIG and fail. We therefore
lazily build it inside :func:`install`. See :mod:`._ida_stub` for the
project-wide "lazy SWIG subclass" convention this follows.
"""
from __future__ import annotations

import logging

from .caches import invalidate_all

logger = logging.getLogger(__name__)

_installed_hook: object | None = None


def install() -> None:
    """Install IDB hooks. Idempotent: safe to call from ``Server.start``."""
    global _installed_hook
    if _installed_hook is not None:
        return

    import ida_idp

    class _Listener(ida_idp.IDB_Hooks):  # type: ignore[misc, valid-type]
        def closebase(self) -> int:
            invalidate_all()
            return 0

        def renamed(self, ea: int, new_name: str, local_name: bool) -> int:
            invalidate_all()
            return 0

    hook = _Listener()
    if not hook.hook():
        logger.warning("Failed to install IDB cache-invalidation hooks")
        return
    _installed_hook = hook


def uninstall() -> None:
    global _installed_hook
    if _installed_hook is None:
        return
    try:
        _installed_hook.unhook()
    finally:
        _installed_hook = None
