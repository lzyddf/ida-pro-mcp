"""Explicit loader for IDA RPC tool modules.

Tool modules register functions through decorators, but discovery happens only
when :func:`load_tools` is called. This keeps imports of shared protocol
modules lightweight while retaining the single registry used by both proxy
schema generation and the in-IDA dispatcher.
"""
from __future__ import annotations

import importlib
import logging
import pkgutil

from .. import _ida_stub

logger = logging.getLogger(__name__)

_MIN_TOOL_MODULES = 10
_loaded: tuple[str, ...] | None = None
_using_stubs: bool | None = None


def load_tools() -> tuple[str, ...]:
    """Discover and import every public tool module exactly once."""
    global _loaded, _using_stubs
    if _loaded is not None:
        return _loaded

    _using_stubs = _ida_stub.install_if_missing()
    loaded: list[str] = []
    for module_info in pkgutil.iter_modules(__path__):
        if module_info.name.startswith("_"):
            continue
        importlib.import_module(f"{__name__}.{module_info.name}")
        loaded.append(module_info.name)

    _loaded = tuple(loaded)
    logger.info("loaded %d tool modules: %s", len(_loaded), ", ".join(sorted(_loaded)))
    if len(_loaded) < _MIN_TOOL_MODULES:
        logger.warning(
            "only %d tool modules discovered (expected >= %d) -- packaging may be broken",
            len(_loaded),
            _MIN_TOOL_MODULES,
        )
    return _loaded


def using_stubs() -> bool | None:
    """Return whether the last load installed SDK stubs, or ``None`` before loading."""
    return _using_stubs


__all__ = ["load_tools", "using_stubs"]
