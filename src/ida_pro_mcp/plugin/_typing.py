"""Shared helpers around :func:`typing.get_type_hints`.

Both the in-IDA dispatcher (:mod:`ida_pro_mcp.plugin.registry`) and the
out-of-IDA FastMCP bridge (:mod:`ida_pro_mcp._tool_bridge`) need to resolve a
function's annotations into concrete types. They previously each implemented
their own variant with subtly different fallback behaviour. Centralising both
flavours here removes the drift risk.
"""
from __future__ import annotations

import importlib
import inspect
import logging
from collections.abc import Callable
from typing import Any, get_type_hints

logger = logging.getLogger(__name__)


def _module_globals(func: Callable[..., Any]) -> dict[str, Any]:
    """Return the defining module's globals, or an empty dict when missing."""
    module_name = getattr(func, "__module__", "")
    if not module_name:
        return {}
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return {}
    return dict(vars(module))


def resolve_hints(
    func: Callable[..., Any],
    *,
    include_extras: bool = True,
    use_module_globals: bool = False,
) -> dict[str, Any]:
    """Resolve *func*'s type hints, gracefully degrading on resolution errors.

    With ``from __future__ import annotations`` the runtime can fail to
    resolve names that are only visible in the defining module's scope (e.g.
    aliases declared in :mod:`ida_pro_mcp.plugin.params`). Two failure modes
    are handled:

    * If ``get_type_hints`` raises (typically :class:`NameError` from a
      forward reference declared in a nested scope), we fall back to
      :attr:`func.__annotations__` and skip any entries that are still
      strings.
    * Setting ``use_module_globals=True`` augments the lookup with the
      defining module's globals so module-level aliases resolve. Without it,
      ``typing.get_type_hints`` walks the standard scope chain.

    The ``return`` key is intentionally **not** stripped; callers that only
    care about parameter hints should pop it themselves.
    """
    globalns = _module_globals(func) if use_module_globals else None
    try:
        return get_type_hints(func, globalns=globalns, include_extras=include_extras)
    except Exception as exc:
        logger.debug("get_type_hints failed for %s: %s; falling back", func.__name__, exc)
        return {
            name: ann
            for name, ann in func.__annotations__.items()
            if not isinstance(ann, str)
        }


def resolved_signature(
    func: Callable[..., Any],
    *,
    use_module_globals: bool = False,
) -> tuple[inspect.Signature, dict[str, Any]]:
    """Return *func*'s :class:`inspect.Signature` with annotations resolved.

    Both the dispatcher and the FastMCP bridge need ``inspect.signature(func)``
    *and* the resolved type hints together. Doing it in two places risks them
    drifting apart (e.g. one uses ``use_module_globals=True``, the other
    doesn't). The returned signature has every parameter and the return
    annotation re-bound to the resolved hints, so callers can read
    ``sig.parameters[name].annotation`` directly without reaching back into
    the hints dict.
    """
    hints = resolve_hints(func, use_module_globals=use_module_globals)
    sig = inspect.signature(func)
    new_params = [
        param.replace(annotation=hints.get(name, param.annotation))
        for name, param in sig.parameters.items()
    ]
    return_annotation = hints.get("return", sig.return_annotation)
    return sig.replace(parameters=new_params, return_annotation=return_annotation), hints
