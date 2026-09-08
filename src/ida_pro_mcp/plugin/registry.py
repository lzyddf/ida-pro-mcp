"""Method registry and decorators for the JSON-RPC layer.

The registry is the single source of truth for "what RPC tools exist". The
HTTP dispatcher (:mod:`.http_server`) and the FastMCP proxy bridge
(:mod:`ida_pro_mcp._tool_bridge`) both consume it via the public attributes
and helpers exposed below.

Two registration paths exist:

* **Module-level decorators** (``@jsonrpc`` / ``@unsafe`` imported from this
  module): register on the shared :data:`rpc_registry` singleton. This is
  the default for in-tree tool modules and keeps definition sites short.
* **Instance methods** (``my_registry.register(func)`` /
  ``my_registry.mark_unsafe(func)``): register on a caller-controlled
  :class:`RPCRegistry`. Tests use this for isolation; embedders can use it
  to expose a *subset* of the tools.

The void-result substitution (turning ``None`` into ``{"ok": True}``) lives in
:meth:`RPCRegistry.dispatch` so every transport sees the same wire contract.
Tools whose return annotation explicitly allows ``None`` (``Optional[X]`` /
``X | None``) are exempt: ``None`` is a meaningful value for them and is
forwarded to the client unchanged so it round-trips through the JSON Schema.
"""
from __future__ import annotations

import inspect
import logging
import types
from collections.abc import Callable
from typing import Any, TypeVar, Union, get_args, get_origin

from ._typing import resolved_signature
from .coerce import CoercionError, coerce
from .errors import JSONRPCError, JSONRPCErrorCode

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

# Sentinel substituted in place of ``None`` results so LLM clients (which handle
# empty payloads poorly) always receive a visible response. We deliberately use
# a dict rather than the string ``"success"`` because some tools legitimately
# return strings starting with that word -- a structured marker is unambiguous
# to both the LLM and any client code branching on shape.
VOID_RESULT_MARKER: dict[str, bool] = {"ok": True}


# The private proxy-to-IDA protocol always sends a JSON object and dispatches
# with ``func(**kwargs)``. Positional-only and variadic parameters therefore
# have no valid wire representation and are rejected at registration time.
_ACCEPTED_PARAM_KINDS = frozenset({
    inspect.Parameter.POSITIONAL_OR_KEYWORD,
    inspect.Parameter.KEYWORD_ONLY,
})


def _annotation_allows_none(annotation: Any) -> bool:
    """Return True iff *annotation* declares ``None`` as a legal value.

    Handles both legacy ``typing.Optional[X]`` / ``typing.Union[X, None]`` and
    PEP 604 ``X | None`` shapes. A bare ``None`` / ``type(None)`` annotation
    counts (the function is declared to *only* return ``None``); the void
    marker still kicks in for those, but the dispatcher treats them as
    "explicitly nullable" so the caller's intent is preserved.
    """
    if annotation is None or annotation is type(None):
        return True
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        return type(None) in get_args(annotation)
    return False


class RPCRegistry:
    def __init__(self) -> None:
        self.methods: dict[str, Callable[..., Any]] = {}
        self.unsafe: set[str] = set()
        # Methods whose return annotation explicitly permits ``None`` -- their
        # ``None`` results bypass the void marker substitution in dispatch().
        self.nullable_result: set[str] = set()

    # --- Registration -------------------------------------------------------

    def register(self, func: F) -> F:
        """Register *func* as a JSON-RPC method on this registry.

        Validates two invariants up front so misuse surfaces at import time
        rather than on the first JSON-RPC call:

        * No ``*args`` / ``**kwargs`` -- the dispatcher builds a kwargs dict
          by parameter name, so variadic params would be silently dropped.
        * Every annotation must be resolvable now (PEP 563 strings included).
          A leftover string annotation later forces :func:`_validate` to
          silently skip type coercion, which masks bugs in tool authoring;
          we'd rather fail loudly here.
        """
        if func.__name__ in self.methods:
            raise ValueError(f"Duplicate RPC method: {func.__name__}")
        for param in inspect.signature(func).parameters.values():
            if param.kind not in _ACCEPTED_PARAM_KINDS:
                raise ValueError(
                    f"RPC method {func.__name__!r} has unsupported parameter "
                    f"{param.name!r} ({param.kind.description}); "
                    "use named parameters only"
                )

        sig, hints = resolved_signature(func)
        unresolved = [
            name
            for name, param in sig.parameters.items()
            if isinstance(hints.get(name, param.annotation), str)
        ]
        if unresolved:
            raise ValueError(
                f"RPC method {func.__name__!r} has unresolved string annotations "
                f"for parameter(s) {unresolved}; ensure the referenced types are "
                "importable at module scope (and not declared in a nested function)."
            )

        # ``Function | None`` etc. are valid wire values, not "void". Tagging
        # them here keeps the dispatcher branch-free at call time.
        if "return" in hints and _annotation_allows_none(hints["return"]):
            # ``-> None`` is the special-case void function: keep the marker
            # behaviour for those (the type system says no value is produced)
            # and only opt out for true unions like ``X | None``.
            origin = get_origin(hints["return"])
            if origin is Union or origin is types.UnionType:
                self.nullable_result.add(func.__name__)

        self.methods[func.__name__] = func
        return func

    def mark_unsafe(self, func: F) -> F:
        """Mark *func* as unsafe; hidden unless ``--unsafe`` is passed.

        Selection policy (apply consistently when adding new tools):

        * **Mark unsafe** when *any* of the following hold:
          - patches bytes / writes to the debuggee (``patch_bytes``,
            ``add_bpt``, ``start_process`` and friends);
          - changes a *type*, prototype, or local declaration -- these can
            silently break decompilation and are tedious to revert
            (``set_function_prototype``, ``set_local_variable_type``,
            ``set_global_variable_type``, ``declare_c_type``,
            ``set_stack_frame_variable_type``);
          - destroys structure (``delete_stack_frame_variable``,
            ``delete_*``) or creates a slot that may overwrite an existing
            one (``create_stack_frame_variable``);
          - controls the debugger lifecycle (``dbg_*`` tools).

        * **Leave safe** for cheap, easily-reversible writes:
          - rename operations (``rename_function``, ``rename_local_variable``,
            ``rename_global_variable``, ``rename_stack_frame_variable``) --
            calling rename again restores the prior name;
          - comments (``set_comment``) -- writing the empty string clears.

        Read-only tools never need this decorator.
        """
        self.unsafe.add(func.__name__)
        return func

    # --- Introspection ------------------------------------------------------

    def is_unsafe(self, name: str) -> bool:
        return name in self.unsafe

    def safe_methods(self) -> list[str]:
        return [name for name in self.methods if name not in self.unsafe]

    # --- Dispatch -----------------------------------------------------------

    def dispatch(self, method: str, params: Any) -> Any:
        """Dispatch *method* with *params*, substituting ``None`` returns.

        The void-marker substitution lives here (rather than in the FastMCP
        bridge) so every transport surfacing this registry sees the same wire
        contract: a successful call is *never* an empty payload -- *unless*
        the tool explicitly declared ``Optional[X]`` / ``X | None``, in which
        case ``None`` is a meaningful value and is forwarded as-is.
        """
        if method not in self.methods:
            raise JSONRPCError(JSONRPCErrorCode.METHOD_NOT_FOUND, f"Method '{method}' not found")

        func = self.methods[method]
        kwargs = self._build_kwargs(func, params)
        result = func(**kwargs)
        if result is None and method not in self.nullable_result:
            return VOID_RESULT_MARKER
        return result

    @staticmethod
    def _build_kwargs(func: Callable[..., Any], params: Any) -> dict[str, Any]:
        sig, hints = resolved_signature(func)
        hints.pop("return", None)

        accepted_params = [
            (name, p) for name, p in sig.parameters.items()
            if p.kind in _ACCEPTED_PARAM_KINDS
        ]
        param_names = [name for name, _ in accepted_params]
        required_names = {
            name for name, p in accepted_params if p.default is inspect.Parameter.empty
        }

        if isinstance(params, dict):
            extra = set(params.keys()) - set(param_names)
            missing = required_names - set(params.keys())
            if extra:
                raise JSONRPCError(
                    JSONRPCErrorCode.INVALID_PARAMS,
                    f"Invalid params: unexpected fields {sorted(extra)}",
                )
            if missing:
                raise JSONRPCError(
                    JSONRPCErrorCode.INVALID_PARAMS,
                    f"Invalid params: missing required fields {sorted(missing)}",
                )
            return {
                name: _validate(name, params[name], hints.get(name))
                for name in param_names
                if name in params
            }

        raise JSONRPCError(
            JSONRPCErrorCode.INVALID_REQUEST,
            "Invalid Request: params must be an object",
        )


def _validate(param_name: str, value: Any, annotation: Any) -> Any:
    """Validate / coerce *value* against the parameter's annotated type.

    Conversion is delegated to :func:`ida_pro_mcp.plugin.coerce`, which is pure
    stdlib: the IDA-side package must import cleanly under IDAPython whatever
    Python version IDA bundles, and a compiled dependency such as
    ``pydantic_core`` cannot satisfy that. ``str -> int`` coercion is enabled so
    JSON-RPC clients that send numbers as strings still work.

    Annotations that are missing, string-form (unresolved), or ``Any``/``object``
    pass through untouched.
    """
    if annotation is None or annotation is Any or annotation is object:
        return value
    if isinstance(annotation, str):
        # Defensive: ``register()`` rejects unresolved string annotations, so
        # this branch is unreachable in well-formed code. Keep it as a
        # fail-open safety net (legacy callers using ``RPCRegistry`` directly
        # without going through ``register()``) and warn loudly.
        logger.warning(
            "skipping validation for parameter %r: unresolved string annotation %r",
            param_name, annotation,
        )
        return value

    try:
        return coerce(value, annotation)
    except CoercionError as exc:
        raise JSONRPCError(
            JSONRPCErrorCode.INVALID_PARAMS,
            f"Invalid value for parameter '{param_name}': {exc}",
        ) from exc


# --- Default singleton + module-level decorators ----------------------------
#
# In-tree tool modules use ``@jsonrpc`` / ``@unsafe`` against this singleton
# for terseness. Tests / embedders that want isolation should construct their
# own :class:`RPCRegistry` and call ``registry.register(func)`` directly.

rpc_registry = RPCRegistry()


def jsonrpc(func: F) -> F:
    """Register *func* on the default :data:`rpc_registry`."""
    return rpc_registry.register(func)


def unsafe(func: F) -> F:
    """Mark *func* as unsafe on the default :data:`rpc_registry`.

    See :meth:`RPCRegistry.mark_unsafe` for the selection policy.
    """
    return rpc_registry.mark_unsafe(func)
