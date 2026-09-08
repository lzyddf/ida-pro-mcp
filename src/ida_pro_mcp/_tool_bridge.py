"""Bridge plugin tool definitions onto a FastMCP server.

Each plugin tool already declares its parameters with
``Annotated[T, pydantic.Field(description=...)]``, which FastMCP consumes
directly. The bridge therefore only needs to:

1. wrap each registered method with a thin proxy whose signature matches the
   original (so FastMCP can introspect parameter types and descriptions); and
2. forward every call into the in-IDA RPC server through *dispatch*, after
   the proxy has peeled off the optional ``session`` keyword used to route
   the call to the right IDA process.

In addition, a small set of *local tools* runs entirely in the proxy:

* ``check_connection`` — diagnoses transport health.
* ``list_ida_sessions`` — enumerates the currently running IDA processes
  so an LLM can pick the right ``session`` id for subsequent calls.

These cannot be registered on the in-IDA side because they need to introspect
*the proxy's* view of the world (the sidecar registry, transport).

The proxy carries an ``__signature__`` that mirrors the original tool's
parameter list (resolved through :func:`resolve_hints` so PEP 563 strings
become real types), with one extra keyword-only ``session`` parameter
appended at the end. FastMCP invokes proxies with kwargs after schema
validation, so the runtime wrapper deliberately accepts keyword arguments
only. ``functools.update_wrapper`` propagates ``__doc__`` / ``__module__`` /
``__qualname__`` / ``__wrapped__`` so debuggers and ``inspect.unwrap`` can
recover the underlying handler.
"""
from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ._schema import apply_param_docs, translate_signature
from .plugin._typing import resolved_signature
from .plugin.errors import IDARpcTransportError
from .plugin.jsonrpc import RemoteJSONRPCError
from .plugin.registry import RPCRegistry, rpc_registry
from .plugin.session import SessionInfo
from .session_registry import (
    SessionAmbiguousError,
    SessionNotFoundError,
    SessionResolutionError,
)
from .spawner import Spawner

logger = logging.getLogger(__name__)

# Dispatch shape: (method, params, session_id_or_None) -> result.
# Session resolution lives outside the bridge (in :mod:`.session_registry`)
# so the bridge stays a pure protocol shim and tests can substitute a
# trivial fake without standing up a real registry.
Dispatch = Callable[[str, dict[str, Any], str | None], Any]
SessionLister = Callable[[], list[SessionInfo]]
LocalToolBuilder = Callable[["Backend"], Callable[..., Any] | None]


class Backend:
    """Bundle of capabilities the local tool builders need.

    A tiny indirection over the callables we hand to local tools so each
    builder takes one obvious argument rather than positional kwargs.
    The ``spawner`` is optional so embedders that don't want AI-driven
    IDA spawning (e.g. CI smoke tests) can opt out -- the open/close
    builders simply skip registration.
    """

    __slots__ = ("dispatch", "list_sessions", "spawner")

    def __init__(
        self,
        *,
        dispatch: Dispatch,
        list_sessions: SessionLister,
        spawner: Spawner | None = None,
    ) -> None:
        self.dispatch = dispatch
        self.list_sessions = list_sessions
        self.spawner = spawner


# Annotated alias mirroring the style in :mod:`plugin.params`. Defined here
# (rather than in plugin.params) because it is a *proxy-side* concern -- the
# in-IDA tools never see this parameter.
SessionParam = Annotated[
    str | None,
    Field(
        default=None,
        description=(
            "Target IDA session id, e.g. from list_ida_sessions(). "
            "Omit when only one IDA Pro session is currently open; "
            "required when multiple are running."
        ),
    ),
]
_SESSION_PARAM_NAME = "session"


def build_check_connection(backend: Backend) -> Callable[[str | None], str]:
    """Build a ``check_connection`` tool bound to *backend*.

    Lives client-side rather than as a registered RPC method because its job
    is to *diagnose the transport* -- a registered method couldn't run at all
    when the transport is broken or no session is selected. The returned
    function reports four shapes of state:

    * No session running: instruct the agent to spawn one with ``open_file``.
    * Multiple sessions, none chosen: ask the LLM to pick one.
    * Chosen session not found: distinct message so the agent can re-list.
    * Healthy session: confirm the open file by querying ``get_metadata``.
    """
    def check_connection(session: str | None = None) -> str:
        try:
            metadata = backend.dispatch("get_metadata", {}, session)
        except SessionResolutionError as exc:
            return str(exc)
        except (RemoteJSONRPCError, IDARpcTransportError, OSError) as exc:
            return (
                "Failed to talk to the IDA Pro plugin "
                f"(session={session or 'auto'}): {exc}. "
                "Call open_file(path=...) to spawn a headless IDA, or "
                "list_ida_sessions() to inspect existing sidecars."
            )

        module = metadata.get("module") if isinstance(metadata, dict) else None
        return (
            f"Successfully connected to IDA Pro (open file: {module})"
            if module else
            "Successfully connected to IDA Pro"
        )

    return check_connection


def build_list_ida_sessions(backend: Backend) -> Callable[[], list[dict[str, Any]]]:
    """Build the ``list_ida_sessions`` enumerator tool.

    Returns a list of dicts (not :class:`SessionInfo`) because FastMCP
    schemas are JSON, and dicts are the obvious lingua franca. Empty list
    when nothing is running -- callers must handle that case explicitly
    rather than relying on an exception.
    """
    def list_ida_sessions() -> list[dict[str, Any]]:
        """List every IDA Pro session currently exposing the MCP plugin."""
        return [info.to_dict() for info in backend.list_sessions()]

    return list_ida_sessions


def build_convert_number(_backend: Backend) -> Callable[..., Any]:
    """Expose number conversion locally so it works without an IDA session."""
    from .number_conversion import convert_number

    return convert_number


def build_open_file(backend: Backend) -> Callable[..., dict[str, Any]] | None:
    """Build ``open_file`` if the *backend* has a spawner; else ``None``.

    Returning ``None`` means "skip registration"; the loop in
    :func:`register_local_tools` filters those out so no half-functional
    tool ever appears in ``tools/list``.
    """
    spawner = backend.spawner
    if spawner is None:
        return None

    def open_file(path: str) -> dict[str, Any]:
        """Spawn a headless IDA Pro on *path* and return the new session info.

        The proxy locates ``idat`` via the ``IDA_PRO_HOME`` environment
        variable (set on the machine running the proxy, **not** the MCP
        client); there is no per-call override.

        Parameters
        ----------
        path:
            Absolute path to a binary readable by IDA Pro.
        """
        return _open_result_payload(spawner.open(path))

    return open_file


def build_reanalyse_file(backend: Backend) -> Callable[[str], dict[str, Any]] | None:
    """Build the destructive fresh-analysis tool when a spawner is available."""
    spawner = backend.spawner
    if spawner is None:
        return None

    def reanalyse_file(path: str) -> dict[str, Any]:
        """Delete an existing IDA database for *path* and analyse it again.

        The operation is refused while the same binary has a live session.
        Existing ``.i64``/``.idb`` artifacts are permanently deleted, so this
        tool is available only when the proxy starts with ``--unsafe``.
        """
        return _open_result_payload(spawner.open(path, fresh=True))

    return reanalyse_file


def _open_result_payload(result: Any) -> dict[str, Any]:
    payload = result.session.to_dict()
    payload["log_file"] = result.log_file
    payload["reused"] = result.reused
    return payload


def _resolve_close_session(backend: Backend, requested: str | None) -> str:
    if requested is not None:
        return requested
    sessions = backend.list_sessions()
    if not sessions:
        raise SessionNotFoundError(None)
    if len(sessions) > 1:
        raise SessionAmbiguousError([item.session_id for item in sessions])
    return sessions[0].session_id


def build_close_file(backend: Backend) -> Callable[..., dict[str, Any]] | None:
    spawner = backend.spawner
    if spawner is None:
        return None

    def close_file(session: str | None = None) -> dict[str, Any]:
        """Stop the headless IDA identified by *session*.

        Omit *session* when exactly one IDA session is running.
        Returns ``graceful=True`` when the IDA exited on its own;
        ``False`` when we had to escalate to ``SIGKILL``.
        """
        session_id = _resolve_close_session(backend, session)
        graceful = spawner.close(session_id)
        return {"session": session_id, "graceful": graceful}

    return close_file


@dataclass(frozen=True, slots=True)
class LocalToolSpec:
    """Local tool builder plus its high-risk registration policy."""

    builder: LocalToolBuilder
    unsafe: bool = False


# Single source of truth for local (non-RPC) tools. Destructive local tools
# participate in the same ``--unsafe`` policy as IDA-side RPC tools.
LOCAL_TOOL_SPECS: tuple[LocalToolSpec, ...] = (
    LocalToolSpec(build_check_connection),
    LocalToolSpec(build_list_ida_sessions),
    LocalToolSpec(build_convert_number),
    LocalToolSpec(build_open_file),
    LocalToolSpec(build_close_file),
    LocalToolSpec(build_reanalyse_file, unsafe=True),
)


def _build_proxy(name: str, original: Callable[..., Any], dispatch: Dispatch) -> Callable[..., Any]:
    """Create a proxy that mirrors *original*'s signature and forwards calls.

    The proxy presents an ``__signature__`` identical to *original*'s (with
    PEP 563 string annotations resolved), plus one extra keyword-only
    ``session`` parameter at the very end so MCP clients can route the call
    to a specific IDA process. FastMCP always invokes proxies via keyword
    arguments after schema validation. Direct positional invocation is not a
    supported bridge API; keeping that compatibility path duplicated Python's
    own argument binding without serving an MCP caller.
    """
    new_sig, hints = resolved_signature(original, use_module_globals=True)
    # IDA-side signatures carry ``Doc`` metadata (dependency-free); FastMCP only
    # understands pydantic fields, so translate before exposing the schema.
    new_sig = translate_signature(new_sig, hints)
    session_param = inspect.Parameter(
        _SESSION_PARAM_NAME,
        inspect.Parameter.KEYWORD_ONLY,
        default=None,
        annotation=SessionParam,
    )
    routed_sig = new_sig.replace(
        parameters=[*new_sig.parameters.values(), session_param]
    )

    def proxy(**kwargs: Any) -> Any:
        session_id = kwargs.pop(_SESSION_PARAM_NAME, None)
        return dispatch(name, kwargs, session_id)

    functools.update_wrapper(proxy, original, updated=())
    proxy.__name__ = name
    proxy.__qualname__ = name
    proxy.__signature__ = routed_sig  # type: ignore[attr-defined]
    proxy.__annotations__ = {
        param.name: param.annotation
        for param in routed_sig.parameters.values()
        if param.annotation is not inspect.Parameter.empty
    }
    if routed_sig.return_annotation is not inspect.Signature.empty:
        proxy.__annotations__["return"] = routed_sig.return_annotation
    return proxy


def _selected_methods(
    registry: RPCRegistry, include_unsafe: bool
) -> Iterable[tuple[str, Callable[..., Any]]]:
    for name, func in registry.methods.items():
        if include_unsafe or not registry.is_unsafe(name):
            yield name, func


def register_remote_tools(
    mcp: FastMCP,
    *,
    dispatch: Dispatch,
    include_unsafe: bool,
    registry: RPCRegistry | None = None,
) -> list[str]:
    """Register every plugin tool on *mcp* as a proxy that forwards via *dispatch*.

    Returns the list of method names registered, useful for ``autoApprove``
    settings in MCP client configs. Logs a count so misconfigured environments
    (e.g. tools failing to import under stubs) surface immediately.

    Names are guaranteed unique by ``RPCRegistry.register`` (which rejects
    duplicates at decoration time) plus ``methods`` being a dict, so no
    runtime de-dup is needed here.
    """
    if registry is None:
        from .plugin.tools import load_tools

        load_tools()
        reg = rpc_registry
    else:
        reg = registry
    registered: list[str] = []
    for name, func in _selected_methods(reg, include_unsafe):
        mcp.tool(name=name)(_build_proxy(name, func, dispatch))
        registered.append(name)
    logger.info(
        "Registered %d tools (%s unsafe)",
        len(registered),
        "including" if include_unsafe else "excluding",
    )
    return registered


def register_local_tools(
    mcp: FastMCP,
    *,
    backend: Backend,
    include_unsafe: bool = False,
) -> list[str]:
    """Register the small set of locally-implemented (non-RPC) tools.

    Iterates :data:`LOCAL_TOOL_SPECS` so adding a new local tool is a
    single-edit change -- no separate name list to keep in sync. Builders
    that return ``None`` (e.g. open_file when no spawner is available)
    are skipped entirely so the resulting tool list is never partial.
    """
    names: list[str] = []
    for spec in LOCAL_TOOL_SPECS:
        if spec.unsafe and not include_unsafe:
            continue
        func = spec.builder(backend)
        if func is None:
            continue
        mcp.tool()(apply_param_docs(func))
        names.append(func.__name__)
    return names
