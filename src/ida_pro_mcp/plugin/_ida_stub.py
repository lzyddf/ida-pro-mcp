"""Provide an importable stand-in for IDA's SDK modules outside IDA Pro.

When this package is imported from a regular Python interpreter (e.g. the
``ida-pro-mcp-headless`` console-script that proxies to a running IDA instance), the
``ida_*`` and ``idaapi`` C extensions are not available. We still want to
import the tool modules so that :func:`rpc_registry.methods` is fully
populated for schema generation; the function bodies are simply never executed
in this environment.

The stub is intentionally minimal:

* attributes resolve to a simple sentinel that returns ``0`` from ``__int__``
  and ``__index__`` (so ``range(MNG_NODEFINIT)``-style import-time evaluation
  still works), and self-propagates through bitwise ops;
* it does **not** support being subclassed -- import-time class definitions
  whose base lives in IDA's SDK must be wrapped in a function so the subclass
  is built lazily, never at module import time.

The "lazy SWIG subclass" convention
-----------------------------------

IDA's Python bindings are SWIG-wrapped C++. Subclassing a SWIG base class
(``ida_idp.IDB_Hooks``, ``ida_hexrays.user_lvar_modifier_t``, ...) at *module
import time* fails outside IDA -- :class:`_Stub.__mro_entries__` deliberately
rejects it so the mistake surfaces with a clear message rather than an
obscure metaclass failure.

The fix is to wrap the subclass declaration in a function so the class is
built only when the function is called (i.e. only inside IDA). Examples:

* :func:`ida_pro_mcp.plugin.idb_hooks.install` -- ``IDB_Hooks`` subclass for
  cache invalidation.
* :func:`ida_pro_mcp.plugin.tools.rename._build_lvar_type_modifier` --
  ``user_lvar_modifier_t`` subclass for local-variable retyping.
"""
from __future__ import annotations

import sys
import types
from collections.abc import Iterable

# Names that the plugin imports at module top level. Keep this list in sync
# with the ``import ida_*`` / ``import idaapi`` statements in the tool modules.
_STUB_MODULES: tuple[str, ...] = (
    "idaapi",
    "idautils",
    "idc",
    "ida_bytes",
    "ida_dbg",
    "ida_entry",
    "ida_frame",
    "ida_funcs",
    "ida_hexrays",
    "ida_ida",
    "ida_idaapi",
    "ida_idd",
    "ida_idp",
    "ida_kernwin",
    "ida_lines",
    "ida_name",
    "ida_nalt",
    "ida_segment",
    "ida_typeinf",
)


class _Stub:
    """Sentinel returned for any attribute lookup on a stub module.

    Implements the small surface area we genuinely need for import-time
    evaluation (``int(...)`` for ``range``, bitwise ``|`` for flag combinations,
    iteration for ``for x in stub``). Anything else is a programming error and
    raises a clear message.
    """

    __slots__ = ("_qualname",)

    def __init__(self, qualname: str):
        self._qualname = qualname

    def __call__(self, *_args, **_kwargs):
        raise RuntimeError(
            f"IDA SDK stub: cannot call '{self._qualname}' outside of IDA Pro"
        )

    def __getattr__(self, item: str) -> _Stub:
        return _Stub(f"{self._qualname}.{item}")

    def __int__(self) -> int:
        return 0

    def __index__(self) -> int:
        return 0

    def __iter__(self):
        return iter(())

    def __or__(self, other):  # support ``FLAG_A | FLAG_B`` at module scope
        return self

    __ror__ = __or__
    __and__ = __or__
    __rand__ = __or__

    def __mro_entries__(self, bases):
        # Subclassing a stub at *import time* indicates that someone forgot
        # to wrap the class definition in a function (see module docstring).
        # Surface a clear error rather than letting Python emit an obscure
        # type-metaclass failure.
        raise TypeError(
            f"Cannot subclass IDA SDK stub '{self._qualname}' outside of IDA Pro. "
            "Wrap the subclass in a function so it's built lazily inside an RPC handler."
        )

    def __repr__(self) -> str:
        return f"<IDA stub {self._qualname}>"


class _StubModule(types.ModuleType):
    def __getattr__(self, item: str) -> _Stub:
        if item.startswith("__") and item.endswith("__"):
            raise AttributeError(item)
        return _Stub(f"{self.__name__}.{item}")


def install_if_missing(names: Iterable[str] = _STUB_MODULES) -> bool:
    """Install IDA SDK stubs when the real modules are absent.

    Returns ``True`` when stubs were installed, ``False`` when the real SDK
    was found. Existing entries in :data:`sys.modules` are left untouched so
    a partial real-SDK environment keeps whatever real modules it has.
    """
    try:
        import idaapi  # type: ignore  # noqa: F401
        return False
    except ImportError:
        for name in names:
            sys.modules.setdefault(name, _StubModule(name))
        return True
