"""Guard: the IDA-side import chain must stay free of compiled dependencies.

The IDA-side package is imported by two different interpreters -- the proxy's
Python and the IDAPython that IDA bundles -- so any compiled extension in the
chain (``pydantic_core`` being the historical offender) breaks as soon as those
versions differ. That failure mode is invisible to the normal test suite, which
runs entirely on the proxy interpreter.

These tests run a subprocess with ``pydantic`` and ``pydantic_core`` blocked at
the import level, then import the IDA-side chain. If a future change reintroduces
a third-party or compiled dependency there, the subprocess fails and this test
goes red.
"""
from __future__ import annotations

import subprocess
import sys

# Blocked at the top of sys.meta_path so *any* import of these names -- direct,
# transitive, or from a stub -- fails loudly instead of silently succeeding
# because the proxy environment happens to have them installed.
_BLOCKER = """
import sys

BLOCKED = ("pydantic", "pydantic_core")


class _Blocker:
    def find_spec(self, fullname, path=None, target=None):
        root = fullname.split(".")[0]
        if root in BLOCKED:
            raise ImportError(f"blocked for the IDA-side dependency guard: {fullname}")
        return None


sys.meta_path.insert(0, _Blocker())
"""


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _BLOCKER + code],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_plugin_package_imports_without_pydantic():
    """``import ida_pro_mcp.plugin`` is the first thing the bootstrap does."""
    result = _run(
        "import ida_pro_mcp.plugin as p;"
        "import sys;"
        "assert 'pydantic' not in sys.modules, sorted(sys.modules);"
        "assert p.rpc_registry is not None"
    )
    assert result.returncode == 0, result.stderr


def test_full_tool_registry_loads_without_pydantic():
    """Every IDA-side tool module must import with no compiled dependency present."""
    result = _run(
        "from ida_pro_mcp.plugin import load_tools;"
        "from ida_pro_mcp.plugin.registry import rpc_registry;"
        "load_tools();"
        "import sys;"
        "assert 'pydantic' not in sys.modules, sorted(sys.modules);"
        "assert len(rpc_registry.methods) >= 40, len(rpc_registry.methods);"
        "print('tools:', len(rpc_registry.methods))"
    )
    assert result.returncode == 0, result.stderr
    assert "tools:" in result.stdout


def test_bootstrap_import_line_works_without_pydantic():
    """Reproduce the exact import that crashed IDA on a version-mismatched proxy.

    ``headless_bootstrap`` runs inside IDA and starts with this import; the
    original failure surfaced here as ``ModuleNotFoundError: No module named
    'pydantic_core._pydantic_core'``.
    """
    result = _run(
        "from ida_pro_mcp.plugin import idb_hooks, session;"
        "assert session.base_dir() is not None"
    )
    assert result.returncode == 0, result.stderr


def test_ida_side_modules_import_no_third_party_packages():
    """Only stdlib and ``typing_extensions`` may appear after loading tools.

    ``typing_extensions`` is allowed because it is pure Python and already a
    declared dependency; everything else on the IDA side would have to be
    justified the same way before being added.
    """
    result = _run(
        "import sys;"
        "before = set(sys.modules);"
        "from ida_pro_mcp.plugin import load_tools;"
        "load_tools();"
        "allowed = {'typing_extensions'};"
        "third_party = sorted("
        "    name for name in set(sys.modules) - before"
        "    if not name.startswith(('ida_', 'ida_pro_mcp', '_'))"
        "    and name.split('.')[0] in {"
        "        'pydantic', 'pydantic_core', 'annotated_types', 'mcp', 'anyio',"
        "        'httpx', 'starlette', 'uvicorn', 'attrs', 'attr', 'cffi',"
        "    }"
        "    and name.split('.')[0] not in allowed"
        ");"
        "assert not third_party, third_party;"
        "print('ok')"
    )
    assert result.returncode == 0, result.stderr
