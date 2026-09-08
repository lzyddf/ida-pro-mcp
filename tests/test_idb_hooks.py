"""Test the IDB hooks module imports cleanly under stubs.

The hooks themselves cannot run outside IDA Pro (they subclass a SWIG type
that the stub guard refuses to subclass), but ``install`` / ``uninstall``
must at least be importable so the bootstrap code in ``headless_bootstrap.py``
does not fail at module load time.
"""
from __future__ import annotations


def test_module_imports():
    from ida_pro_mcp.plugin import idb_hooks

    assert callable(idb_hooks.install)
    assert callable(idb_hooks.uninstall)


def test_uninstall_is_idempotent_no_install():
    from ida_pro_mcp.plugin import idb_hooks

    idb_hooks.uninstall()  # safe even when nothing was installed
