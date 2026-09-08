"""Tests that the IDA SDK stubs let every tool module import cleanly."""
from __future__ import annotations


def test_plugin_package_imports_under_stubs():
    import ida_pro_mcp.plugin as plugin
    from ida_pro_mcp.plugin.tools import using_stubs

    plugin.load_tools()
    # Stubs must have been installed since these tests run outside IDA.
    assert using_stubs() is True


def test_registry_populated():
    from ida_pro_mcp.plugin import rpc_registry
    assert len(rpc_registry.methods) > 30
    assert "get_metadata" in rpc_registry.methods
    assert "list_functions" in rpc_registry.methods


def test_unsafe_methods_are_marked():
    from ida_pro_mcp.plugin import rpc_registry
    # Anything debugger or patch should be unsafe.
    assert rpc_registry.is_unsafe("dbg_set_breakpoint")
    assert rpc_registry.is_unsafe("patch_address_assembles")
    assert not rpc_registry.is_unsafe("get_metadata")


def test_safe_and_unsafe_partition():
    from ida_pro_mcp.plugin import rpc_registry
    safe = set(rpc_registry.safe_methods())
    unsafe = set(rpc_registry.unsafe)
    assert safe.isdisjoint(unsafe)
    assert safe | unsafe == set(rpc_registry.methods)


def test_subclassing_stub_at_import_time_raises():
    """Build-time subclassing of a stub must fail loudly with a helpful message."""
    import ida_idp  # stub-injected
    import pytest

    # ``class Foo(stub_attr): ...`` is what tool authors actually write; it
    # invokes ``__mro_entries__`` on each non-class base. Use exec so the
    # syntax is exercised faithfully instead of via ``type(...)``.
    src = "class Foo(ida_idp.IDB_Hooks):\n    pass\n"
    with pytest.raises(TypeError, match="Wrap the subclass"):
        exec(src, {"ida_idp": ida_idp})


def test_public_exports_are_actually_present():
    """Every name in ``__all__`` must resolve on the package."""
    import ida_pro_mcp.plugin as plugin
    for name in plugin.__all__:
        assert hasattr(plugin, name), f"missing public export: {name}"
