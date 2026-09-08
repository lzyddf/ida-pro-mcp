"""Regression tests for the explicit IDA tool-loading boundary."""
from __future__ import annotations

import subprocess
import sys


def test_protocol_import_does_not_load_ida_tools_or_stubs():
    script = """
import sys
import ida_pro_mcp.plugin.constants
from ida_pro_mcp.plugin import rpc_registry

assert not rpc_registry.methods
assert "idaapi" not in sys.modules
"""
    subprocess.run([sys.executable, "-c", script], check=True)


def test_explicit_loader_is_idempotent():
    from ida_pro_mcp.plugin import load_tools

    first = load_tools()
    second = load_tools()
    assert first is second
    assert "functions" in first
    assert "type_editing" in first
    assert "convert" not in first
