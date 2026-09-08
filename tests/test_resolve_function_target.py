"""Tests for ``resolve_function_target`` (shared by decompile + disasm).

The resolver lives in :mod:`ida_pro_mcp.plugin.names` so both
``decompile_function_text`` and ``disassemble_function_text`` can lean on
the same hex-vs-name disambiguation logic. Direct IDA calls are stubbed
in via ``monkeypatch`` so the resolver can be exercised outside of IDA.
"""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin import names as names_module
from ida_pro_mcp.plugin.errors import IDAError


@pytest.fixture
def stub_lookups(monkeypatch):
    """Provide deterministic IDA-side responses for the resolver.

    ``get_func`` returns truthy for a fixed set of EAs (the "real"
    functions in the test scenario); ``lookup_function_ea_by_name`` looks
    up names in a mapping or raises ``IDAError`` when missing.
    """
    fake_funcs = {0x401000, 0x401234}
    fake_names = {
        "main": 0x401000,
        "fcf94739": 0x402000,  # name that also parses as a hex address
    }

    monkeypatch.setattr(
        names_module.idaapi,
        "get_func",
        lambda ea: object() if ea in fake_funcs else None,
        raising=False,
    )

    def _lookup(name: str) -> int:
        if name in fake_names:
            return fake_names[name]
        raise IDAError(f"No function found with name {name}")

    monkeypatch.setattr(names_module, "lookup_function_ea_by_name", _lookup)
    return fake_funcs, fake_names


class TestResolveFunctionTarget:
    def test_hex_address_with_prefix(self, stub_lookups):
        assert names_module.resolve_function_target("0x401000") == 0x401000

    def test_bare_hex_address(self, stub_lookups):
        assert names_module.resolve_function_target("401000") == 0x401000

    def test_name_with_non_hex_chars(self, stub_lookups):
        assert names_module.resolve_function_target("main") == 0x401000

    def test_hex_looking_name_falls_back_to_name_lookup(self, stub_lookups):
        # ``fcf94739`` parses as 0xFCF94739 but no function lives there,
        # so the resolver must fall back to a name lookup that does
        # have the entry.
        assert names_module.resolve_function_target("fcf94739") == 0x402000

    def test_empty_target_raises(self, stub_lookups):
        with pytest.raises(IDAError):
            names_module.resolve_function_target("")

    def test_whitespace_only_raises(self, stub_lookups):
        with pytest.raises(IDAError):
            names_module.resolve_function_target("   ")

    def test_unknown_name_propagates_lookup_error(self, stub_lookups):
        with pytest.raises(IDAError):
            names_module.resolve_function_target("missing_name")

    def test_strips_surrounding_whitespace(self, stub_lookups):
        assert names_module.resolve_function_target("  0x401000  ") == 0x401000
        assert names_module.resolve_function_target("\tmain\n") == 0x401000


class TestResolveNameOrAddress:
    def test_name_wins_even_when_it_looks_hexadecimal(self, monkeypatch):
        monkeypatch.setattr(
            names_module,
            "resolve_name_ea",
            lambda name: 0x500000 if name == "deadbeef" else None,
        )
        assert names_module.resolve_name_or_address("deadbeef") == 0x500000

    def test_address_is_used_when_no_name_matches(self, monkeypatch):
        monkeypatch.setattr(names_module, "resolve_name_ea", lambda _name: None)
        assert names_module.resolve_name_or_address("0x401000") == 0x401000

    def test_unknown_non_address_raises_domain_error(self, monkeypatch):
        monkeypatch.setattr(names_module, "resolve_name_ea", lambda _name: None)
        with pytest.raises(IDAError, match="not found"):
            names_module.resolve_name_or_address("missing_symbol", kind="global variable")
