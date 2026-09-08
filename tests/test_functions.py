"""Function lookup regressions that do not require a live IDA database."""
from __future__ import annotations

import inspect
from types import SimpleNamespace

from ida_pro_mcp.plugin import funcs
from ida_pro_mcp.plugin.tools import functions


def test_function_payload_uses_canonical_start_address(monkeypatch):
    fake = SimpleNamespace(start_ea=0x401000, end_ea=0x401080)
    monkeypatch.setattr(funcs.idaapi, "get_func", lambda _ea: fake, raising=False)
    monkeypatch.setattr(
        funcs.ida_funcs,
        "get_func_name",
        lambda ea: "main" if ea == 0x401000 else "",
        raising=False,
    )

    result = funcs.get_function(0x401042)

    assert result == {"address": "0x401000", "name": "main", "size": "0x80"}


def test_get_callers_deduplicates_by_canonical_function(monkeypatch):
    monkeypatch.setattr(
        functions,
        "get_func_or_raise",
        lambda _target: SimpleNamespace(start_ea=0x401000),
    )
    monkeypatch.setattr(
        functions.idautils,
        "CodeRefsTo",
        lambda target, _flow: [0x402005, 0x402020] if target == 0x401000 else [],
        raising=False,
    )
    monkeypatch.setattr(
        functions,
        "make_function",
        lambda _ea, raise_error=False: {
            "address": "0x402000",
            "name": "caller",
            "size": "0x40",
        },
    )
    monkeypatch.setattr(functions, "_CALL_OPS", (7,))

    class _Insn:
        itype = 0

    def _decode(insn, _ea):
        insn.itype = 7
        return 1

    monkeypatch.setattr(functions.idaapi, "insn_t", _Insn, raising=False)
    monkeypatch.setattr(functions.idaapi, "decode_insn", _decode, raising=False)

    raw_get_callers = inspect.unwrap(functions.get_callers)
    assert raw_get_callers("main") == [
        {"address": "0x402000", "name": "caller", "size": "0x40"}
    ]
