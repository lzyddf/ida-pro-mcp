"""Tests for the line-renderer that backs ``disassemble_function_text``.

The renderer is a tiny pure function -- the value lives in nailing down
the format LLM callers will see (so any future tweak shows up here as a
visible diff rather than as a silent prompt churn).
"""
from __future__ import annotations

from ida_pro_mcp.plugin.tools.disasm import _render_disasm_text


class TestRenderDisasmText:
    def test_address_and_instruction_only(self):
        line = {"address": "0x401000", "instruction": "push    rbp"}
        assert _render_disasm_text(line) == "0x401000  push    rbp"

    def test_with_single_comment(self):
        line = {
            "address": "0x401004",
            "instruction": "mov     eax, 1",
            "comments": ["return code"],
        }
        assert _render_disasm_text(line) == "0x401004  mov     eax, 1  ; return code"

    def test_with_multiple_comments_joined(self):
        line = {
            "address": "0x401008",
            "instruction": "call    sub_402000",
            "comments": ["non-repeatable", "repeatable"],
        }
        rendered = _render_disasm_text(line)
        assert rendered == "0x401008  call    sub_402000  ; non-repeatable; repeatable"

    def test_label_emitted_on_its_own_line(self):
        line = {
            "address": "0x40100C",
            "instruction": "mov     ecx, edx",
            "label": "loc_40100C",
        }
        assert _render_disasm_text(line) == "loc_40100C:\n0x40100C  mov     ecx, edx"

    def test_label_and_comment(self):
        line = {
            "address": "0x401010",
            "instruction": "ret",
            "label": "exit_path",
            "comments": ["unwind"],
        }
        assert (
            _render_disasm_text(line)
            == "exit_path:\n0x401010  ret  ; unwind"
        )

    def test_segment_field_is_ignored_in_text_form(self):
        # ``DisassemblyLine`` carries a "segment" field used by the
        # structured tool; the text form intentionally omits it to stay
        # token-cheap.
        line = {
            "address": "0x401014",
            "instruction": "nop",
            "segment": ".text",
        }
        assert _render_disasm_text(line) == "0x401014  nop"
