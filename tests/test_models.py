"""Pin the wire contract of every public response model.

The TypedDicts in ``plugin.models`` are part of the JSON-RPC contract: their
field names appear verbatim in MCP responses, so silently renaming or
dropping a field is a breaking change for downstream clients. This test
locks the *intended* field set of each model so accidental drift fails CI
loudly.

When a field is genuinely added/removed/renamed, update the expected set
here as part of the same change so the contract update is explicit in
review.
"""
from __future__ import annotations

from typing import get_type_hints

from ida_pro_mcp.plugin import models

# Each entry: (model class, required-fields, optional-fields).
# "Optional" means ``NotRequired[...]`` in the TypedDict; required keys must
# always appear in valid responses.
_EXPECTED_FIELDS: list[tuple[type, set[str], set[str]]] = [
    (models.Metadata, {"path", "module", "base", "size", "md5", "sha256", "crc32", "filesize"}, set()),
    (models.Function, {"address", "name", "size"}, set()),
    (models.ConvertedNumber, {"decimal", "hexadecimal", "bytes", "ascii", "binary"}, set()),
    (models.Page, {"data", "total", "next_offset"}, set()),
    (models.Global, {"address", "name"}, set()),
    (models.Import, {"address", "imported_name", "module"}, set()),
    (models.String, {"address", "length", "string"}, set()),
    (models.DisassemblyLine, {"address", "instruction"}, {"segment", "label", "comments"}),
    (models.DecompiledLine, {"line", "text"}, {"address"}),
    (models.Argument, {"name", "type"}, set()),
    (models.StackFrameVariable, {"name", "offset", "size", "type"}, set()),
    (
        models.DisassemblyFunction,
        {"name", "start_ea", "stack_frame", "lines"},
        {"return_type", "arguments"},
    ),
    (models.Xref, {"address", "type", "function"}, set()),
    (models.StructureMember, {"name", "offset", "size", "type"}, set()),
    (models.StructureDefinition, {"name", "size", "members"}, set()),
    (models.StructureMemberValue, {"name", "offset", "type", "size", "value"}, {"is_nested_udt"}),
    (models.StructureAtAddress, {"struct_name", "address", "members"}, set()),
    (models.Callee, {"address", "name", "type"}, set()),
    (models.RegisterValue, {"name", "value"}, set()),
    (models.ThreadRegisters, {"thread_id", "registers"}, set()),
    (models.Breakpoint, {"ea", "enabled", "condition"}, set()),
    (models.CallStackFrame, {"address"}, {"module", "symbol", "error"}),
]


class TestFieldSets:
    def test_every_model_matches_expected_field_set(self):
        for cls, required, optional in _EXPECTED_FIELDS:
            keys = set(get_type_hints(cls).keys())
            expected = required | optional
            assert keys == expected, (
                f"{cls.__name__} fields drifted: expected {sorted(expected)}, got {sorted(keys)}"
            )

    def test_required_keys_match_typeddict_required_set(self):
        # ``__required_keys__`` is an authoritative source -- if it disagrees
        # with our table, the test table is wrong (or the model annotation is
        # missing ``NotRequired``).
        for cls, required, _optional in _EXPECTED_FIELDS:
            assert set(cls.__required_keys__) == required, (
                f"{cls.__name__} __required_keys__={sorted(cls.__required_keys__)} != "
                f"expected {sorted(required)}"
            )
