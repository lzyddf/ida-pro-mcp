"""TypedDict schemas exposed by RPC tools.

Centralising them here lets MCP clients and the generated server agree on
shape without duplicating definitions. Keep field names stable: changes to
these types are part of the public RPC contract.

NOTE: this module deliberately does *not* use ``from __future__ import
annotations``. PEP 563 turns every annotation into a string at class
creation time, but ``TypedDict``'s ``__required_keys__`` machinery only
recognises ``NotRequired[...]`` when it sees the runtime sentinel object,
not the string ``"NotRequired[...]"``. With PEP 563 enabled, every
``NotRequired`` field would silently become required. Avoiding the future
import keeps the schema correct.
"""
import sys
from typing import Generic, TypeVar

if sys.version_info >= (3, 12):
    from typing import NotRequired, TypedDict
else:
    from typing import NotRequired

    from typing_extensions import TypedDict

T = TypeVar("T")


class Metadata(TypedDict):
    path: str
    module: str
    base: str
    size: str
    md5: str
    sha256: str
    crc32: str
    filesize: str


class Function(TypedDict):
    address: str
    name: str
    size: str


class ConvertedNumber(TypedDict):
    decimal: int
    hexadecimal: str
    bytes: str
    ascii: str | None
    binary: str


class Page(TypedDict, Generic[T]):
    data: list[T]
    total: int
    next_offset: int | None


class Global(TypedDict):
    address: str
    name: str


class Import(TypedDict):
    address: str
    imported_name: str
    module: str


class String(TypedDict):
    address: str
    length: int
    string: str


class Segment(TypedDict):
    name: str
    start: str
    end: str
    perms: str  # rwx triple, e.g. "r-x", "rw-", "---"
    sclass: NotRequired[str]  # IDA segment class: CODE / DATA / BSS / ...
    bitness: NotRequired[int]  # 16 / 32 / 64


class DisassemblyLine(TypedDict):
    segment: NotRequired[str]
    address: str
    label: NotRequired[str]
    instruction: str
    comments: NotRequired[list[str]]


class DecompiledLine(TypedDict):
    line: int
    address: NotRequired[str]
    text: str


class Argument(TypedDict):
    name: str
    type: str


class StackFrameVariable(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class DisassemblyFunction(TypedDict):
    name: str
    start_ea: str
    return_type: NotRequired[str]
    arguments: NotRequired[list[Argument]]
    stack_frame: list[StackFrameVariable]
    lines: list[DisassemblyLine]


class Xref(TypedDict):
    address: str
    type: str
    function: Function | None


class StructureMember(TypedDict):
    name: str
    offset: str
    size: str
    type: str


class StructureDefinition(TypedDict):
    name: str
    size: str
    members: list[StructureMember]


class StructureMemberValue(TypedDict):
    name: str
    offset: str
    type: str
    size: int
    value: str
    is_nested_udt: NotRequired[bool]


class StructureAtAddress(TypedDict):
    struct_name: str
    address: str
    members: list[StructureMemberValue]


class Callee(TypedDict):
    address: str
    name: str
    type: str  # "internal" | "external"


class RegisterValue(TypedDict):
    name: str
    value: str


class ThreadRegisters(TypedDict):
    thread_id: int
    registers: list[RegisterValue]


class Breakpoint(TypedDict):
    ea: str
    enabled: bool
    condition: str | None


class CallStackFrame(TypedDict):
    address: str
    module: NotRequired[str]
    symbol: NotRequired[str]
    error: NotRequired[str]
