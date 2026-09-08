"""Shared test bootstrap for modules that normally run inside IDA Pro."""
from __future__ import annotations

from ida_pro_mcp.plugin import load_tools

# Production composition roots load tools explicitly. Tests import individual
# IDA-side helpers during collection, so install the lightweight SDK stubs and
# populate the registry before those modules are collected.
load_tools()
