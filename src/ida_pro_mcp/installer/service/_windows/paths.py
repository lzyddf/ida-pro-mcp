"""On-disk locations for the Windows service backend artifacts.

All paths are resolved per-call (not cached) so tests can monkeypatch
``LOCALAPPDATA`` and ``Path.home`` between cases without poking module
globals. The directory layout is::

    %LOCALAPPDATA%\\ida-pro-mcp-headless\\service\\
        service.json       # runner configuration
        task.xml           # generated Scheduled Task XML
        proxy.stdout.log   # proxy standard output
        proxy.stderr.log   # proxy standard error

The whole tree is wiped on ``--service uninstall`` -- nothing else stores
state there, so a wholesale ``rmtree`` is the right cleanup primitive.
"""
from __future__ import annotations

import os
from pathlib import Path

# Stable identifier; the task name and the on-disk artifacts both use this.
# Matches ``MCP_SERVER_NAME`` so users only have to remember one string.
TASK_NAME = "ida-pro-mcp-headless"


def _service_dir() -> Path:
    """Per-user, non-roaming directory for the config + XML + logs.

    Falls back to ``~/.ida-pro-mcp-headless/service`` when ``LOCALAPPDATA`` is unset
    (rare in practice, but the test harness deletes it -- and the fallback
    keeps the helper usable from inside an `os.environ`-cleared sandbox).
    """
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "ida-pro-mcp-headless" / "service"
    return Path.home() / ".ida-pro-mcp-headless" / "service"


def _config_path() -> Path:
    return _service_dir() / "service.json"


def _legacy_wrapper_path() -> Path:
    """Return the pre-1.5 proxy.cmd path so upgrades can remove it."""
    return _service_dir() / "proxy.cmd"


def _task_xml_path() -> Path:
    return _service_dir() / "task.xml"


def _stdout_log() -> Path:
    return _service_dir() / "proxy.stdout.log"


def _stderr_log() -> Path:
    return _service_dir() / "proxy.stderr.log"
