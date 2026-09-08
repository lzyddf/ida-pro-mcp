"""Locate the no-console Python interpreter paired with the proxy runtime."""
from __future__ import annotations

from pathlib import Path


class WindowedPythonNotFoundError(RuntimeError):
    """Raised when the selected Windows Python has no pythonw.exe sibling."""


def find_windowed_python(console_python: str) -> str:
    """Return the pythonw.exe belonging to console_python."""
    executable = Path(console_python)
    if executable.name.casefold() == "pythonw.exe":
        candidate = executable
    else:
        candidate = executable.with_name("pythonw.exe")
    if not candidate.is_file():
        raise WindowedPythonNotFoundError(
            f"windowless service runtime not found: {candidate}. "
            "Install a standard CPython Windows runtime containing pythonw.exe."
        )
    return str(candidate)


def find_console_python(windowed_python: str) -> str:
    """Return the python.exe paired with a running pythonw.exe."""
    candidate = Path(windowed_python).with_name("python.exe")
    if not candidate.is_file():
        raise FileNotFoundError(f"console service runtime not found: {candidate}")
    return str(candidate)
