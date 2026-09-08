"""Locate the *proxy*'s own Python interpreter and forward Python env vars.

The MCP host invocation strips the parent environment, so when we render an
``mcpServers`` config we must explicitly forward the variables that influence
how Python finds modules.

The chosen interpreter is the one the rendered MCP config will hand to the
host (Cursor, Claude Desktop, ...) as ``"command"``. If we hand back a path
whose Python cannot ``import ida_pro_mcp``, the host fails at startup with a
``ModuleNotFoundError`` -- the most common cause being a user running
``ida-pro-mcp-headless config`` with an unrelated venv activated.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


# Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
PYTHON_ENV_VARS = (
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSAFEPATH",
    "PYTHONPLATLIBDIR",
    "PYTHONPYCACHEPREFIX",
    "PYTHONNOUSERSITE",
    "PYTHONUSERBASE",
)

# How long we let an import probe run before giving up. The probe is a tiny
# ``python -c "import ida_pro_mcp"``; on a healthy machine it finishes in
# tens of milliseconds. The timeout exists to defend against a wedged
# interpreter (frozen mount, antivirus interception) rather than to bound a
# normal-case duration.
_IMPORT_PROBE_TIMEOUT_S = 5.0


def _venv_python() -> Path | None:
    venv = os.environ.get("VIRTUAL_ENV")
    if not venv:
        return None
    if sys.platform == "win32":
        candidate = Path(venv) / "Scripts" / "python.exe"
    else:
        candidate = Path(venv) / "bin" / "python3"
    return candidate if candidate.exists() else None


def _can_import_package(interpreter: str | os.PathLike[str], package: str) -> bool:
    """Return whether *interpreter* can ``import`` *package* in a fresh subprocess.

    We invoke the candidate with ``-c "import <pkg>"`` and check the exit
    status. ``stdin=DEVNULL`` keeps Windows from popping a console; output
    is silenced so a noisy ``import`` doesn't leak through to the user.
    """
    try:
        result = subprocess.run(
            [str(interpreter), "-c", f"import {package}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_IMPORT_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("import probe for %s failed: %s", interpreter, exc)
        return False
    return result.returncode == 0


def _candidate_interpreters() -> list[str]:
    """Return the ordered list of interpreter paths to probe.

    The order matters: we prefer the user's *active venv*, then
    ``sys.executable`` -- the interpreter that *actually* loaded this module
    and therefore has ``ida_pro_mcp`` importable by definition.

    Duplicates are stripped (preserving order) so a venv whose ``python3``
    happens to be ``sys.executable`` is probed only once.
    """
    raw: list[str] = []
    venv = _venv_python()
    if venv is not None:
        raw.append(str(venv))
    raw.append(sys.executable)

    seen: set[str] = set()
    deduped: list[str] = []
    for path in raw:
        if path and path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def get_python_executable() -> str:
    """Locate an interpreter that can run the MCP server.

    Strategy: probe candidates in priority order (active venv first,
    ``sys.executable`` last) and return the first one that can actually
    import the package. If *none* succeed, fall back to ``sys.executable``
    and warn -- this is the best we can do without lying to the user.
    """
    candidates = _candidate_interpreters()
    for interpreter in candidates:
        if _can_import_package(interpreter, "ida_pro_mcp"):
            return interpreter

    logger.warning(
        "no candidate interpreter could import ida_pro_mcp; falling back to %s. "
        "The generated MCP config may fail at startup -- install ida_pro_mcp into "
        "the interpreter you intend to run, or run `config` from that environment.",
        sys.executable,
    )
    return sys.executable


def collect_python_env() -> dict[str, str]:
    """Return a dict of any user-set Python env variables we should forward."""
    return {var: value for var in PYTHON_ENV_VARS if (value := os.environ.get(var))}
