"""Environment scrubbing for the headless ``idat`` child process.

The MCP host (Cursor / Claude Desktop / Windsurf / ...) typically launches
the proxy with ``PYTHONHOME`` pointed at a ``uv``/``pipx``-managed CPython.
Forwarding that env to IDA's embedded interpreter is fatal: IDA loads C
extensions (``_sre``, ...) compiled for the *other* Python version and
``init.py`` aborts with messages like "SRE module mismatch" -- IDA then
refuses to even recognise ``.py`` scripts, so the bootstrap never runs and
``open_file`` times out.

This module owns the blocklist + the ``PATH`` venv stripper + the working-
directory picker. The :class:`Spawner` consumes :func:`build_spawn_env` and
:func:`spawn_cwd_for` to produce the env / cwd it hands to ``Popen``.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path

from ..installer.proxy_python import PYTHON_ENV_VARS

logger = logging.getLogger(__name__)


# Environment variables that configure *our* Python interpreter (the proxy)
# but would actively break IDA's embedded interpreter if forwarded. We strip
# them unconditionally: anything that influences module resolution for the
# proxy's interpreter is, by construction, wrong for IDA's interpreter.
_PYTHON_ENV_VARS_TO_STRIP: tuple[str, ...] = (
    *PYTHON_ENV_VARS,
    "PYTHONSTARTUP",
    "PYTHONEXECUTABLE",
    "VIRTUAL_ENV",
    "VIRTUAL_ENV_PROMPT",
    # uv's launch shim records its driver interpreter here. IDA's
    # IDAPython treats it as a venv hint and switches interpreter --
    # same blast radius as the variables above.
    "UV_INTERNAL__PYTHONHOME",
)


def _strip_venv_from_path(path_value: str) -> str:
    """Drop PATH entries that point inside a Python virtual environment.

    IDA 9.0's IDAPython auto-detects venvs by walking ``PATH``: if it
    finds a ``python.exe`` whose directory's parent contains a
    ``pyvenv.cfg``, it switches *its own* embedded interpreter to that
    venv -- even though the venv's Python might be a completely
    different version from the DLL ``idapyswitch`` selected. The result
    is a cross-version C-extension load (typically ``pydantic_core``)
    that fails with::

        ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'

    A common trigger is launching the proxy via ``uv run`` from a
    project checkout: ``uv`` prepends ``<repo>/.venv/Scripts`` to
    ``PATH`` so its shims win over system Python, and that very entry
    is what IDA then mis-uses.

    Removal criterion: ``<entry>/../pyvenv.cfg`` exists. That's the
    canonical Python venv marker (PEP 405); pip's ``virtualenv`` and
    ``uv`` both write it. Entries that don't resolve, that don't exist,
    or that are unreadable are kept as-is so we don't accidentally
    strip a malformed-but-needed system path.
    """
    if not path_value:
        return path_value

    kept: list[str] = []
    for entry in path_value.split(os.pathsep):
        if not entry:
            continue
        try:
            marker = Path(entry).parent / "pyvenv.cfg"
            if marker.is_file():
                continue
        except OSError:
            pass
        kept.append(entry)
    return os.pathsep.join(kept)


def hard_kill_signal() -> int:
    """Return the signal value that hard-kills a process on this platform.

    POSIX: ``SIGKILL`` (uncatchable). Windows: ``SIGKILL`` is undefined,
    but ``os.kill(pid, signal.SIGTERM)`` already maps to
    ``TerminateProcess(handle, 15)`` -- a hard kill -- so we reuse it.
    """
    if sys.platform == "win32":
        return signal.SIGTERM
    return signal.SIGKILL


def build_spawn_env(*, package_root: str) -> dict[str, str]:
    """Return a copy of ``os.environ`` cleaned for the headless ``idat`` child.

    *package_root* is forwarded as ``IDA_PRO_MCP_PACKAGE_ROOT`` so the
    bootstrap can ``sys.path.insert(0, ...)`` it without depending on
    IDA's embedded site-packages knowing about the project. ``TVHEADLESS=1``
    keeps IDA's TUI machinery quiet under headless invocation.

    The Python configuration of the proxy interpreter (``PYTHONHOME``,
    ``PYTHONPATH``, ``VIRTUAL_ENV``, ...) is stripped: see the module
    docstring for the rationale.
    """
    env = dict(os.environ)
    for name in _PYTHON_ENV_VARS_TO_STRIP:
        env.pop(name, None)
    scrubbed = _strip_venv_from_path(env.get("PATH", ""))
    if scrubbed:
        env["PATH"] = scrubbed
    elif "PATH" in env:
        # Defensive: if PATH was *entirely* venv entries, leave the key
        # absent so the OS falls back to its default search rather than
        # using an empty PATH (which on Windows breaks DLL resolution).
        env.pop("PATH", None)
    env.setdefault("TVHEADLESS", "1")
    env["IDA_PRO_MCP_PACKAGE_ROOT"] = package_root
    return env


def spawn_cwd_for(binary: Path) -> str:
    """Pick a cwd for the headless ``idat`` that's free of stray ``.venv``.

    IDA 9.0's IDAPython auto-detects a ``.venv`` directory next to the
    process's working directory and switches to that interpreter --
    even though IDA itself loaded a Python DLL of a different version
    through ``idapyswitch``. The result is a cross-version ``import``
    chain that explodes at the first C extension::

        ModuleNotFoundError: No module named 'pydantic_core._pydantic_core'

    Inheriting the parent's cwd is dangerous because the parent is
    typically the proxy CLI launched from the user's shell -- often the
    same checkout that *also* hosts the project's ``.venv``. Using the
    binary's directory matches what users get from running ``idat <file>``
    directly from a file manager and keeps IDA's relative-path lookups
    (loader configs, IDS files) working.

    Falls back to the process cwd when the binary's parent doesn't exist
    on disk (e.g. binary on a now-unmounted share); ``Popen`` would
    otherwise crash on a non-existent path.
    """
    parent = binary.parent
    if parent.is_dir():
        return str(parent)
    return os.getcwd()
