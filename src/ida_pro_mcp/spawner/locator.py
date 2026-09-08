"""Locate the ``idat`` executable to spawn.

The proxy reads the **single** environment variable :envvar:`IDA_PRO_HOME` --
your IDA install directory -- and looks for ``idat`` (POSIX) or ``idat.exe``
(Windows) inside it. There is no other resolution path: no ``PATH`` lookup,
no platform-default glob, no per-call override. This keeps the contract
explicit ("set one env var, get a working proxy") and matches the way users
already think about IDA installs ("the directory containing ``idat`` and
the licence file").

For ``stdio`` MCP transports the variable is normally written into
``env.IDA_PRO_HOME`` of the rendered ``mcpServers`` block; for HTTP transports
the proxy inherits it from the shell of whatever runs ``ida-pro-mcp-headless serve`` --
the remote MCP client config has no idat-related field at all.

Failure raises :class:`IdatNotFoundError` with the searched paths embedded so
the user sees actionable diagnostics rather than ``[Errno 2] No such file``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

IDA_HOME_ENV_VAR = "IDA_PRO_HOME"
"""Name of the env var the spawner consults for the IDA install directory."""


class IdatNotFoundError(RuntimeError):
    """Raised when no ``idat`` binary can be located on this machine."""


def _idat_basenames() -> tuple[str, ...]:
    """Return the platform-specific filenames :func:`locate_idat` will probe.

    Listed in resolution order so a Linux box that, somehow, has both
    binaries side-by-side prefers the POSIX one. Windows is single-entry
    because IDA does not ship a bare ``idat`` on that platform.
    """
    if sys.platform == "win32":
        return ("idat.exe",)
    return ("idat", "idat.exe")


def _is_executable(path: Path) -> bool:
    """Cross-platform ``can I exec this file?`` check.

    On POSIX we trust the kernel's exec bit via :func:`os.access`. On
    Windows ``os.access(X_OK)`` is documented as ignored on most builds
    and effectively returns ``True`` for any readable file, so we fall
    back to a ``PATHEXT`` extension check -- exactly what
    :func:`shutil.which` does internally. The default ``PATHEXT`` value
    (``.COM;.EXE;.BAT;.CMD``) is used when the env var is unset, matching
    Windows shell behaviour.
    """
    if sys.platform == "win32":
        pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD")
        suffixes = [ext.strip().lower() for ext in pathext.split(os.pathsep) if ext.strip()]
        return path.suffix.lower() in suffixes
    return os.access(path, os.X_OK)


def locate_idat_in_home(home: str | os.PathLike[str]) -> Path:
    """Return the usable ``idat`` binary inside an explicit IDA install directory.

    This environment-independent validator is shared by runtime spawning and
    user-facing configuration. Keeping the filesystem checks here prevents
    generated configuration from drifting away from what the spawner accepts.
    """
    home_text = os.fspath(home)
    directory = Path(home_text).expanduser()
    if not directory.is_dir():
        raise IdatNotFoundError(
            f"Could not locate IDA Pro headless binary: IDA install directory "
            f"{home_text!r} is not a directory."
        )

    tried: list[str] = []
    for name in _idat_basenames():
        candidate = directory / name
        tried.append(str(candidate))
        if candidate.is_file() and _is_executable(candidate):
            return candidate.resolve()

    raise IdatNotFoundError(
        f"Could not locate IDA Pro headless binary inside IDA install directory "
        f"{home_text!r}. "
        f"(searched: {tried})"
    )


def locate_idat() -> Path:
    """Return the absolute path to the ``idat`` selected by ``IDA_PRO_HOME``.

    Environment lookup lives in this thin wrapper; directory and executable
    validation is delegated to :func:`locate_idat_in_home` so every caller
    enforces the same contract.
    """
    home = os.environ.get(IDA_HOME_ENV_VAR)
    if not home:
        raise IdatNotFoundError(
            f"Could not locate IDA Pro headless binary: {IDA_HOME_ENV_VAR} is not set. "
            f"Set {IDA_HOME_ENV_VAR} to your IDA install directory (the folder "
            "containing `idat` / `idat.exe`)."
        )
    return locate_idat_in_home(home)
