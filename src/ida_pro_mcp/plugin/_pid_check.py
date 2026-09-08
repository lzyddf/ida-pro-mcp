"""Cross-platform "is this PID still alive?" probe.

Used by :mod:`.session` to GC sidecar files whose owner crashed without
removing them. Lifted out of ``session.py`` because the implementation has
its own platform branching (POSIX ``os.kill(pid, 0)`` vs. the Win32
process-status API via ctypes), a module-cached kernel32 handle, and
half a dozen Win32 constants -- none of which has anything to do with
the JSON-shaped sidecar contract that ``session.py`` is otherwise about.

Public surface is one function, :func:`is_pid_alive`. Everything else is
underscore-prefixed implementation detail; tests should monkeypatch the
public name.
"""
from __future__ import annotations

import ctypes
import errno
import os
import sys


def is_pid_alive(pid: int) -> bool:
    """Best-effort check that *pid* still exists on the local system.

    On POSIX we use ``os.kill(pid, 0)`` -- the standard idiom that sends
    no signal but raises ``ProcessLookupError`` when the pid is gone.

    On Windows ``os.kill`` is **not** an existence probe: ``signal=0``
    falls through to ``TerminateProcess(handle, 0)``, which actively
    kills the target. Using it from the proxy (which interrogates many
    foreign pids -- live headless IDAs, stale sidecars from previous
    runs) would silently terminate unrelated processes. We instead
    consult the Win32 process-status API via ctypes, which is the
    canonical existence check on Windows and never has side effects.

    Returns ``False`` for non-positive pids (defensive: ``0`` is "current
    process group" on POSIX and ``-1`` is reserved for ``waitpid`` -- in
    both cases callers asking "is this PID alive?" want ``False``).
    """
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:  # pragma: no cover -- platform-specific
        return exc.errno != errno.ESRCH
    return True


# Win32 constants we need; defined module-scoped so the per-call hot path
# doesn't re-allocate them. Values are documented at:
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
_WIN32_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WIN32_STILL_ACTIVE = 259
_WIN32_ERROR_INVALID_PARAMETER = 87

# Cache the kernel32 handle module-side so a fan-out probe (one per sidecar)
# doesn't re-walk ctypes' DLL table on every call. Lazy because importing
# this module on POSIX must not touch ``ctypes.WinDLL``.
_kernel32: object | None = None


def _get_kernel32() -> object:
    global _kernel32
    if _kernel32 is None:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    return _kernel32


def _pid_alive_windows(pid: int) -> bool:
    """Existence probe via ``OpenProcess`` + ``GetExitCodeProcess``.

    ``OpenProcess`` returning ``NULL`` with ``ERROR_INVALID_PARAMETER``
    means the pid does not name a live process.
    ``ERROR_ACCESS_DENIED`` means the process exists but our token
    cannot inspect it (Windows session boundary, elevated process,
    etc.) -- we still consider it alive. Any other error path defaults
    to "alive" so we never falsely GC a sidecar whose owner is healthy
    but harder to query.
    """
    kernel32 = _get_kernel32()
    handle = kernel32.OpenProcess(
        _WIN32_PROCESS_QUERY_LIMITED_INFORMATION, False, ctypes.c_uint32(pid)
    )
    if not handle:
        # Anything *but* "no such pid" means the process exists; we treat
        # ACCESS_DENIED and friends as alive so a sidecar whose owner is
        # in another session/elevation level isn't GC'd by mistake.
        return ctypes.get_last_error() != _WIN32_ERROR_INVALID_PARAMETER
    try:
        exit_code = ctypes.c_uint32()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == _WIN32_STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)
