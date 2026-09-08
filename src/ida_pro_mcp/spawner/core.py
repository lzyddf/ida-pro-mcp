"""Headless ``idat`` launcher used by the ``open_file`` / ``close_file`` MCP tools.

The proxy (``ida-pro-mcp-headless``) talks to running IDAs over JSON-RPC; this module
adds the missing capability of *spawning* an IDA when the LLM asks for one.
The shape is deliberately minimal:

* :class:`Spawner` calls ``Popen`` with ``-A -S<bootstrap> -L<log>`` and polls
  the sidecar registry for the new session. Success returns an
  :class:`OpenResult`; failure tears down the half-spawned process and surfaces
  the IDA log tail to the caller.

We do *not* maintain a long-lived child table here -- the sidecar registry
already knows which PIDs are alive, and ``close_file`` finds the target
through that registry. Keeping this module stateless makes it trivial to
test (no fixtures to reset) and lets the proxy come and go without
orphaning state.
"""
from __future__ import annotations

import contextlib
import logging
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from ..plugin import session
from ..plugin.session import SessionInfo
from . import kill_switch
from .idb_artifacts import delete_idb_artifacts
from .locator import locate_idat
from .process_env import build_spawn_env, hard_kill_signal, spawn_cwd_for

logger = logging.getLogger(__name__)


def _bootstrap_script() -> Path:
    """Return the path to ``plugin/headless_bootstrap.py``.

    Resolved at call time (rather than module import) so tests that
    monkey-patch the package layout still work.
    On Windows, returns the 8.3 short path to avoid IDA's -S argument
    splitting on spaces.
    """
    p = Path(session.__file__).resolve().parent / "headless_bootstrap.py"
    if sys.platform == "win32":
        import ctypes
        buf = ctypes.create_unicode_buffer(512)
        ctypes.windll.kernel32.GetShortPathNameW(str(p), buf, 512)
        if buf.value:
            return Path(buf.value)
    return p


def _logs_dir() -> Path:
    path = session.base_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _ida_log_path(session_id: str) -> Path:
    return _logs_dir() / f"{session_id}.ida.log"


def _stdio_log_path(session_id: str) -> Path:
    return _logs_dir() / f"{session_id}.stdio.log"


def _package_root() -> str:
    """Return the directory the spawner sets as ``IDA_PRO_MCP_PACKAGE_ROOT``."""
    return str(Path(session.__file__).resolve().parents[2])


def _tail(path: Path, lines: int = 30) -> str:
    """Return the last *lines* lines of *path*, or a placeholder.

    Defensive: surfaces the diagnostic even if the log is huge or in a
    locale we can't decode.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return f"[no log at {path}]\n"
    body = "\n".join(text.splitlines()[-lines:])
    return f"--- {path.name} ---\n{body}\n"


@dataclass(frozen=True)
class OpenResult:
    """Public payload returned from :meth:`Spawner.open`.

    A separate type from :class:`SessionInfo` because we surface a few
    spawn-specific extras (``log_file``, ``reused``) the LLM benefits
    from but that have no place in the on-disk sidecar.
    """

    session: SessionInfo
    log_file: str
    reused: bool


class Spawner:
    """Launches headless ``idat`` and waits for the new session sidecar.

    Authoritative session state lives in the on-disk sidecar (the registry
    in :mod:`.plugin.session`); the spawner deliberately avoids holding a
    parallel "current session" model that could drift out of sync. The
    instance does keep a small amount of *bookkeeping* state -- ``Popen``
    handles for processes we spawned (so they can be reaped cleanly) and
    a per-session-id lock dict (so concurrent ``open`` calls for the same
    binary serialise instead of double-spawning) -- but neither is
    consulted to answer "is this session alive?": that question is
    delegated to the sidecar's PID-liveness GC.
    """

    DEFAULT_STARTUP_TIMEOUT_S = 600.0
    DEFAULT_CLOSE_TIMEOUT_S = 30.0
    POLL_INTERVAL_S = 0.1

    def __init__(
        self,
        *,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT_S,
    ) -> None:
        self._startup_timeout = startup_timeout
        # Keep ``Popen`` handles alive until the corresponding ``close``;
        # otherwise CPython's GC of the unreferenced Popen issues a
        # ``ResourceWarning`` even though the OS will happily reap the
        # child via init when the proxy exits. Sidecars remain the
        # source of truth -- this dict is just bookkeeping.
        self._handles: dict[int, subprocess.Popen[bytes]] = {}
        # Per-session-id locks serialise concurrent ``open`` calls for
        # the same binary so a slow auto-analysis on the first call
        # cannot race a second call that finds ``existing is None`` and
        # double-spawns IDA. ``_locks_lock`` only guards the dict; the
        # per-id lock is held across the actual spawn and is dropped
        # once the sidecar is published (or the spawn fails). Different
        # binaries spawn in parallel as before.
        self._locks_lock = threading.Lock()
        self._spawn_locks: dict[str, threading.Lock] = {}

    # --- public surface ------------------------------------------------------

    def open(
        self,
        path: str | os.PathLike[str],
        *,
        fresh: bool = False,
        timeout: float | None = None,
    ) -> OpenResult:
        """Spawn (or reuse) a headless IDA for *path* and return when ready.

        Re-uses an already-running session whose id matches *path* (which
        happens when ``open_file`` is called twice in a row, or two
        agents target the same binary concurrently). When ``fresh=True``
        the existing IDB artifacts are deleted first so IDA reanalyses
        from scratch -- but we still refuse to fight a live session,
        returning an error instead of killing it.

        Concurrent calls for the *same* binary are serialised by a
        per-session-id lock: the second caller waits for the first to
        publish its sidecar (or fail), then takes the reuse path. This
        closes the otherwise unavoidable check-then-spawn TOCTOU window.
        """
        timeout_s = timeout if timeout is not None else self._startup_timeout
        deadline = time.monotonic() + timeout_s
        binary = session.normalize_input_file(path)
        if not binary.is_file():
            raise FileNotFoundError(f"Input file not found: {binary}")

        session_id = session.derive_session_id(str(binary))

        with self._spawn_lock(session_id):
            existing = session.get(session_id)
            if existing is not None:
                if fresh:
                    raise RuntimeError(
                        f"Session {session_id} is already running (PID {existing.pid}); "
                        "close it before requesting a fresh analysis."
                    )
                return OpenResult(
                    session=existing,
                    log_file=str(_ida_log_path(session_id)),
                    reused=True,
                )

            if fresh:
                removed = delete_idb_artifacts(binary)
                if removed:
                    logger.info("removed %d stale IDB artefact(s) for %s", len(removed), binary)

            idat_path = locate_idat()
            bootstrap = _bootstrap_script()
            ida_log = _ida_log_path(session_id)
            stdio_log = _stdio_log_path(session_id)

            # IDA's ``-S`` argument bundles the script path + its argv into a
            # single token (split internally on whitespace). We assemble it
            # ourselves so spaces / quoting are explicit.
            script_arg = f"{bootstrap} --session-id {shlex.quote(session_id)}"
            argv = [
                str(idat_path),
                "-A",
                f"-S{script_arg}",
                f"-L{ida_log}",
                str(binary),
            ]
            env = self._spawn_env()
            cwd = self._spawn_cwd(binary)

            logger.info("spawning idat: %s (cwd=%s)", " ".join(argv), cwd)
            with stdio_log.open("wb") as stdio:
                try:
                    proc = subprocess.Popen(
                        argv,
                        stdout=stdio,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        env=env,
                        cwd=cwd,
                        close_fds=True,
                    )
                except OSError as exc:
                    raise RuntimeError(f"failed to start idat at {idat_path}: {exc}") from exc

            try:
                info = self._await_sidecar(
                    session_id,
                    proc,
                    deadline,
                    timeout_s,
                    stdio_log,
                    ida_log,
                )
            except BaseException:
                # ``_await_sidecar`` already kills the process on timeout;
                # the early-exit path leaves it terminated but unwaited.
                # Reap unconditionally so the Popen handle never lingers
                # (CPython warns at GC otherwise) and the OS releases pid
                # resources promptly.
                self._best_effort_reap(proc)
                raise
            self._handles[info.pid] = proc
            return OpenResult(session=info, log_file=str(ida_log), reused=False)

    def close(self, session_id: str, *, timeout: float = DEFAULT_CLOSE_TIMEOUT_S) -> bool:
        """Ask the headless IDA for *session_id* to shut down gracefully.

        Returns ``True`` when the sidecar disappears within *timeout*,
        ``False`` when we had to escalate to ``SIGKILL``.
        """
        info = session.get(session_id)
        if info is None:
            raise FileNotFoundError(f"No live session named {session_id!r}")

        # The graceful path differs by platform:
        #
        # * POSIX: ``SIGTERM`` is delivered to the bootstrap's signal
        #   handler, which sets the shutdown event and lets ``main()``
        #   tear everything down cleanly. The kill-switch file is also
        #   touched as a defence-in-depth backup.
        # * Windows: there is no real ``SIGTERM`` -- ``os.kill(pid, 15)``
        #   maps straight to ``TerminateProcess(handle, 15)`` (immediate
        #   hard kill), which is the *opposite* of graceful. The
        #   bootstrap polls the kill-switch file once a second; that's
        #   the only graceful channel we have, so on Windows the file
        #   *is* the request and we skip ``os.kill`` entirely.
        kill_switch.request_shutdown(session_id)
        if sys.platform != "win32":
            self._signal(info.pid, signal.SIGTERM)

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if session.get(session_id) is None:
                kill_switch.cleanup(session_id)
                self._reap(info.pid)
                return True
            time.sleep(self.POLL_INTERVAL_S)

        # Escalate: hard-kill. ``signal.SIGKILL`` is undefined on
        # Windows; ``os.kill`` already maps ``SIGTERM`` to
        # ``TerminateProcess`` so we reuse it as the hard signal there.
        self._signal(info.pid, hard_kill_signal())
        # Best-effort sidecar cleanup; PID-GC would catch it next round
        # but freeing it eagerly avoids a confusing window.
        session.remove(session_id)
        kill_switch.cleanup(session_id)
        self._reap(info.pid)
        return False

    # --- internals -----------------------------------------------------------

    def _spawn_lock(self, session_id: str) -> threading.Lock:
        """Return the per-session-id lock, creating it on first use.

        We never evict entries here: at steady state the dict holds one
        :class:`threading.Lock` per binary the agent ever asked us to
        open, which is bounded by the workflow and dwarfed by IDA's own
        memory footprint. Eviction would have to coordinate with
        threads currently waiting on the lock, which is more complexity
        than the savings justify.
        """
        with self._locks_lock:
            lock = self._spawn_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._spawn_locks[session_id] = lock
            return lock

    @staticmethod
    def _best_effort_reap(proc: subprocess.Popen[bytes]) -> None:
        """Wait on *proc* without raising; for use on the failure path.

        ``_await_sidecar`` either kills the process explicitly (timeout)
        or observes ``poll() is not None`` (early exit). In both cases
        ``wait()`` returns immediately; we still call it so the Popen's
        internal pipes/handles close and CPython doesn't emit a
        ``ResourceWarning`` when the object eventually gets GC'd.
        """
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.wait(timeout=5.0)

    def _spawn_env(self) -> dict[str, str]:
        """Forward our env, scrubbed of proxy-Python-specific configuration.

        Delegates the actual blocklist + ``PATH`` venv stripping to
        :mod:`.process_env`; this method only injects the package-root
        pointer the bootstrap needs.
        """
        return build_spawn_env(package_root=_package_root())

    def _spawn_cwd(self, binary: Path) -> str:
        """Pick a cwd for the headless ``idat`` that's free of stray ``.venv``.

        Delegates to :func:`.process_env.spawn_cwd_for`; kept as a method
        so subclasses (and tests) can override the policy without monkey-
        patching a free function.
        """
        return spawn_cwd_for(binary)

    def _await_sidecar(
        self,
        session_id: str,
        proc: subprocess.Popen[bytes],
        deadline: float,
        timeout_s: float,
        stdio_log: Path,
        ida_log: Path,
    ) -> SessionInfo:
        """Block until the sidecar appears or the spawn fails.

        Three terminal states:

        * sidecar appears -> success.
        * idat exits before sidecar -> read the tail of both log files
          and surface them in the exception (the LLM gets enough context
          to fix common mistakes -- bad ``IDA_PRO_HOME``, license
          issue, unsupported binary).
        * deadline hits -> raise; the caller is responsible for
          terminating *proc* (see :meth:`_best_effort_reap`).
        """
        while time.monotonic() < deadline:
            info = session.get(session_id)
            if info is not None:
                return info
            if proc.poll() is not None:
                tail = _tail(ida_log) + _tail(stdio_log)
                raise RuntimeError(
                    f"idat exited before publishing the session sidecar "
                    f"(exit code {proc.returncode}). Logs:\n{tail}"
                )
            time.sleep(self.POLL_INTERVAL_S)

        tail = _tail(ida_log) + _tail(stdio_log)
        raise TimeoutError(
            f"idat did not become ready within {timeout_s:.0f}s. "
            f"Logs:\n{tail}"
        )

    def _signal(self, pid: int, sig: int) -> bool:
        """Best-effort ``os.kill`` wrapper.

        Returns ``True`` when the signal was delivered, ``False`` when
        the process is already gone or the platform refused (Windows
        without the right Win32 plumbing).
        """
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as exc:
            logger.warning("kill(%d, %d) failed: %s", pid, sig, exc)
            return False

    def _reap(self, pid: int) -> None:
        """Wait on the recorded ``Popen`` so its handle can be GC'd cleanly.

        Called only once we believe the child has exited (sidecar gone
        or after SIGKILL). Best-effort: if we don't own the handle (e.g.
        spawner was restarted between open and close) we just drop the
        sidecar reference and let init reap.
        """
        proc = self._handles.pop(pid, None)
        if proc is None:
            return
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.wait(timeout=5.0)
