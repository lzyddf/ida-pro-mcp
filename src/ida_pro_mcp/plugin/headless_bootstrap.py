"""In-IDA bootstrap for proxy-spawned ``idat -A`` processes.

This script runs **inside** a headless IDA Pro instance that the proxy CLI
launched via ``idat -A -S"<this-script> --session-id <id>" <binary>``. The
proxy waits for our sidecar to appear in :func:`session.sessions_dir` and
then dispatches JSON-RPC tool calls to the bound port.

Lifecycle:

1. Wait for IDA's auto-analysis to finish (``idc.auto_wait``); without this
   the LLM's first ``decompile_function`` call would race with the
   analyser and return half-baked output.
2. Bind the JSON-RPC HTTP server on an ephemeral port.
3. Install :mod:`plugin.idb_hooks` so cache invalidation flushes whenever
   tools mutate the database.
4. Write the session sidecar so the proxy can discover and route to us.
5. Run the JSON-RPC HTTP server's ``serve_forever`` loop on the IDA main
   thread so ``@idaread`` / ``@idawrite`` handlers short-circuit
   ``execute_sync`` to a direct call -- there is no Qt loop in ``idat -A``
   to drain the queue otherwise. Signal handlers (SIGTERM, SIGINT) and a
   Windows-friendly kill-switch watcher both call :meth:`Server.stop` to
   wake the loop. The kill-switch path is a sentinel file under
   ``base_dir() / "kill" / <session_id>``; see
   :func:`_install_kill_switch_watcher` and :mod:`ida_pro_mcp.spawner`.
6. On wake-up, remove the sidecar, stop the server, and ``ida_pro.qexit``.

Failure modes:

* Bad ``--session-id`` (empty / missing): we abort before binding so the
  proxy times out cleanly with no orphan port.
* Bind failure: :meth:`Server.bind` raises; we log to IDA's output window
  and ``qexit(1)`` so ``Popen.wait()`` on the proxy side observes a
  non-zero status.
* Anything raised below: best-effort sidecar removal in ``finally``,
  then ``qexit(1)``.

This file deliberately uses no relative imports inside ``ida_pro_mcp``
besides ``session`` -- IDA's batch invocation runs us before the parent
package's ``__init__`` has been loaded by anyone, and the import path is
arranged by the spawner via ``IDA_PRO_MCP_PACKAGE_ROOT``.
"""
from __future__ import annotations

import argparse
import atexit
import logging
import os
import signal
import sys
import threading

# The spawner sets this so we can ``import ida_pro_mcp`` without relying on
# IDA's ``site-packages`` knowing about the project. Stripping the
# environment variable in the parent doesn't break us either: ``import
# ida_pro_mcp`` still works if it was installed conventionally.
_PACKAGE_ROOT = os.environ.get("IDA_PRO_MCP_PACKAGE_ROOT")
if _PACKAGE_ROOT and _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

import ida_pro
import idc

from ida_pro_mcp.plugin import idb_hooks, session
from ida_pro_mcp.plugin.http_server import Server
from ida_pro_mcp.plugin.tools import load_tools
from ida_pro_mcp.spawner import kill_switch

_log = logging.getLogger("ida_pro_mcp.headless")
if not _log.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("[MCP-headless] %(message)s"))
    _log.addHandler(_handler)
    _log.setLevel(logging.INFO)
    _log.propagate = False


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ida_pro_mcp.headless_bootstrap",
        description="Boot the IDA-side MCP server in headless mode.",
    )
    parser.add_argument(
        "--session-id",
        required=True,
        help="Session id chosen by the proxy; must match the sidecar filename.",
    )
    return parser.parse_args(argv)


def _install_kill_switch_watcher(
    session_id: str,
    event: threading.Event,
    server: Server,
) -> None:
    """Spawn a daemon thread that wakes the main loop on kill-switch.

    The thread polls for the kill-switch file (a Windows-friendly
    alternative to SIGTERM, which on Windows hard-kills rather than
    delivering a handler-able signal) and, when observed, sets the
    shutdown event *and* asks the server to exit its ``serve_forever``
    loop. Calling :meth:`Server.stop` from this thread is safe and is
    in fact the only way to wake the foreground server in headless
    mode -- the event by itself doesn't unblock the main thread, which
    is sitting inside ``serve_forever``.

    Polling at 1Hz keeps the steady-state cost invisible while bounding
    worst-case shutdown latency. The kill-switch path scheme is shared
    with :mod:`ida_pro_mcp.spawner.kill_switch` (the writer side) so
    both ends agree on the on-disk contract without duplicating it.
    """
    target = kill_switch.kill_switch_path(session_id)
    target.parent.mkdir(parents=True, exist_ok=True)

    def _watch() -> None:
        while not event.is_set():
            if target.exists():
                _log.info("kill switch observed; shutting down")
                event.set()
                _request_shutdown(server)
                return
            event.wait(timeout=1.0)

    threading.Thread(target=_watch, name="mcp-kill-switch", daemon=True).start()


def _install_signal_handlers(event: threading.Event, server: Server) -> None:
    """Wake :data:`event` on SIGTERM/SIGINT and ask *server* to stop.

    Setting the event alone does not unblock the headless main thread,
    which is sitting inside :meth:`Server.serve_in_current_thread`;
    handlers must call :meth:`Server.stop` so ``serve_forever`` returns
    on its next ``select`` poll. Calling ``stop`` from a signal handler
    is safe because it just calls ``HTTPServer.shutdown`` (a thread-safe
    flag flip).

    Skipped for signals the platform doesn't support (Windows lacks a
    usable ``SIGTERM`` handler when the process is killed; we rely on
    the kill switch in that case).
    """
    def _handler(_signum: int, _frame: object) -> None:
        event.set()
        _request_shutdown(server)

    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (OSError, ValueError):
            # ValueError on non-main thread or unsupported platform.
            _log.debug("could not install handler for %s", name)


def _request_shutdown(server: Server) -> None:
    """Best-effort :meth:`Server.stop` from a signal / watcher thread.

    Wraps the call in defensive logging so a teardown error in one
    handler can't escape and crash the daemon thread that called us.
    Idempotent because :meth:`Server.stop` itself tolerates an already-
    shut-down server (``self._server`` becomes ``None``).
    """
    try:
        server.stop()
    except Exception:
        # Never let teardown wedge the wakeup path; just log and move on.
        _log.exception("server.stop from shutdown handler raised")


def _cleanup(session_id: str, server: Server, sidecar_written: bool) -> None:
    """Idempotent teardown invoked from both ``finally`` and ``atexit``."""
    if sidecar_written:
        try:
            session.remove(session_id)
        except OSError as exc:
            _log.debug("sidecar removal failed: %s", exc)
    try:
        idb_hooks.uninstall()
    except Exception as exc:
        _log.debug("idb_hooks.uninstall failed: %s", exc)
    try:
        server.stop()
    except Exception as exc:
        _log.debug("server.stop failed: %s", exc)


class _BootstrapError(RuntimeError):
    """Raised by helpers when the bootstrap cannot proceed.

    Treated as a hard failure by :func:`main` -- it stops *server* (if any
    was bound), logs the message, and exits IDA with status 1 so the
    proxy's ``Popen.wait`` observes a non-zero status.
    """


def _wait_for_analysis() -> None:
    """Block until IDA's auto-analysis has stabilised.

    Skipping this races the analyser: the LLM's first ``decompile_function``
    call would hit half-baked function boundaries / type info. ``auto_wait``
    is the canonical "ready to query" gate Hex-Rays recommends for batch
    scripts, so we use it verbatim.
    """
    _log.info("auto_wait: waiting for analysis to complete")
    idc.auto_wait()


def _bind_server() -> Server:
    """Construct + bind a :class:`Server`; raise on failure.

    The server is single-threaded by design: ``idat -A`` runs without a
    Qt event loop, so a worker-thread server would deadlock the moment
    any ``@idaread`` / ``@idawrite`` handler trampolined through
    ``execute_sync`` (the main thread, blocked in ``serve_forever``,
    would never service the queued callback). Running the request loop
    on the IDA main thread instead lets ``execute_sync`` short-circuit
    to a direct call and the deadlock disappears.
    """
    server = Server()
    try:
        server.bind()
    except OSError as exc:
        raise _BootstrapError(f"failed to bind RPC server: {exc}") from exc
    if server.bound_port is None:
        # Defensive: ``bind`` should have either raised or set the port,
        # but if a future refactor leaves it unset the proxy would just
        # spin waiting for a sidecar with port 0. Fail loud instead.
        server.stop()
        raise _BootstrapError("server reported no bound port after bind")
    return server


def _build_session_info(session_id: str, port: int) -> session.SessionInfo:
    """Collect IDA-side state into a :class:`SessionInfo` payload.

    The ``input_file`` check is the most common failure: ``idat -A`` was
    invoked without a target binary (e.g. a typo'd path the loader
    silently ignored). Surfacing this as ``_BootstrapError`` is friendlier
    than an empty sidecar that then makes the proxy's discovery code
    crash on the next dispatch.
    """
    input_file = idc.get_input_file_path() or ""
    if not input_file:
        raise _BootstrapError("no input file loaded; cannot publish sidecar")
    idb_path = idc.get_idb_path() or input_file
    return session.make_info(
        session_id=session_id,
        host="127.0.0.1",
        port=port,
        pid=os.getpid(),
        idb_path=idb_path,
        input_file=input_file,
    )


def _publish_sidecar(info: session.SessionInfo) -> None:
    """Persist *info* so the proxy's :class:`SessionRegistry` discovers us."""
    try:
        session.write(info)
    except OSError as exc:
        raise _BootstrapError(f"failed to write session sidecar: {exc}") from exc


def _install_shutdown_hooks(
    shutdown: threading.Event,
    server: Server,
    session_id: str,
) -> None:
    """Wire up every wake-up source for the foreground :func:`serve_in_current_thread`.

    Both signal handlers and the kill-switch watcher arrive on *non-main*
    threads (Windows in particular delivers signals on a dedicated thread).
    They wake the main loop by calling :meth:`Server.stop` which in turn
    calls ``HTTPServer.shutdown`` -- ``serve_forever`` notices the request
    on its next ``select`` poll and returns, letting :func:`main`'s
    ``finally`` run cleanup.

    ``atexit`` is the safety net for the case where IDA tears the process
    down through some path we didn't intercept (a Qt-side abort, e.g.).
    """
    _install_signal_handlers(shutdown, server)
    _install_kill_switch_watcher(session_id, shutdown, server)
    atexit.register(_cleanup, session_id, server, True)


def _abort(server: Server | None, message: str) -> None:
    """Log *message*, best-effort stop *server*, then ``qexit(1)``.

    Centralises the early-exit pattern so :func:`main` reads as a flat
    sequence of "do this thing or abort" steps without duplicating the
    log + stop + qexit triplet at every failure site.
    """
    _log.error("%s", message)
    if server is not None:
        try:
            server.stop()
        except Exception:
            # Best-effort: if cleanup itself raises, the qexit(1) below
            # is still the right outcome -- we don't want to mask the
            # original error with a teardown failure.
            _log.debug("server.stop during abort raised", exc_info=True)
    ida_pro.qexit(1)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(idc.ARGV[1:] if argv is None else argv)
    session_id: str = args.session_id

    load_tools()
    _wait_for_analysis()

    try:
        server = _bind_server()
    except _BootstrapError as exc:
        _abort(None, str(exc))
        return

    idb_hooks.install()

    try:
        info = _build_session_info(session_id, server.bound_port)
        _publish_sidecar(info)
    except _BootstrapError as exc:
        _abort(server, str(exc))
        return

    shutdown = threading.Event()
    _install_shutdown_hooks(shutdown, server, session_id)

    _log.info("session %s ready on port %d", session_id, server.bound_port)
    try:
        # Run the HTTP request loop on the IDA main thread. Each handler
        # runs inline here, so ``@idaread`` / ``@idawrite`` decorated
        # tools see ``execute_sync`` short-circuit to a direct call --
        # no Qt loop, no queue, no deadlock. Returns when ``server.stop``
        # fires from the watcher / signal-handler side.
        server.serve_in_current_thread()
    finally:
        kill_switch.cleanup(session_id)
        _cleanup(session_id, server, sidecar_written=True)
        ida_pro.qexit(0)


if __name__ == "__main__":
    main()
