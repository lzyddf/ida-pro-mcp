"""Cross-process shutdown protocol between the spawner and the headless bootstrap.

On POSIX the spawner sends ``SIGTERM`` and the bootstrap's signal handler
takes care of an orderly shutdown. On Windows there is no real ``SIGTERM`` --
``os.kill(pid, 15)`` maps to ``TerminateProcess(handle, 15)`` (immediate hard
kill), the *opposite* of graceful. So the spawner instead writes a sentinel
file under ``base_dir() / "kill" / <session_id>``; the headless bootstrap
polls that path once a second and shuts down cleanly when it observes it.

Centralising the two ends of the protocol here means the path scheme cannot
drift between writer (spawner) and reader (headless bootstrap).
"""
from __future__ import annotations

import contextlib
import logging
from pathlib import Path

from ..plugin import session

logger = logging.getLogger(__name__)


def kill_switch_dir() -> Path:
    """Return ``~/.ida-pro-mcp-headless/kill``, creating it on first use."""
    path = session.base_dir() / "kill"
    path.mkdir(parents=True, exist_ok=True)
    return path


def kill_switch_path(session_id: str) -> Path:
    """The sentinel file the spawner writes / the bootstrap watches for *session_id*."""
    return kill_switch_dir() / session_id


def request_shutdown(session_id: str) -> None:
    """Write the kill-switch sentinel; idempotent and never raises."""
    target = kill_switch_path(session_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        target.touch()


def cleanup(session_id: str) -> None:
    """Remove the sentinel; called by both ends after a graceful shutdown."""
    target = kill_switch_path(session_id)
    try:
        target.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("failed to remove kill switch %s: %s", target, exc)
