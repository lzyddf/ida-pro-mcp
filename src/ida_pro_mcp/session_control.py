"""Programmatic shutdown of headless IDA sessions.

``close_file`` is an MCP tool: it only runs when the language model chooses
to call it, so an agent that finishes an analysis and moves on can leave its
``idat`` process (and the IDB lock) behind. This module backs the
``session close`` CLI subcommand, which lets the *user* reclaim those
processes without going through the model.

The shutdown primitive already exists -- :meth:`Spawner.close` talks to the
headless bootstrap through the kill-switch file and the sidecar registry, so
it works from any process, including a fresh CLI invocation that never
spawned the IDA. This module only adds selection and batch error aggregation
on top and deliberately does not re-implement any shutdown logic.

Batch semantics: one failing session must not abort the rest, so every
target is attempted and each outcome is reported independently. The caller
turns the returned list into an exit code.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from .plugin import session
from .plugin.session import SessionInfo
from .spawner import Spawner

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CloseOutcome:
    """Result of asking one session to stop.

    ``graceful`` is ``None`` when no shutdown was attempted (the session was
    already gone, or the attempt raised before reaching IDA). It is ``True``
    when IDA exited on its own and ``False`` when the spawner had to escalate
    to a hard kill.
    """

    session_id: str
    closed: bool
    graceful: bool | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "closed": self.closed,
            "graceful": self.graceful,
            "error": self.error,
        }


def live_sessions() -> list[SessionInfo]:
    """Return every live session, oldest first.

    Delegates to :func:`ida_pro_mcp.plugin.session.list_all`, which already
    filters out sidecars whose PID is gone, so stale files are never offered
    as close targets.
    """
    return session.list_all()


def live_session_ids() -> list[str]:
    """Return the ids of every live session, oldest first."""
    return [info.session_id for info in live_sessions()]


def resolve_targets(
    *,
    session_ids: Sequence[str] = (),
    paths: Sequence[str] = (),
) -> list[str]:
    """Map explicit ids and binary paths to a deduplicated session id list.

    Paths are resolved through :func:`session.session_id_for_path`, which
    applies the same normalisation ``open_file`` uses, so a user can name a
    session by the binary they opened instead of the derived hash id.
    Duplicates (the same session named twice, or by both id and path) are
    collapsed while preserving first-seen order.
    """
    candidates = list(session_ids)
    candidates.extend(session.session_id_for_path(path) for path in paths)

    ordered: list[str] = []
    seen: set[str] = set()
    for session_id in candidates:
        if session_id not in seen:
            seen.add(session_id)
            ordered.append(session_id)
    return ordered


def close_sessions(
    session_ids: Sequence[str],
    *,
    timeout: float | None = None,
    spawner: Spawner | None = None,
) -> list[CloseOutcome]:
    """Close each id in *session_ids*, reporting one outcome per session.

    *spawner* is injectable for tests. Production callers get a fresh
    :class:`Spawner`: constructing one is cheap and it holds no state that
    matters here, because the sidecar registry -- not the spawner -- is the
    source of truth for "is this session alive?".
    """
    spawner = spawner or Spawner()
    close_kwargs = {} if timeout is None else {"timeout": timeout}

    outcomes: list[CloseOutcome] = []
    for session_id in session_ids:
        try:
            graceful = spawner.close(session_id, **close_kwargs)
        except Exception as exc:
            # Batch isolation: a bad target must not prevent the remaining
            # sessions from being closed, so every failure is recorded
            # instead of propagated.
            logger.debug("closing session %s failed: %s", session_id, exc)
            outcomes.append(CloseOutcome(session_id, closed=False, error=str(exc)))
        else:
            outcomes.append(CloseOutcome(session_id, closed=True, graceful=graceful))
    return outcomes
