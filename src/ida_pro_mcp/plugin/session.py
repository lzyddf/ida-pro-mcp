"""Sidecar registry for per-IDA MCP sessions.

Each headless ``idat -A`` instance the proxy spawns advertises itself by
writing one JSON file under :func:`sessions_dir` (``~/.ida-pro-mcp-headless/sessions/
<id>.json``). The proxy reads those files to discover which IDAs are
currently reachable and on which ephemeral port; :mod:`.headless_bootstrap`
writes the sidecar after ``idc.auto_wait()`` returns and the server is
up.

Design notes:

* All IO uses pure stdlib so this module is importable from the proxy
  process (which never imports the IDA SDK) as well as from inside IDA.
* :func:`derive_session_id` is deterministic on ``input_file``, so
  re-opening the same binary across IDA restarts re-uses the same
  session id -- callers that hard-code the id in scripts keep working.
* :func:`list_all` filters out *stale* entries (PID gone, JSON malformed)
  so callers don't need their own cleanup loop. Removing the file is
  best-effort -- a future write at the same id will overwrite anyway.
* The on-disk layout is intentionally trivial JSON. We never embed
  secrets here; the contents are equivalent to ``ps aux | grep idat``
  observability.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path

from ._pid_check import is_pid_alive

logger = logging.getLogger(__name__)


# Single root for both the sidecar dir and (later) headless launch logs.
# Lives in the user's home so it survives reboots and is per-user; we
# explicitly do *not* use ``/tmp`` because background ``tmpwatch``-style
# cleaners on some Linux distros would yank live sidecars out from under
# us.
def base_dir() -> Path:
    """Return the per-user root (``~/.ida-pro-mcp-headless``); created on first use."""
    root = Path.home() / ".ida-pro-mcp-headless"
    root.mkdir(parents=True, exist_ok=True)
    return root


def sessions_dir() -> Path:
    """Return the directory holding ``<session_id>.json`` files."""
    path = base_dir() / "sessions"
    path.mkdir(parents=True, exist_ok=True)
    return path


# Allowed in derived ids (anything else collapsed to ``-``). Hex digest is
# always appended, so collisions on the human-readable prefix are harmless.
_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(text: str) -> str:
    cleaned = _SLUG_RE.sub("-", text).strip("-")
    return cleaned or "ida"


def normalize_input_file(path: str | os.PathLike[str]) -> Path:
    """Return the canonical form of *path* used for session identity.

    :meth:`Spawner.open` and the ``session close --path`` CLI both map a
    user-supplied binary path to a session id, so the normalisation has to
    live in exactly one place: any difference (relative vs absolute, ``~``,
    symlinks) changes the sha1 input and therefore the derived id, which
    would make the two callers disagree about which session a path names.
    """
    return Path(os.fspath(path)).expanduser().resolve()


def session_id_for_path(path: str | os.PathLike[str]) -> str:
    """Return the session id that opening *path* would produce.

    Convenience wrapper over :func:`normalize_input_file` +
    :func:`derive_session_id` for callers that only hold a raw path.
    """
    return derive_session_id(str(normalize_input_file(path)))


def derive_session_id(input_file: str | os.PathLike[str]) -> str:
    """Compute the session id for the analysed *input_file*.

    Format: ``<sanitized basename>-<sha1(input_file)[:8]>``. The hash
    makes the id stable across IDA restarts on the same binary, while
    the prefix keeps it human-readable when listed.

    *input_file* must be the original binary path, **not** the ``.i64``.
    Re-issuing :func:`Spawner.open` against the same binary therefore
    discovers the existing sidecar and re-uses it instead of spawning a
    second IDA.
    """
    raw = os.fspath(input_file)
    basename = os.path.basename(raw) or "ida"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
    return f"{_slug(basename)}-{digest}"


@dataclass(frozen=True)
class SessionInfo:
    """Public on-disk shape of a sidecar entry.

    Order of fields determines the JSON key order; keep it human-friendly
    (``session_id`` first) for grep-ability when users open the file
    directly.
    """

    session_id: str
    host: str
    port: int
    pid: int
    idb_path: str
    input_file: str
    created_at: float   # seconds since epoch (UTC); float, not ISO, to keep
                        # round-tripping cheap and dependency-free

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SessionInfo:
        return cls(
            session_id=str(data["session_id"]),
            host=str(data["host"]),
            port=int(data["port"]),  # type: ignore[arg-type]
            pid=int(data["pid"]),  # type: ignore[arg-type]
            idb_path=str(data["idb_path"]),
            input_file=str(data["input_file"]),
            created_at=float(data["created_at"]),  # type: ignore[arg-type]
        )


def _sidecar_path(session_id: str) -> Path:
    return sessions_dir() / f"{session_id}.json"


def write(info: SessionInfo) -> Path:
    """Atomically write *info* to its sidecar file; return the path.

    Uses a tempfile-and-rename so a partially-written file is never
    observable. Any pre-existing entry with the same id is overwritten;
    re-opening the same IDB after a crash should *not* require manual
    cleanup, even if the previous IDA died without removing its sidecar.
    """
    target = _sidecar_path(info.session_id)
    payload = json.dumps(info.to_dict(), indent=2).encode("utf-8")

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{info.session_id}.", suffix=".json", dir=sessions_dir()
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(tmp_path, target)
    except Exception:
        # Best-effort cleanup of the temp file if rename failed.
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_path)
        raise
    return target


def remove(session_id: str) -> None:
    """Delete the sidecar for *session_id*; missing files are not an error."""
    try:
        _sidecar_path(session_id).unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("failed to remove session sidecar %s: %s", session_id, exc)


def get(session_id: str) -> SessionInfo | None:
    """Return the live :class:`SessionInfo` for *session_id*, or ``None``.

    "Live" means the JSON parses *and* the recorded PID is still
    running. Stale files (writer crashed) return ``None``; callers that
    want the raw payload should read the file directly.
    """
    path = _sidecar_path(session_id)
    info = _load(path)
    if info is None:
        return None
    if not is_pid_alive(info.pid):
        # Best-effort GC -- next ``list_all`` won't have to filter it again.
        remove(session_id)
        return None
    return info


def list_all() -> list[SessionInfo]:
    """Return every live session known on disk, sorted by ``created_at``.

    Sidecar files whose JSON is malformed or whose PID is no longer
    alive are silently dropped (and removed) so callers can iterate
    without writing their own GC.
    """
    live: list[SessionInfo] = []
    for path in _iter_sidecars():
        info = _load(path)
        if info is None:
            _drop_stale(path)
            continue
        if not is_pid_alive(info.pid):
            _drop_stale(path)
            continue
        live.append(info)
    live.sort(key=lambda s: s.created_at)
    return live


def _iter_sidecars() -> Iterator[Path]:
    try:
        children = sessions_dir().iterdir()
    except FileNotFoundError:
        return iter(())
    return (child for child in children if child.is_file() and child.suffix == ".json")


def _load(path: Path) -> SessionInfo | None:
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("session sidecar %s unreadable: %s", path, exc)
        return None
    try:
        return SessionInfo.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        logger.debug("session sidecar %s malformed: %s", path, exc)
        return None


def _drop_stale(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.debug("failed to drop stale sidecar %s: %s", path, exc)


def make_info(
    *,
    session_id: str,
    host: str,
    port: int,
    pid: int,
    idb_path: str,
    input_file: str,
    created_at: float | None = None,
) -> SessionInfo:
    """Convenience constructor that fills in ``created_at`` if missing."""
    return SessionInfo(
        session_id=session_id,
        host=host,
        port=port,
        pid=pid,
        idb_path=idb_path,
        input_file=input_file,
        created_at=time.time() if created_at is None else created_at,
    )
