"""Helpers for the ``fresh=True`` reanalysis switch in :meth:`Spawner.open`.

When the LLM asks for a fresh analysis we delete every IDB component IDA
might have left next to the binary so the next ``idat -A`` invocation
re-analyses from scratch instead of reusing the stale database.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# Files we must clean up when ``fresh=True``: every IDB component IDA might
# leave behind. Keeping the list here (rather than inside ``Spawner``) means
# adding a new suffix only touches one place.
_IDB_SUFFIXES: tuple[str, ...] = (
    ".i64", ".idb", ".id0", ".id1", ".id2", ".nam", ".til",
)


def delete_idb_artifacts(input_file: Path) -> list[Path]:
    """Remove every IDB component IDA might have left next to *input_file*.

    Returns the list of paths actually removed so the caller can include
    it in the ``open_file`` response (handy for the agent to confirm the
    refresh actually happened).
    """
    removed: list[Path] = []
    parent = input_file.parent
    base_with_ext = input_file.name
    base_without_ext = input_file.stem
    for suffix in _IDB_SUFFIXES:
        for candidate in (parent / f"{base_with_ext}{suffix}", parent / f"{base_without_ext}{suffix}"):
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.debug("could not delete %s: %s", candidate, exc)
                continue
            removed.append(candidate)
    return removed
