"""Thin wrappers around ``schtasks.exe`` invocations.

Each helper handles the success path *and* the platform-specific
"task does not exist" / "not currently running" cases so the orchestrator
in :mod:`.. ` can stay declarative. Errors that aren't part of the
expected idempotent contract bubble up as :class:`RuntimeError` with the
schtasks output attached -- that's what the CLI surfaces to the user.
"""
from __future__ import annotations

import subprocess

from .paths import TASK_NAME, _task_xml_path


def _register_task() -> None:
    """``schtasks /create /xml ... /f`` -- replaces any existing definition."""
    proc = subprocess.run(
        ["schtasks", "/create", "/tn", TASK_NAME, "/xml", str(_task_xml_path()), "/f"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"schtasks /create failed: {msg}")


def _unregister_task() -> str:
    """``schtasks /delete /f`` -- returns ``"deleted" | "absent"``.

    "absent" lets ``--service uninstall`` stay idempotent: re-running the
    uninstaller after a previous successful uninstall is a no-op rather
    than an error the user has to ignore.
    """
    proc = subprocess.run(
        ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return "deleted"
    combined = (proc.stderr + proc.stdout).lower()
    if "cannot find" in combined or "does not exist" in combined:
        return "absent"
    msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
    raise RuntimeError(f"schtasks /delete failed: {msg}")


def _start_task() -> None:
    """``schtasks /run`` -- kicks the task off immediately on install."""
    proc = subprocess.run(
        ["schtasks", "/run", "/tn", TASK_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"schtasks /run failed: {msg}")


def _end_task() -> str:
    """Best-effort ``schtasks /end`` so ``/delete`` doesn't race a live process.

    Returns a status string instead of raising so the orchestrator can
    log what happened without forcing the uninstall path to handle three
    different exception types (absent, already-stopped, hard failure).
    """
    proc = subprocess.run(
        ["schtasks", "/end", "/tn", TASK_NAME],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return "stopped"
    combined = (proc.stderr + proc.stdout).lower()
    if "cannot find" in combined or "does not exist" in combined:
        return "absent"
    if "is not currently running" in combined or "not running" in combined:
        return "already-stopped"
    return f"end-failed: {(proc.stderr or proc.stdout).strip() or proc.returncode}"


def _query_task() -> tuple[bool, dict[str, str]]:
    """Run ``schtasks /query /fo LIST /v`` and return ``(installed, fields)``.

    ``installed`` is ``False`` when the task isn't registered; ``fields``
    is the parsed key/value mapping otherwise. Splitting the booleanity
    out keeps the orchestrator from re-checking ``returncode``.
    """
    proc = subprocess.run(
        ["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False, {}
    return True, _parse_schtasks_list(proc.stdout)


def _parse_schtasks_list(stdout: str) -> dict[str, str]:
    """Turn ``schtasks /fo LIST /v`` output into a key/value dict.

    Output is one ``Key: Value`` per line with the *first* colon being the
    separator. Lines without a colon (blank section breaks, the trailing
    ``HostName:`` line) are dropped. We don't try to coerce types -- the
    caller picks specific fields and converts as needed.
    """
    info: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key:
            info[key] = value
    return info
