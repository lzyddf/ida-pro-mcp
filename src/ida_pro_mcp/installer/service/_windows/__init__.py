"""Windows Scheduled Task backend for ``ida-pro-mcp-headless service``.

We model "auto-start at login + restart on crash" as a single per-user
Scheduled Task because:

* It needs no admin (a *user* task with ``InteractiveToken`` runs as the
  triggering user, which is the only account that can see IDA's per-user
  license under ``%APPDATA%/Hex-Rays/``).
* A small Python supervisor restarts the proxy without requiring a visible
  command-shell window.
* Built into every modern Windows; no NSSM / WinSW dependency.

This package is a thin orchestrator: each concern lives in its own
submodule so the install / uninstall / status flows here read like a
table of contents:

* :mod:`.paths` -- on-disk locations + the canonical ``TASK_NAME``.
* :mod:`.service_spec` -- validate and persist runner configuration.
* :mod:`.pythonw` / :mod:`.runner` -- launch the proxy without a console.
* :mod:`.task_xml` -- render and persist the Scheduled Task XML.
* :mod:`.schtasks` -- thin wrappers around ``schtasks.exe`` invocations.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from typing import Any

from ....runtime_args import HTTPTransport
from ....spawner.locator import IDA_HOME_ENV_VAR, locate_idat_in_home
from ...config import _IDA_HOME_PLACEHOLDER, _resolve_ida_home
from ...proxy_python import get_python_executable
from .health import (
    listener_is_reachable,
    probe_host,
    wait_for_listener,
    wait_for_listener_to_close,
)
from .paths import (
    TASK_NAME,
    _config_path,
    _legacy_wrapper_path,
    _service_dir,
    _stderr_log,
    _stdout_log,
    _task_xml_path,
)
from .pythonw import find_windowed_python
from .schtasks import (
    _end_task,
    _query_task,
    _register_task,
    _start_task,
    _unregister_task,
)
from .service_spec import ServiceSpec
from .task_xml import _write_task_xml

__all__ = ["TASK_NAME", "install", "status", "uninstall"]

_RUNNER_MODULE = "ida_pro_mcp.installer.service._windows.runner"


def install(
    *,
    transport: HTTPTransport,
    host: str,
    port: int,
    unsafe: bool,
    ida_home: str | None,
) -> dict[str, Any]:
    """Render the config + XML, then replace, start, and verify the task."""
    service_dir = _service_dir()
    service_dir.mkdir(parents=True, exist_ok=True)

    home = _pick_ida_home(ida_home)
    console_python = get_python_executable()
    windowed_python = find_windowed_python(console_python)
    spec = ServiceSpec(
        ida_home=home,
        transport=transport,
        host=host,
        port=port,
        unsafe=unsafe,
    )
    spec.write(_config_path())
    runner_arguments = subprocess.list2cmdline(
        ["-m", _RUNNER_MODULE, "--config", str(_config_path())]
    )
    _write_task_xml(
        command=windowed_python,
        arguments=runner_arguments,
        working_directory=service_dir,
    )

    # Re-installation is an in-place update. Stop the previous definition and
    # prove its listener is gone so a stale/manual process cannot make the new
    # task look healthy while it is actually failing with an address conflict.
    _end_task()
    wait_for_listener_to_close(host, port)
    _register_task()
    _start_task()
    wait_for_listener(host, port)
    _legacy_wrapper_path().unlink(missing_ok=True)

    info = {
        "task_name": TASK_NAME,
        "runner": windowed_python,
        "config": str(_config_path()),
        "task_xml": str(_task_xml_path()),
        "stdout_log": str(_stdout_log()),
        "stderr_log": str(_stderr_log()),
        "ida_home": home,
        "bind_url": spec.endpoint_url(),
        "url": spec.endpoint_url(host=probe_host(host)),
    }
    if home == _IDA_HOME_PLACEHOLDER:
        # The service still starts -- read-only tools work fine without IDA --
        # but ``open_file`` will refuse to spawn a new IDA. Surface this loudly
        # so the user knows what to fix and how.
        print(
            f"[WARNING] {IDA_HOME_ENV_VAR} is unset and --ida-home was not given; the "
            f"service config carries the placeholder ({_IDA_HOME_PLACEHOLDER!r}). The "
            "service will run, but `open_file` will fail until you re-run "
            "`service install --ida-home <path-to-IDA-install-dir>`.",
            file=sys.stderr,
        )
    endpoint_lines = (
        f"     Bind:       {info['bind_url']}\n"
        f"     Local URL:  {info['url']}\n"
        if info["bind_url"] != info["url"]
        else f"     URL:        {info['url']}\n"
    )
    print(
        f"[OK] Scheduled Task '{TASK_NAME}' registered and started.\n"
        f"{endpoint_lines}"
        f"     Runner:     {info['runner']}\n"
        f"     Config:     {info['config']}\n"
        f"     Logs:       {info['stdout_log']}\n"
        f"                 {info['stderr_log']}\n"
        f"     Inspect:    schtasks /query /tn {TASK_NAME} /fo LIST /v\n"
        f"     Uninstall:  ida-pro-mcp-headless service uninstall"
    )
    return info


def uninstall() -> dict[str, Any]:
    """Stop the task, unregister it, and remove its config and logs."""
    try:
        spec = ServiceSpec.read(_config_path())
    except ValueError:
        spec = None
    end_result = _end_task()
    if spec is not None and end_result == "stopped":
        wait_for_listener_to_close(spec.host, spec.port)
    delete_result = _unregister_task()

    service_dir = _service_dir()
    existed = service_dir.exists()
    if existed:
        shutil.rmtree(service_dir)
    removed = existed

    print(
        f"[OK] Scheduled Task '{TASK_NAME}' removed.\n"
        f"     Stop:       {end_result}\n"
        f"     Delete:     {delete_result}\n"
        f"     Cleared:    {service_dir if removed else '(nothing to remove)'}"
    )
    return {
        "task_name": TASK_NAME,
        "ended": end_result,
        "deleted": delete_result,
        "service_dir_removed": removed,
    }


def status() -> dict[str, Any]:
    """Run ``schtasks /query`` and assemble a structured status dict."""
    installed, info = _query_task()
    if not installed:
        return {"installed": False, "task_name": TASK_NAME}

    result: dict[str, Any] = {
        "installed": True,
        "task_name": TASK_NAME,
        "status": info.get("Status"),
        "last_run_time": info.get("Last Run Time"),
        "last_result": info.get("Last Result"),
        "next_run_time": info.get("Next Run Time"),
        "task_to_run": info.get("Task To Run"),
        "config": str(_config_path()),
        "task_xml": str(_task_xml_path()),
        "stdout_log": str(_stdout_log()),
        "stderr_log": str(_stderr_log()),
    }
    try:
        spec = ServiceSpec.read(_config_path())
    except ValueError as exc:
        result["config_error"] = str(exc)
    else:
        result["bind_url"] = spec.endpoint_url()
        result["url"] = spec.endpoint_url(host=probe_host(spec.host))
        result["healthy"] = listener_is_reachable(spec.host, spec.port)
    return result


# ---- orchestrator-level helpers -------------------------------------------


def _pick_ida_home(override: str | None) -> str:
    """Return the resolved IDA install directory (or the loud placeholder)."""
    home, is_placeholder = _resolve_ida_home(override)
    if not is_placeholder:
        locate_idat_in_home(home)
    return home
