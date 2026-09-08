"""Windowless supervisor executed by the Windows Scheduled Task."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from ....spawner.locator import IDA_HOME_ENV_VAR
from .paths import _stderr_log, _stdout_log
from .pythonw import find_console_python
from .service_spec import ServiceSpec
from .windows_job import KillOnCloseJob

_RESTART_DELAY_SECONDS = 5.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Supervise ida-pro-mcp-headless without a console window.")
    parser.add_argument("--config", type=Path, required=True)
    return parser


def _write_line(stream: BinaryIO, message: str) -> None:
    stream.write(f"[{datetime.now().isoformat(timespec='seconds')}] {message}\n".encode())
    stream.flush()


def _child_command(spec: ServiceSpec) -> list[str]:
    console_python = find_console_python(sys.executable)
    return [console_python, "-m", "ida_pro_mcp", *spec.serve_argv()]


def _run_child_once(
    spec: ServiceSpec,
    config_path: Path,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> int:
    """Run one proxy child without a console and return its exit status."""
    env = dict(os.environ)
    env[IDA_HOME_ENV_VAR] = spec.ida_home
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    command = _child_command(spec)
    with KillOnCloseJob() as job:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=env,
            cwd=config_path.parent,
            close_fds=True,
            creationflags=creationflags,
        )
        try:
            job.assign(process)
        except BaseException:
            process.terminate()
            process.wait()
            raise
        _write_line(stdout, f"proxy started pid={process.pid}")
        return process.wait()


def supervise(config_path: Path) -> None:
    """Keep the proxy alive while the Scheduled Task itself is running."""
    spec = ServiceSpec.read(config_path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with (
        _stdout_log().open("ab", buffering=0) as stdout,
        _stderr_log().open("ab", buffering=0) as stderr,
    ):
        _write_line(stdout, "windowless supervisor starting")
        while True:
            try:
                returncode = _run_child_once(spec, config_path, stdout, stderr)
                _write_line(stderr, f"proxy exited with code {returncode}; restarting")
            except Exception:
                _write_line(stderr, "proxy launch failed; restarting")
                stderr.write(traceback.format_exc().encode("utf-8", errors="backslashreplace"))
                stderr.flush()
            time.sleep(_RESTART_DELAY_SECONDS)


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    supervise(args.config)


if __name__ == "__main__":
    main()
