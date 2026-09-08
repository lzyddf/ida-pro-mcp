"""Render the Scheduled Task XML and persist it to disk.

We register a per-user logon-triggered, long-running task. XML is the only
``schtasks`` input format that exposes every knob we care about
(``StartWhenAvailable``, an unlimited execution time, etc.). The on-disk
encoding is UTF-16 LE with BOM because older Windows builds reject UTF-8
silently.
"""
from __future__ import annotations

import getpass
import os
from pathlib import Path
from xml.sax.saxutils import escape

from .paths import TASK_NAME, _task_xml_path


def _logon_user() -> str:
    """Return ``DOMAIN\\user`` so Task Scheduler can match the LogonTrigger.

    Falls back to ``USERNAME`` alone when ``USERDOMAIN`` is empty (e.g. on
    machines that aren't joined to a domain and are running as a local
    account whose domain is the machine name -- both are accepted by
    Task Scheduler, so we don't try to be clever).
    """
    domain = os.environ.get("USERDOMAIN") or ""
    user = os.environ.get("USERNAME") or getpass.getuser()
    return f"{domain}\\{user}" if domain else user


def _write_task_xml(
    *,
    command: str,
    arguments: str,
    working_directory: Path,
) -> None:
    """Emit the Scheduled Task definition as UTF-16 LE with BOM.

    ``schtasks /create /xml`` accepts UTF-8 on Windows 10 1809+, but older
    Windows builds still demand UTF-16 LE BOM. Writing the older encoding
    works on all targets and doesn't require us to detect the OS build.
    """
    xml = _render_task_xml(
        user_id=_logon_user(),
        command=command,
        arguments=arguments,
        working_directory=str(working_directory),
    )
    _task_xml_path().write_bytes("\ufeff".encode("utf-16-le") + xml.encode("utf-16-le"))


def _render_task_xml(
    *,
    user_id: str,
    command: str,
    arguments: str,
    working_directory: str,
) -> str:
    """Construct the XML for a logon-triggered, long-running user task.

    Notes for the curious:
    * ``ExecutionTimeLimit=PT0S`` disables the default 72h kill switch --
      we want this thing to live forever.
    * We use ``LeastPrivilege`` (no UAC elevation): the proxy doesn't
      need admin, and elevation makes the task fail to launch silently
      if UAC denies the prompt.
    * ``StartWhenAvailable=true`` means a missed login window (e.g.
      laptop was asleep) still triggers the next time conditions allow.
    """
    user_xml = escape(user_id)
    command_xml = escape(command)
    arguments_xml = escape(arguments)
    working_directory_xml = escape(working_directory)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>IDA Pro MCP proxy (HTTP transport, auto-restart on failure).</Description>
    <Author>ida-pro-mcp-headless</Author>
    <URI>\\{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user_xml}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user_xml}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command_xml}</Command>
      <Arguments>{arguments_xml}</Arguments>
      <WorkingDirectory>{working_directory_xml}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""
