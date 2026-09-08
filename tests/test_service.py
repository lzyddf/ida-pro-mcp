"""Tests for the cross-platform service plumbing and Windows backend."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from ida_pro_mcp.installer import service as service_pkg
from ida_pro_mcp.installer.service import ServiceUnsupportedError, _windows
from ida_pro_mcp.installer.service._windows import health as _health
from ida_pro_mcp.installer.service._windows import paths as _paths
from ida_pro_mcp.installer.service._windows import pythonw as _pythonw
from ida_pro_mcp.installer.service._windows import runner as _runner
from ida_pro_mcp.installer.service._windows import schtasks as _schtasks
from ida_pro_mcp.installer.service._windows import task_xml as _task_xml
from ida_pro_mcp.installer.service._windows.service_spec import ServiceSpec
from ida_pro_mcp.installer.service._windows.windows_job import KillOnCloseJob
from ida_pro_mcp.spawner import IdatNotFoundError


class TestDispatcher:
    def test_windows_returns_windows_module(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        assert service_pkg._backend() is _windows

    @pytest.mark.parametrize("platform", ["darwin", "linux", "haiku"])
    def test_unsupported_platforms_raise(self, monkeypatch, platform):
        monkeypatch.setattr(sys, "platform", platform)
        with pytest.raises(ServiceUnsupportedError):
            service_pkg._backend()

    def test_install_rejects_stdio_before_selecting_backend(self, monkeypatch):
        monkeypatch.setattr(
            service_pkg,
            "_backend",
            lambda: pytest.fail("backend should not be selected"),
        )
        with pytest.raises(ValueError, match="service transport"):
            service_pkg.install_service(transport="stdio")  # type: ignore[arg-type]


class TestServicePaths:
    def test_uses_localappdata(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        assert _paths._service_dir() == tmp_path / "ida-pro-mcp-headless" / "service"
        assert _paths._config_path().name == "service.json"

    def test_falls_back_to_home(self, tmp_path, monkeypatch):
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        assert _paths._service_dir() == tmp_path / ".ida-pro-mcp-headless" / "service"


class TestServiceSpec:
    def test_round_trip_and_serve_argv(self, tmp_path):
        path = tmp_path / "service.json"
        original = ServiceSpec(
            ida_home=r"C:\IDA 9.0",
            transport="streamable-http",
            host="0.0.0.0",
            port=13337,
            unsafe=True,
        )
        original.write(path)
        loaded = ServiceSpec.read(path)
        assert loaded == original
        assert loaded.serve_argv() == [
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "13337",
            "--unsafe",
        ]
        assert loaded.endpoint_url() == "http://0.0.0.0:13337/mcp"
        assert loaded.endpoint_url(host="127.0.0.1") == "http://127.0.0.1:13337/mcp"
        assert not path.with_name("service.json.tmp").exists()

    @pytest.mark.parametrize("port", [0, 65536, True, "13337"])
    def test_rejects_invalid_port(self, port):
        with pytest.raises(ValueError, match="port"):
            ServiceSpec(
                ida_home=r"C:\IDA",
                transport="streamable-http",
                host="127.0.0.1",
                port=port,  # type: ignore[arg-type]
            )

    def test_rejects_missing_json_field(self, tmp_path):
        path = tmp_path / "service.json"
        path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        with pytest.raises(ValueError, match="missing"):
            ServiceSpec.read(path)


class TestWindowedPython:
    def test_returns_sibling_pythonw(self, tmp_path):
        console = tmp_path / "python.exe"
        windowed = tmp_path / "pythonw.exe"
        console.touch()
        windowed.touch()
        assert _pythonw.find_windowed_python(str(console)) == str(windowed)

    def test_missing_pythonw_is_actionable(self, tmp_path):
        with pytest.raises(_pythonw.WindowedPythonNotFoundError, match=r"pythonw\.exe"):
            _pythonw.find_windowed_python(str(tmp_path / "python.exe"))


class TestKillOnCloseJob:
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object only")
    def test_closing_job_terminates_assigned_process(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            with KillOnCloseJob() as job:
                job.assign(process)
                assert process.poll() is None
            assert process.wait(timeout=5) is not None
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


class TestHealth:
    @pytest.mark.parametrize(
        ("bind", "probe"),
        [("0.0.0.0", "127.0.0.1"), ("::", "::1"), ("192.168.1.2", "192.168.1.2")],
    )
    def test_probe_host(self, bind, probe):
        assert _health.probe_host(bind) == probe

    def test_http_probe_accepts_any_http_status(self, monkeypatch):
        class Response:
            def read(self):
                return b"not found"

        class Connection:
            def __init__(self, host, port, timeout):
                self.target = (host, port, timeout)

            def request(self, method, path):
                assert (method, path) == ("GET", "/__ida_pro_mcp_health__")

            def getresponse(self):
                return Response()

            def close(self):
                pass

        monkeypatch.setattr(_health.http.client, "HTTPConnection", Connection)
        assert _health.listener_is_reachable("0.0.0.0", 13337) is True


class TestRunner:
    def test_runs_proxy_child_without_console_and_assigns_job(self, tmp_path, monkeypatch):
        spec = ServiceSpec(
            ida_home=r"C:\IDA 9.0",
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
        )
        seen: dict[str, object] = {}

        class Process:
            pid = 4321

            def wait(self):
                return 7

            def terminate(self):
                pytest.fail("healthy assignment must not terminate the child")

        class Job:
            def __enter__(self):
                return self

            def assign(self, process):
                seen["assigned"] = process

            def __exit__(self, *_args):
                pass

        def fake_popen(command, **kwargs):
            seen["command"] = command
            seen["kwargs"] = kwargs
            return Process()

        monkeypatch.setattr(_runner, "find_console_python", lambda _python: r"C:\fake\python.exe")
        monkeypatch.setattr(_runner, "KillOnCloseJob", Job)
        monkeypatch.setattr(_runner.subprocess, "Popen", fake_popen)
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        result = _runner._run_child_once(spec, tmp_path / "service.json", stdout, stderr)

        assert result == 7
        assert seen["command"] == [
            r"C:\fake\python.exe",
            "-m",
            "ida_pro_mcp",
            "serve",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            "13337",
        ]
        kwargs = seen["kwargs"]
        assert isinstance(kwargs, dict)
        assert kwargs["env"]["IDA_PRO_HOME"] == r"C:\IDA 9.0"
        assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)
        assert seen["assigned"] is not None
        assert b"proxy started pid=4321" in stdout.getvalue()

    def test_supervisor_restarts_after_child_exit(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
        _paths._service_dir().mkdir(parents=True)
        ServiceSpec(
            ida_home=r"C:\IDA",
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
        ).write(_paths._config_path())

        class StopLoop(BaseException):
            pass

        calls = 0

        def run_once(*_args):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 9
            raise StopLoop

        monkeypatch.setattr(_runner, "_run_child_once", run_once)
        monkeypatch.setattr(_runner.time, "sleep", lambda _delay: None)
        with pytest.raises(StopLoop):
            _runner.supervise(_paths._config_path())
        assert calls == 2
        stderr = _paths._stderr_log().read_text(encoding="utf-8")
        assert "proxy exited with code 9; restarting" in stderr


class TestLogonUser:
    def test_with_domain(self, monkeypatch):
        monkeypatch.setenv("USERDOMAIN", "ACME")
        monkeypatch.setenv("USERNAME", "alice")
        assert _task_xml._logon_user() == r"ACME\alice"

    def test_falls_back_to_getpass(self, monkeypatch):
        monkeypatch.delenv("USERDOMAIN", raising=False)
        monkeypatch.delenv("USERNAME", raising=False)
        monkeypatch.setattr(_task_xml.getpass, "getuser", lambda: "fallback")
        assert _task_xml._logon_user() == "fallback"


class TestParseSchtasksList:
    def test_preserves_colons_in_values(self):
        sample = (
            "\r\nTaskName: \\ida-pro-mcp-headless\r\n"
            "Status: Ready\r\n"
            "Task To Run: C:\\Python\\pythonw.exe\r\n"
        )
        info = _schtasks._parse_schtasks_list(sample)
        assert info["TaskName"] == r"\ida-pro-mcp-headless"
        assert info["Task To Run"] == r"C:\Python\pythonw.exe"


class TestRenderTaskXml:
    def test_renders_windowless_action_and_unlimited_runtime(self):
        command = r"C:\Python & Tools\pythonw.exe"
        arguments = r'-m ida_pro_mcp.installer.service._windows.runner --config "C:\A&B\service.json"'
        working_directory = r"C:\A&B"
        xml = _task_xml._render_task_xml(
            user_id=r"ACME\alice",
            command=command,
            arguments=arguments,
            working_directory=working_directory,
        )
        root = ET.fromstring(xml)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        assert root.findtext("t:Actions/t:Exec/t:Command", namespaces=ns) == command
        assert root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns) == arguments
        assert root.findtext("t:Actions/t:Exec/t:WorkingDirectory", namespaces=ns) == working_directory
        assert root.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns) == "InteractiveToken"
        assert root.find("t:Settings/t:RestartOnFailure", ns) is None
        assert root.findtext("t:Settings/t:ExecutionTimeLimit", namespaces=ns) == "PT0S"


@pytest.fixture()
def fake_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("USERDOMAIN", "TESTHOST")
    monkeypatch.setenv("USERNAME", "tester")
    monkeypatch.setattr(_windows, "get_python_executable", lambda: r"C:\fake\python.exe")
    monkeypatch.setattr(_windows, "find_windowed_python", lambda _python: r"C:\fake\pythonw.exe")
    monkeypatch.setattr(_windows, "locate_idat_in_home", lambda _home: Path(r"C:\fake\idat.exe"))
    monkeypatch.setattr(_windows, "wait_for_listener_to_close", lambda _host, _port: None)
    monkeypatch.setattr(_windows, "wait_for_listener", lambda _host, _port: None)
    monkeypatch.setattr(_windows, "listener_is_reachable", lambda _host, _port: True)

    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(_schtasks.subprocess, "run", fake_run)
    return tmp_path, calls


_FAKE_IDA_HOME = r"C:\Program Files\IDA Professional 9.0"


class TestInstall:
    def test_writes_config_and_windowless_task(self, fake_environment):
        tmp_path, _calls = fake_environment
        info = _windows.install(
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
            unsafe=False,
            ida_home=_FAKE_IDA_HOME,
        )
        service_dir = tmp_path / "ida-pro-mcp-headless" / "service"
        spec = ServiceSpec.read(service_dir / "service.json")
        assert spec.ida_home == _FAKE_IDA_HOME
        assert spec.serve_argv()[-2:] == ["--port", "13337"]
        assert info["runner"].endswith("pythonw.exe")
        assert info["url"] == "http://127.0.0.1:13337/mcp"
        assert not (service_dir / "proxy.cmd").exists()

        xml = (service_dir / "task.xml").read_bytes().decode("utf-16-le")[1:]
        root = ET.fromstring(xml)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        assert root.findtext("t:Actions/t:Exec/t:Command", namespaces=ns) == r"C:\fake\pythonw.exe"
        arguments = root.findtext("t:Actions/t:Exec/t:Arguments", namespaces=ns)
        assert arguments is not None and _windows._RUNNER_MODULE in arguments
        assert "service.json" in arguments

    def test_reinstall_stops_old_task_before_replacing_it(self, fake_environment):
        _tmp_path, calls = fake_environment
        _windows.install(
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
            unsafe=False,
            ida_home=_FAKE_IDA_HOME,
        )
        assert calls[0][:4] == ["schtasks", "/end", "/tn", _windows.TASK_NAME]
        assert calls[1][:3] == ["schtasks", "/create", "/tn"]
        assert calls[2][:4] == ["schtasks", "/run", "/tn", _windows.TASK_NAME]

    def test_removes_legacy_wrapper_after_healthy_start(self, fake_environment):
        tmp_path, _calls = fake_environment
        legacy = tmp_path / "ida-pro-mcp-headless" / "service" / "proxy.cmd"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text("old", encoding="utf-8")
        _windows.install(
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
            unsafe=False,
            ida_home=_FAKE_IDA_HOME,
        )
        assert not legacy.exists()

    def test_unsafe_and_sse_are_persisted(self, fake_environment):
        tmp_path, _calls = fake_environment
        info = _windows.install(
            transport="sse",
            host="127.0.0.1",
            port=4242,
            unsafe=True,
            ida_home=_FAKE_IDA_HOME,
        )
        spec = ServiceSpec.read(tmp_path / "ida-pro-mcp-headless" / "service" / "service.json")
        assert spec.unsafe is True
        assert spec.transport == "sse"
        assert info["url"] == "http://127.0.0.1:4242/sse"

    def test_warns_when_ida_home_is_placeholder(self, fake_environment, capsys, monkeypatch):
        monkeypatch.delenv("IDA_PRO_HOME", raising=False)
        _windows.install(
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
            unsafe=False,
            ida_home=None,
        )
        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "open_file" in err

    def test_create_failure_propagates(self, fake_environment, monkeypatch):
        def failing_run(argv, **_kwargs):
            if "/create" in argv:
                return subprocess.CompletedProcess(
                    argv, returncode=1, stdout="", stderr="ERROR: access denied"
                )
            return subprocess.CompletedProcess(argv, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(_schtasks.subprocess, "run", failing_run)
        with pytest.raises(RuntimeError, match="schtasks /create failed"):
            _windows.install(
                transport="streamable-http",
                host="127.0.0.1",
                port=13337,
                unsafe=False,
                ida_home=_FAKE_IDA_HOME,
            )

    def test_concrete_ida_home_is_validated(self, monkeypatch):
        def invalid(_home):
            raise IdatNotFoundError("missing idat")

        monkeypatch.setattr(_windows, "locate_idat_in_home", invalid)
        with pytest.raises(IdatNotFoundError, match="missing idat"):
            _windows._pick_ida_home(r"C:\missing")


class TestUninstall:
    def test_stops_deletes_and_removes_artifacts(self, fake_environment):
        tmp_path, calls = fake_environment
        service_dir = tmp_path / "ida-pro-mcp-headless" / "service"
        service_dir.mkdir(parents=True)
        (service_dir / "service.json").write_text("{}", encoding="utf-8")
        result = _windows.uninstall()
        assert calls[0][:4] == ["schtasks", "/end", "/tn", _windows.TASK_NAME]
        assert calls[1][:4] == ["schtasks", "/delete", "/tn", _windows.TASK_NAME]
        assert not service_dir.exists()
        assert result["service_dir_removed"] is True

    def test_is_idempotent_when_absent(self, fake_environment, monkeypatch):
        def absent_run(argv, **_kwargs):
            return subprocess.CompletedProcess(
                argv,
                returncode=1,
                stdout="",
                stderr="ERROR: The system cannot find the file specified.",
            )

        monkeypatch.setattr(_schtasks.subprocess, "run", absent_run)
        result = _windows.uninstall()
        assert result["deleted"] == "absent"
        assert result["ended"] == "absent"


class TestStatus:
    def test_reports_not_installed(self, fake_environment, monkeypatch):
        def absent_run(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, returncode=1, stdout="", stderr="not found")

        monkeypatch.setattr(_schtasks.subprocess, "run", absent_run)
        assert _windows.status() == {"installed": False, "task_name": _windows.TASK_NAME}

    def test_reports_config_url_and_health(self, fake_environment, monkeypatch):
        tmp_path, _calls = fake_environment
        service_dir = tmp_path / "ida-pro-mcp-headless" / "service"
        service_dir.mkdir(parents=True)
        ServiceSpec(
            ida_home=_FAKE_IDA_HOME,
            transport="streamable-http",
            host="127.0.0.1",
            port=13337,
        ).write(service_dir / "service.json")
        sample = (
            "TaskName: \\ida-pro-mcp-headless\r\n"
            "Status: Running\r\n"
            "Last Result: 267009\r\n"
            "Task To Run: C:\\fake\\pythonw.exe\r\n"
        )

        def query_run(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, returncode=0, stdout=sample, stderr="")

        monkeypatch.setattr(_schtasks.subprocess, "run", query_run)
        result = _windows.status()
        assert result["installed"] is True
        assert result["healthy"] is True
        assert result["url"] == "http://127.0.0.1:13337/mcp"
        assert result["task_to_run"].endswith("pythonw.exe")
