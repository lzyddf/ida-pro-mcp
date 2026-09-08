"""Tests for the cross-platform PID-existence probe.

The Windows path drives the ``_pid_alive_windows`` helper through
monkeypatched ``ctypes`` so we can assert the OpenProcess /
GetExitCodeProcess decision tree without depending on real foreign pids.
"""
from __future__ import annotations

import os
import sys

import pytest

from ida_pro_mcp.plugin import _pid_check


class TestNonPositive:
    """Sentinel values must short-circuit before any platform call."""

    @pytest.mark.parametrize("pid", [0, -1, -1234])
    def test_non_positive_returns_false(self, pid):
        assert _pid_check.is_pid_alive(pid) is False


class TestCurrentProcess:
    def test_current_process_is_alive(self):
        # ``os.getpid`` is alive by definition while this test runs.
        assert _pid_check.is_pid_alive(os.getpid()) is True


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only branch")
class TestPosixBranch:
    def test_definitely_dead_pid_returns_false(self, monkeypatch):
        # Force ``os.kill`` to raise as if the pid were gone, regardless
        # of platform behaviour (``os.kill(pid, 0)`` semantics differ).
        def _gone(*_args, **_kwargs):
            raise ProcessLookupError(3, "No such process")

        monkeypatch.setattr(_pid_check.os, "kill", _gone)
        assert _pid_check.is_pid_alive(99999) is False

    def test_permission_denied_treated_as_alive(self, monkeypatch):
        def _denied(*_args, **_kwargs):
            raise PermissionError(1, "Operation not permitted")

        monkeypatch.setattr(_pid_check.os, "kill", _denied)
        # A pid we lack permission to signal must still count as alive --
        # otherwise the proxy would GC sidecars whose owners run under a
        # different uid (matters on multi-user dev boxes).
        assert _pid_check.is_pid_alive(1) is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only branch")
class TestWindowsBranch:
    @pytest.fixture()
    def fake_kernel32(self, monkeypatch):
        """Stub :func:`_get_kernel32` so each test controls the Win32 calls."""
        captured: dict[str, object] = {"open_handle": None, "exit_code": None, "last_error": 0}

        class _FakeKernel32:
            @staticmethod
            def OpenProcess(_access, _inherit, _pid):
                handle = captured["open_handle"]
                if handle in (None, 0):
                    return 0
                return handle

            @staticmethod
            def GetExitCodeProcess(_handle, out_ptr):
                ec = captured["exit_code"]
                if ec is None:
                    return 0  # signals failure to the caller
                out_ptr._obj.value = ec
                return 1

            @staticmethod
            def CloseHandle(_handle):
                return 1

        monkeypatch.setattr(_pid_check, "_get_kernel32", lambda: _FakeKernel32)
        monkeypatch.setattr(
            _pid_check.ctypes, "get_last_error",
            lambda: captured["last_error"],
        )
        return captured

    def test_open_failure_invalid_parameter_returns_false(self, fake_kernel32):
        # OpenProcess returns 0 + GetLastError == ERROR_INVALID_PARAMETER:
        # the pid does not name a live process.
        fake_kernel32["open_handle"] = 0
        fake_kernel32["last_error"] = _pid_check._WIN32_ERROR_INVALID_PARAMETER
        assert _pid_check._pid_alive_windows(12345) is False

    def test_open_failure_other_error_treated_as_alive(self, fake_kernel32):
        # ACCESS_DENIED (etc.) means the process exists but our token can't
        # inspect it -- still alive from the GC's perspective.
        fake_kernel32["open_handle"] = 0
        fake_kernel32["last_error"] = 5  # ERROR_ACCESS_DENIED
        assert _pid_check._pid_alive_windows(12345) is True

    def test_still_active_exit_code_is_alive(self, fake_kernel32):
        fake_kernel32["open_handle"] = 0xDEADBEEF
        fake_kernel32["exit_code"] = _pid_check._WIN32_STILL_ACTIVE
        assert _pid_check._pid_alive_windows(12345) is True

    def test_completed_exit_code_is_dead(self, fake_kernel32):
        fake_kernel32["open_handle"] = 0xDEADBEEF
        fake_kernel32["exit_code"] = 0  # any value other than STILL_ACTIVE
        assert _pid_check._pid_alive_windows(12345) is False

    def test_get_exit_code_failure_treated_as_alive(self, fake_kernel32):
        # GetExitCodeProcess returning 0 (failure) leaves the alive/dead
        # decision ambiguous; we err on the side of alive so a probe glitch
        # doesn't GC a healthy session.
        fake_kernel32["open_handle"] = 0xDEADBEEF
        fake_kernel32["exit_code"] = None
        assert _pid_check._pid_alive_windows(12345) is True


class TestKernel32Cache:
    """The ``_kernel32`` lazy load must memoise across calls."""

    @pytest.mark.skipif(sys.platform != "win32", reason="kernel32 only loads on Windows")
    def test_handle_is_memoised(self, monkeypatch):
        # Reset the module-level cache so the test runs deterministically
        # regardless of whether prior tests already triggered the load.
        monkeypatch.setattr(_pid_check, "_kernel32", None)
        first = _pid_check._get_kernel32()
        second = _pid_check._get_kernel32()
        assert first is second
