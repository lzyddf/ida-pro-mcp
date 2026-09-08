"""Integration tests for :class:`Spawner` driven by a fake idat binary.

We do *not* mock subprocess: a fake ``idat`` shell script reads the
``-S`` value, parses ``--session-id``, writes a real sidecar, then sleeps
until killed. That exercises the full Popen + sidecar polling path with
realistic concurrency, while staying hermetic (no real IDA on the box).
"""
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

import pytest

from ida_pro_mcp.plugin import session
from ida_pro_mcp.spawner import IdatNotFoundError, Spawner

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only fake idat")


@pytest.fixture()
def isolate_sessions_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "ida-pro-mcp-headless"
    target.mkdir()
    monkeypatch.setattr(session, "base_dir", lambda: target)
    return target


@pytest.fixture()
def fake_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "fixture.bin"
    binary.write_bytes(b"\x90" * 16)
    return binary


@pytest.fixture()
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop ``IDA_PRO_HOME`` so each test sets up its own fake home dir."""
    monkeypatch.delenv("IDA_PRO_HOME", raising=False)


def _install_fake_idat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    behaviour: str,
) -> Path:
    """Drop a fake ``idat`` into a fresh dir and point ``IDA_PRO_HOME`` at it.

    The locator reads ``IDA_PRO_HOME`` exclusively, so each test gets a
    per-call home dir, a fake ``idat`` script inside it, and the env var
    set via *monkeypatch* (auto-restored at teardown).
    """
    home = tmp_path / "ida_home"
    home.mkdir(exist_ok=True)
    fake = _write_fake_idat_inside(home, behaviour=behaviour)
    monkeypatch.setenv("IDA_PRO_HOME", str(home))
    return fake


def _write_fake_idat_inside(
    directory: Path,
    *,
    behaviour: str,
    name: str = "idat",
) -> Path:
    """Create a shell-script fake ``idat`` whose body is *behaviour*.

    The script is invoked exactly the way ``Spawner`` constructs argv:
    ``["idat", "-A", "-S<bootstrap> --session-id <id>", "-L<log>",
    "<binary>"]``. The fake script reads ``$2`` (the ``-S`` argument)
    to extract the session id and exposes it via ``$SID`` to *behaviour*.

    The fake lives at ``<directory>/<name>`` so :func:`locate_idat`
    accepts it when ``IDA_PRO_HOME=<directory>``.
    """
    import shlex

    fake = directory / name
    header = "\n".join([
        "#!/bin/sh",
        '# argv: -A -S<script ...> -L<log> <binary>',
        'S_ARG="$2"',
        r"SID=$(echo \"$S_ARG\" | sed -E 's/.*--session-id ([^ ]+).*/\1/')",
        "export SID",
        f"export PYTHON={shlex.quote(sys.executable)}",
        "",
    ]).replace(r'\"', '"')
    fake.write_text(header + behaviour)
    fake.chmod(0o755)
    return fake


def _publish_via_python(
    target_dir: Path,
    *,
    pre_publish_sleep: float = 0.0,
    spawn_marker_dir: Path | None = None,
) -> str:
    """Generate inline python that publishes a sidecar then sleeps until SIGTERM.

    ``target_dir`` is the redirected ``base_dir`` for tests; the helper
    embeds it so the child process writes to the same location the test
    is monkey-patched to read from.

    ``pre_publish_sleep`` lets concurrency tests slow the spawn down so a
    second ``open`` call hits the lock window before the first publishes
    its sidecar. ``spawn_marker_dir`` (when set) makes every fake-idat
    instance touch a unique file there *before* sleeping, so the test
    can count how many idat processes were actually launched.
    """
    src_dir = str(Path(__file__).resolve().parents[1] / 'src')
    marker_block = ""
    if spawn_marker_dir is not None:
        marker_block = (
            "import uuid\n"
            f"_marker = Path({str(spawn_marker_dir)!r})\n"
            "_marker.mkdir(parents=True, exist_ok=True)\n"
            "(_marker / f'{os.getpid()}-{uuid.uuid4().hex}').touch()\n"
        )
    sleep_block = f"time.sleep({pre_publish_sleep})\n" if pre_publish_sleep > 0 else ""
    body = (
        "import os, signal, sys, time\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {src_dir!r})\n"
        + marker_block
        + sleep_block
        + "from ida_pro_mcp.plugin import session as sess\n"
        f"sess.base_dir = lambda: Path({str(target_dir)!r})\n"
        "info = sess.make_info(\n"
        "    session_id=os.environ['SID'],\n"
        "    host='127.0.0.1', port=4321, pid=os.getpid(),\n"
        "    idb_path='/tmp/x.i64', input_file='/tmp/x',\n"
        ")\n"
        "sess.write(info)\n"
        "signal.signal(signal.SIGTERM, lambda *_: (sess.remove(os.environ['SID']), os._exit(0)))\n"
        "signal.signal(signal.SIGINT,  lambda *_: (sess.remove(os.environ['SID']), os._exit(0)))\n"
        "while True:\n"
        "    time.sleep(0.1)\n"
    )
    return f'"$PYTHON" - <<\'PY\'\n{body}PY\n'


class TestOpenHappyPath:
    def test_spawn_publishes_sidecar(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(isolate_sessions_dir),
        )
        spawner = Spawner(startup_timeout=10.0)
        result = spawner.open(fake_binary)
        try:
            assert result.reused is False
            assert result.session.mode == "headless"
            assert result.session.input_file != ""
            on_disk = session.get(result.session.session_id)
            assert on_disk is not None
            assert on_disk.session_id == result.session.session_id
        finally:
            spawner.close(result.session.session_id, timeout=5.0)

    def test_open_reuses_existing_session(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(isolate_sessions_dir),
        )
        spawner = Spawner(startup_timeout=10.0)
        first = spawner.open(fake_binary)
        try:
            second = spawner.open(fake_binary)
            assert second.reused is True
            assert second.session.session_id == first.session.session_id
        finally:
            spawner.close(first.session.session_id, timeout=5.0)


class TestOpenFailures:
    def test_spawn_exit_before_sidecar_surfaces_logs(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour='echo "boom" >&2; exit 7',
        )
        spawner = Spawner(startup_timeout=5.0)
        with pytest.raises(RuntimeError, match="exit code 7"):
            spawner.open(fake_binary)

    def test_spawn_timeout_kills_process(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(tmp_path, monkeypatch, behaviour="sleep 30")
        spawner = Spawner(startup_timeout=1.0)
        with pytest.raises(TimeoutError, match="did not become ready"):
            spawner.open(fake_binary, timeout=1.0)

    def test_missing_input_file_raises(
        self,
        isolate_sessions_dir: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(tmp_path, monkeypatch, behaviour="exit 0")
        spawner = Spawner()
        with pytest.raises(FileNotFoundError):
            spawner.open(tmp_path / "does_not_exist.bin")

    def test_no_idat_raises_idat_not_found(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        clean_env,
    ):
        spawner = Spawner()
        with pytest.raises(IdatNotFoundError):
            spawner.open(fake_binary)


class TestClose:
    def test_close_signals_target(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(isolate_sessions_dir),
        )
        spawner = Spawner(startup_timeout=10.0)
        result = spawner.open(fake_binary)
        sid = result.session.session_id
        graceful = spawner.close(sid, timeout=5.0)
        assert graceful is True
        assert session.get(sid) is None

    def test_close_unknown_session_raises(self, isolate_sessions_dir: Path):
        spawner = Spawner()
        with pytest.raises(FileNotFoundError):
            spawner.close("ghost-12345678")

    def test_close_escalates_when_child_ignores_sigterm(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        src_dir = str(Path(__file__).resolve().parents[1] / 'src')
        body = (
            "import os, signal, sys, time\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {src_dir!r})\n"
            "from ida_pro_mcp.plugin import session as sess\n"
            f"sess.base_dir = lambda: Path({str(isolate_sessions_dir)!r})\n"
            "info = sess.make_info(\n"
            "    session_id=os.environ['SID'],\n"
            "    host='127.0.0.1', port=4321, pid=os.getpid(),\n"
            "    idb_path='/tmp/x.i64', input_file='/tmp/x',\n"
            ")\n"
            "sess.write(info)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        )
        behaviour = f'"$PYTHON" - <<\'PY\'\n{body}PY\n'
        _install_fake_idat(tmp_path, monkeypatch, behaviour=behaviour)
        spawner = Spawner(startup_timeout=10.0)
        result = spawner.open(fake_binary)
        sid = result.session.session_id
        try:
            graceful = spawner.close(sid, timeout=1.0)
            assert graceful is False
            assert session.get(sid) is None
        finally:
            import contextlib
            with contextlib.suppress(ProcessLookupError):
                os.kill(result.session.pid, signal.SIGKILL)


class TestFresh:
    def test_fresh_deletes_idb_artifacts(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        idb = fake_binary.with_suffix(fake_binary.suffix + ".i64")
        idb.write_bytes(b"old idb")
        til = fake_binary.with_suffix(fake_binary.suffix + ".til")
        til.write_bytes(b"old til")

        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(isolate_sessions_dir),
        )
        spawner = Spawner(startup_timeout=10.0)
        result = spawner.open(fake_binary, fresh=True)
        try:
            assert not idb.exists()
            assert not til.exists()
        finally:
            spawner.close(result.session.session_id, timeout=5.0)

    def test_fresh_refuses_when_session_running(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(isolate_sessions_dir),
        )
        spawner = Spawner(startup_timeout=10.0)
        result = spawner.open(fake_binary)
        try:
            with pytest.raises(RuntimeError, match="already running"):
                spawner.open(fake_binary, fresh=True)
        finally:
            spawner.close(result.session.session_id, timeout=5.0)


class TestConcurrency:
    def test_concurrent_open_does_not_double_spawn(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Two threads opening the same binary at once must spawn exactly one IDA.

        Without the per-session-id spawn lock both ``open`` calls would
        observe ``existing is None`` and race to start a separate idat
        process. We slow the fake idat enough that the second call
        unambiguously enters while the first is still spawning.
        """
        import threading

        marker_dir = tmp_path / "spawn_markers"
        _install_fake_idat(
            tmp_path, monkeypatch,
            behaviour=_publish_via_python(
                isolate_sessions_dir,
                pre_publish_sleep=0.5,
                spawn_marker_dir=marker_dir,
            ),
        )
        spawner = Spawner(startup_timeout=10.0)

        results: dict[int, object] = {}

        def worker(idx: int) -> None:
            try:
                results[idx] = spawner.open(fake_binary)
            except Exception as exc:
                results[idx] = exc

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)
            assert not t.is_alive()

        first, second = results[0], results[1]
        assert not isinstance(first, Exception), first
        assert not isinstance(second, Exception), second
        assert first.session.session_id == second.session.session_id
        reused_flags = sorted([first.reused, second.reused])
        assert reused_flags == [False, True]
        assert len(list(marker_dir.iterdir())) == 1

        spawner.close(first.session.session_id, timeout=5.0)


class TestProcessHandleHygiene:
    def test_open_failure_does_not_retain_handle(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """Failed spawns must not leak a Popen handle into the bookkeeping dict."""
        _install_fake_idat(tmp_path, monkeypatch, behaviour='echo "boom" >&2; exit 7')
        spawner = Spawner(startup_timeout=5.0)
        with pytest.raises(RuntimeError, match="exit code 7"):
            spawner.open(fake_binary)
        assert spawner._handles == {}

    def test_open_timeout_does_not_retain_handle(
        self,
        isolate_sessions_dir: Path,
        fake_binary: Path,
        tmp_path: Path,
        clean_env,
        monkeypatch: pytest.MonkeyPatch,
    ):
        _install_fake_idat(tmp_path, monkeypatch, behaviour="sleep 30")
        spawner = Spawner(startup_timeout=1.0)
        with pytest.raises(TimeoutError):
            spawner.open(fake_binary, timeout=1.0)
        assert spawner._handles == {}


def test_session_id_stable_across_opens(
    isolate_sessions_dir: Path,
    fake_binary: Path,
    tmp_path: Path,
    clean_env,
    monkeypatch: pytest.MonkeyPatch,
):
    """Open + close + reopen must produce the same session id."""
    _install_fake_idat(
        tmp_path, monkeypatch,
        behaviour=_publish_via_python(isolate_sessions_dir),
    )
    spawner = Spawner(startup_timeout=10.0)
    first = spawner.open(fake_binary)
    spawner.close(first.session.session_id, timeout=5.0)
    deadline = time.monotonic() + 5.0
    while session.get(first.session.session_id) is not None and time.monotonic() < deadline:
        time.sleep(0.05)
    second = spawner.open(fake_binary)
    try:
        assert second.session.session_id == first.session.session_id
        assert second.reused is False
    finally:
        spawner.close(second.session.session_id, timeout=5.0)
