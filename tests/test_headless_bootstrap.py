"""Sanity checks for ``plugin.headless_bootstrap``.

Running the bootstrap end-to-end requires a real IDA, but two cheap
checks catch the most common breakages:

* ``compile`` validates the script parses (spotting syntax slip-ups
  introduced when refactoring shared helpers).
* Reading the file confirms it actually exists at the location the
  spawner advertises -- otherwise ``Spawner.open`` would happily issue
  ``idat -S<broken-path>`` and time out without explanation.
"""
from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.plugin import session


def _bootstrap_path() -> Path:
    return Path(session.__file__).resolve().parent / "headless_bootstrap.py"


def test_bootstrap_script_exists_at_expected_location():
    assert _bootstrap_path().is_file()


def test_bootstrap_script_compiles():
    source = _bootstrap_path().read_text(encoding="utf-8")
    compile(source, str(_bootstrap_path()), "exec")


def test_bootstrap_script_advertises_session_id_arg():
    """The spawner relies on the script accepting ``--session-id``."""
    source = _bootstrap_path().read_text(encoding="utf-8")
    assert "--session-id" in source
