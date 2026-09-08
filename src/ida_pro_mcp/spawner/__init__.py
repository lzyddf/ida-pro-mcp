"""Headless ``idat`` launcher used by the ``open_file`` / ``close_file`` tools.

The package is split by responsibility so each file stays focused:

* :mod:`.locator` -- find or validate ``idat`` under an IDA install directory.
  Exports :func:`locate_idat`, :func:`locate_idat_in_home`, and
  :class:`IdatNotFoundError`.
* :mod:`.process_env` -- scrub the environment we hand to the child ``idat``
  (``PYTHONHOME`` / ``PATH`` venv stripping / ``TVHEADLESS`` injection /
  ``IDA_PRO_MCP_PACKAGE_ROOT`` injection).
* :mod:`.kill_switch` -- shared cross-process protocol with
  :mod:`ida_pro_mcp.plugin.headless_bootstrap` for graceful shutdown on
  Windows (where ``SIGTERM`` is a hard kill).
* :mod:`.idb_artifacts` -- ``fresh=True`` reanalysis support: enumerates and
  removes the IDB files IDA may have left next to a binary.
* :mod:`.core` -- the :class:`Spawner` itself plus :class:`OpenResult`.

Public symbols are re-exported here so ``from ida_pro_mcp.spawner import
Spawner`` keeps working unchanged. Internal helpers used by tests live on
their submodules and should be imported from there.
"""
from __future__ import annotations

from .core import OpenResult, Spawner
from .locator import IdatNotFoundError, locate_idat, locate_idat_in_home
from .process_env import _PYTHON_ENV_VARS_TO_STRIP, _strip_venv_from_path

__all__ = [
    "_PYTHON_ENV_VARS_TO_STRIP",
    "IdatNotFoundError",
    "OpenResult",
    "Spawner",
    "_strip_venv_from_path",
    "locate_idat",
    "locate_idat_in_home",
]
