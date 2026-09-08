"""End-to-end smoke test against a real headless IDA process.

The normal suite uses lightweight IDA SDK stubs and remains runnable on CI.
Set ``IDA_PRO_HOME`` and ``IDA_PRO_MCP_INTEGRATION_BINARY`` to opt into this
test. The selected binary should be a disposable copy because IDA may create
or update database artefacts next to it.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp.client import IDARpcClient
from ida_pro_mcp.spawner import IdatNotFoundError, Spawner, locate_idat

INTEGRATION_BINARY_ENV = "IDA_PRO_MCP_INTEGRATION_BINARY"


@pytest.fixture(scope="module")
def integration_binary() -> Path:
    """Resolve and validate the explicitly selected disposable sample."""
    raw = os.environ.get(INTEGRATION_BINARY_ENV)
    if not raw:
        pytest.skip(
            f"set {INTEGRATION_BINARY_ENV} to run the real-IDA integration test"
        )

    binary = Path(raw).expanduser().resolve()
    if not binary.is_file():
        pytest.fail(f"{INTEGRATION_BINARY_ENV} is not a file: {binary}", pytrace=False)

    try:
        locate_idat()
    except IdatNotFoundError as exc:
        pytest.fail(str(exc), pytrace=False)
    return binary


@pytest.mark.integration
def test_headless_ida_bootstrap_and_metadata_rpc(integration_binary: Path):
    """Exercise spawn, bootstrap, JSON-RPC dispatch, metadata, and shutdown."""
    spawner = Spawner()
    result = spawner.open(integration_binary)
    try:
        client = IDARpcClient(
            host=result.session.host,
            port=result.session.port,
            timeout=30,
        )
        metadata = client.call("get_metadata", {})

        assert metadata["module"]
        assert metadata["base"].startswith("0x")
        assert metadata["size"].startswith("0x")
        assert Path(metadata["path"]).resolve() == integration_binary
    finally:
        # Never close a session that was already owned by another workflow.
        if not result.reused:
            spawner.close(result.session.session_id)
