"""Validated, serialisable configuration for the Windows service runner."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from ....runtime_args import HTTP_TRANSPORTS, HTTPTransport, build_serve_argv

_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    """All runtime values needed by the windowless service entry point."""

    ida_home: str
    transport: HTTPTransport
    host: str
    port: int
    unsafe: bool = False
    schema_version: int = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != _SCHEMA_VERSION:
            raise ValueError(
                f"unsupported service config schema {self.schema_version}; "
                f"expected {_SCHEMA_VERSION}"
            )
        if not isinstance(self.ida_home, str) or not self.ida_home:
            raise ValueError("service config ida_home must not be empty")
        if self.transport not in HTTP_TRANSPORTS:
            raise ValueError(f"unsupported service transport {self.transport!r}")
        if not isinstance(self.host, str) or not self.host:
            raise ValueError("service config host must not be empty")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise ValueError(f"service config port must be in 1-65535, got {self.port!r}")
        if not isinstance(self.unsafe, bool):
            raise ValueError("service config unsafe must be a boolean")

    def serve_argv(self) -> list[str]:
        """Build the canonical CLI arguments used to run the proxy."""
        return build_serve_argv(
            transport=self.transport,
            host=self.host,
            port=self.port,
            unsafe=self.unsafe,
        )

    def endpoint_url(self, *, host: str | None = None) -> str:
        """Return the transport endpoint for a bind or client host."""
        address = self.host if host is None else host
        if ":" in address and not address.startswith("["):
            address = f"[{address}]"
        path = "/mcp" if self.transport == "streamable-http" else "/sse"
        return f"http://{address}:{self.port}{path}"

    def write(self, path: Path) -> None:
        """Atomically persist this spec so the task never sees partial JSON."""
        payload = json.dumps(asdict(self), indent=2) + "\n"
        temporary = path.with_name(f"{path.name}.tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(path)

    @classmethod
    def read(cls, path: Path) -> ServiceSpec:
        """Load and validate a service spec from path."""
        try:
            raw: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read service config {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"service config {path} must contain a JSON object")
        try:
            return cls(
                schema_version=raw["schema_version"],
                ida_home=raw["ida_home"],
                transport=cast(HTTPTransport, raw["transport"]),
                host=raw["host"],
                port=raw["port"],
                unsafe=raw["unsafe"],
            )
        except KeyError as exc:
            raise ValueError(f"service config {path} is missing {exc.args[0]!r}") from exc
