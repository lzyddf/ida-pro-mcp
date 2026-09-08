"""Metadata about the current IDB."""
from __future__ import annotations

import logging
from collections.abc import Callable

import ida_nalt
import idaapi

from ..format import format_ea, format_hex
from ..ida_sync import idaread
from ..memory import get_image_size
from ..models import Metadata
from ..registry import jsonrpc

logger = logging.getLogger(__name__)


def _hex_hash(getter: Callable[[], bytes | None]) -> str:
    """Return *getter()* hex-encoded, or empty string when unavailable.

    Fat Mach-O binaries can return a ``None`` hash, so a missing digest is
    reported as an empty string rather than raising.
    """
    try:
        raw = getter()
    except Exception as exc:
        logger.debug("hash getter %s failed: %s", getter, exc)
        return ""
    return raw.hex() if raw else ""


@jsonrpc
@idaread
def get_metadata() -> Metadata:
    """Get metadata about the current IDB"""
    return Metadata(
        path=idaapi.get_input_file_path(),
        module=idaapi.get_root_filename(),
        base=format_ea(idaapi.get_imagebase()),
        size=format_hex(get_image_size()),
        md5=_hex_hash(ida_nalt.retrieve_input_file_md5),
        sha256=_hex_hash(ida_nalt.retrieve_input_file_sha256),
        crc32=format_hex(ida_nalt.retrieve_input_file_crc32()),
        filesize=format_hex(ida_nalt.retrieve_input_file_size()),
    )
