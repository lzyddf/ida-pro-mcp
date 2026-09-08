"""Internal helpers shared by ``list_*`` and ``get_*`` tool implementations."""
from __future__ import annotations

from collections.abc import Mapping
from typing import TypeVar

from ..errors import IDAError, IDAErrorKind
from ..models import Page

T = TypeVar("T")
M = TypeVar("M", bound=Mapping[str, object])


def paginate(data: list[T], offset: int, count: int) -> Page[T]:
    """Slice *data* into a :class:`Page`.

    A *count* of zero means "remainder from offset". Negative inputs raise
    :class:`IDAError` so callers get a clear error rather than an empty page.
    The page always reports ``total = len(data)`` so clients know whether more
    items exist without having to walk to the end.
    """
    if offset < 0:
        raise IDAError(f"offset must be >= 0, got {offset}", IDAErrorKind.INVALID_INPUT)
    if count < 0:
        raise IDAError(f"count must be >= 0, got {count}", IDAErrorKind.INVALID_INPUT)

    total = len(data)
    end = total if count == 0 else min(offset + count, total)
    next_offset = end if end < total else None
    return {"data": data[offset:end], "total": total, "next_offset": next_offset}


def substring_filter(data: list[M], query: str, key: str) -> list[M]:
    """Case-insensitive substring filter on the *key* attribute of each item."""
    if not query:
        return data
    needle = query.lower()
    return [item for item in data if needle in str(item[key]).lower()]
