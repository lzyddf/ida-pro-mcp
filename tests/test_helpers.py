"""Tests for tools/_helpers.py: paginate + substring_filter."""
from __future__ import annotations

import pytest

from ida_pro_mcp.plugin.errors import IDAError
from ida_pro_mcp.plugin.tools._helpers import paginate, substring_filter


class TestPaginate:
    def test_basic_slice(self):
        page = paginate([{"v": i} for i in range(5)], 1, 2)
        assert page["data"] == [{"v": 1}, {"v": 2}]
        assert page["total"] == 5
        assert page["next_offset"] == 3

    def test_count_zero_returns_remainder(self):
        page = paginate([{"v": i} for i in range(3)], 1, 0)
        assert page["data"] == [{"v": 1}, {"v": 2}]
        assert page["next_offset"] is None

    def test_last_page_has_no_next(self):
        page = paginate([{"v": i} for i in range(3)], 0, 5)
        assert page["data"] == [{"v": 0}, {"v": 1}, {"v": 2}]
        assert page["next_offset"] is None

    def test_negative_offset_raises(self):
        with pytest.raises(IDAError):
            paginate([], -1, 1)

    def test_negative_count_raises(self):
        with pytest.raises(IDAError):
            paginate([], 0, -1)

    def test_offset_beyond_total_returns_empty(self):
        page = paginate([{"v": 1}], 5, 10)
        assert page["data"] == []
        assert page["total"] == 1
        assert page["next_offset"] is None


class TestSubstringFilter:
    def test_empty_query_returns_all(self):
        items = [{"name": "foo"}, {"name": "bar"}]
        assert substring_filter(items, "", "name") == items

    def test_case_insensitive(self):
        items = [{"name": "Foo"}, {"name": "bar"}]
        assert substring_filter(items, "FOO", "name") == [{"name": "Foo"}]

    def test_substring_match(self):
        items = [{"name": "foobar"}, {"name": "barbaz"}]
        assert substring_filter(items, "bar", "name") == items

    def test_no_match_returns_empty(self):
        items = [{"name": "foo"}]
        assert substring_filter(items, "xyz", "name") == []
