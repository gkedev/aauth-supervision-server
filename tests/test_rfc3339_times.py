"""A mission's `expires_at` is read as RFC 3339 allows it to be written.

RFC 3339 Section 5.6: the "T" and "Z" may be lower case, and `time-second` may be 60 (a
leap second, Section 5.7). Such a timestamp is a valid time, never read as expired; one
that is not a timestamp with an offset still fails closed.
"""
from __future__ import annotations

import math

import pytest

from aauth_supervision_server.store import iso_to_epoch

NEW_YEAR = iso_to_epoch("2017-01-01T00:00:00Z")


@pytest.mark.parametrize("v,want", [
    ("2017-01-01t00:00:00z", NEW_YEAR),
    ("2017-01-01T00:00:00z", NEW_YEAR),
    ("2017-01-01t01:00:00+01:00", NEW_YEAR),
    ("2016-12-31T23:59:60Z", NEW_YEAR),
    ("2016-12-31t23:59:60.5z", (NEW_YEAR or 0) + 0.5),
])
def test_a_valid_timestamp_is_its_time(v: str, want: float) -> None:
    assert iso_to_epoch(v) == want


@pytest.mark.parametrize("v", ["2016-12-31T23:59:61Z", "2016-12-31T23:60:00Z",
                               "2017-01-01T00:00:00", "2017-01-01", "soon", 7])
def test_anything_else_fails_closed(v: object) -> None:
    assert iso_to_epoch(v) == -math.inf
