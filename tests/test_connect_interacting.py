"""A pending connect reports `interacting` once the person is at the interaction page.

Protocol L2523: `status` is `"pending"` while the request is waiting, and `"interacting"`
when the user has arrived at the interaction endpoint. The person arrives by opening the
page with the code (L2384-L2400); the PS polling the pending URL is then told so.
"""
from __future__ import annotations

import pytest
from conftest import SUB, make_env

from aauth_supervision_server.httpsig import HttpRequest


def _connect() -> tuple:
    ss, ps, _ = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    assert r.status == 202
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
    return ss, ps, code, r.headers["Location"]


@pytest.mark.req("REF-047")
def test_the_status_is_pending_until_the_person_arrives_then_interacting() -> None:
    ss, ps, code, loc = _connect()
    assert ps.call(ss, "GET", loc).json() == {"status": "pending"}
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", f"code={code}"))
    assert page.status == 200
    poll = ps.call(ss, "GET", loc)
    assert poll.status == 202 and poll.json() == {"status": "interacting"}
    # The connect retried reports the same.
    assert ps.connect(ss, SUB).json() == {"status": "interacting"}


def test_a_wrong_code_is_no_arrival() -> None:
    ss, ps, _, loc = _connect()
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", "code=WRONG"))
    assert page.status == 410
    assert ps.call(ss, "GET", loc).json() == {"status": "pending"}
