"""The connect confirmation page takes its form posts from its own origin only.

The page locks after five wrong operator tokens (until restart). Its form is a plain
`application/x-www-form-urlencoded` POST, which a browser sends to any site without a
preflight, so any page the operator opened could post five wrong tokens and lock them out.
A post a browser marks as coming from another site (`Origin` not the SS's issuer, or
`Sec-Fetch-Site` neither `same-origin` nor `none`) is refused before it counts. A client
that is not a browser sends neither and is judged by its token alone.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import pytest
from conftest import SUB, make_env

from aauth_supervision_server.httpsig import HttpRequest


def _env() -> tuple[Any, str]:
    ss, ps, _ = make_env(auto_connect=False)
    ss.cfg.admin_token = "operator-secret"
    r = ps.connect(ss, SUB)
    return ss, r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')


def _post(ss: Any, code: str, token: str, **headers: str) -> Any:
    h = {"content-type": "application/x-www-form-urlencoded", **headers}
    return ss.handle(HttpRequest("POST", "ss.example", "/interaction", h,
                                 urlencode({"code": code, "admin_token": token}).encode()))


@pytest.mark.parametrize("headers", [{"origin": "https://evil.example"}, {"origin": "null"},
                                     {"sec-fetch-site": "cross-site"},
                                     {"sec-fetch-site": "same-site"},
                                     {"origin": "https://ss.example", "sec-fetch-site": "cross-site"}])
def test_a_post_from_another_site_is_refused_before_it_counts(headers: dict[str, str]) -> None:
    ss, code = _env()
    for _ in range(10):
        r = _post(ss, code, "wrong", **headers)
        assert r.status == 403 and b"another site" in r.body
    assert _post(ss, code, "operator-secret", **headers).status == 403
    assert _post(ss, code, "operator-secret", origin="https://ss.example",
                 **{"sec-fetch-site": "same-origin"}).status == 200   # not locked


@pytest.mark.parametrize("headers", [{}, {"origin": "https://ss.example"},
                                     {"sec-fetch-site": "same-origin"},
                                     {"sec-fetch-site": "none"}])
def test_a_post_from_the_page_itself_or_no_browser_counts(headers: dict[str, str]) -> None:
    ss, code = _env()
    for _ in range(5):
        assert _post(ss, code, "wrong", **headers).status == 403
    late = _post(ss, code, "operator-secret", **headers)    # the connect failed for good
    assert late.status == 410 and late.json()["error"] == "invalid_code"


def _post_at(ss: Any, authority: str, code: str, origin: str) -> Any:
    h = {"content-type": "application/x-www-form-urlencoded", "origin": origin,
         "sec-fetch-site": "same-origin"}
    return ss.handle(HttpRequest("POST", authority, "/interaction", h,
                                 urlencode({"code": code, "admin_token": "operator-secret"})
                                 .encode()))


@pytest.mark.parametrize("authority", ["127.0.0.1:8443", "localhost:8443", "[::1]:8443"])
def test_the_page_opened_on_loopback_takes_its_own_form(authority: str) -> None:
    # The development page is often opened on the listener itself: its origin is then
    # http://<loopback>:<port>, which is not the https issuer, and is still its own.
    ss, code = _env()
    assert _post_at(ss, authority, code, f"http://{authority}").status == 200


@pytest.mark.parametrize("authority,origin", [
    ("evil.example:8443", "http://evil.example:8443"),     # a name that resolves to loopback
    ("ss.example", "http://127.0.0.1:8443"),
    ("127.0.0.1:8443", "http://127.0.0.1:9999"),
    ("127.0.0.1:8443", "https://127.0.0.1:8443"),
])
def test_another_origin_is_still_refused(authority: str, origin: str) -> None:
    ss, code = _env()
    r = _post_at(ss, authority, code, origin)
    assert r.status == 403 and b"another site" in r.body
