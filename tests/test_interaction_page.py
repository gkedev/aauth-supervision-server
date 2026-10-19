"""The connect confirmation page shows the code first, and the PS's name as plain text.

The PS's `name` comes from its own metadata (self-asserted): the page shows it with no
character the person cannot see (bidi controls among them) and cut to `MAX_NAME`, after
the code the person compares with the one their PS shows (Protocol L2384-L2400).
"""
from __future__ import annotations

from conftest import SUB, make_env

from aauth_supervision_server import service
from aauth_supervision_server.httpsig import HttpRequest


def _page(name: str) -> tuple[str, str]:
    ss, ps, _ = make_env(auto_connect=False)
    ss.resolver.fetcher.documents[f"{ps.issuer}/.well-known/aauth-person.json"]["name"] = name
    r = ps.connect(ss, SUB)
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", f"code={code}"))
    assert page.status == 200
    return page.body.decode(), code


def test_the_code_comes_before_anything_the_ps_chose() -> None:
    body, code = _page("Acme PS")
    assert body.index(code) < body.index("Acme PS") and body.index(code) < body.index(
        "https://ps.example")


def test_the_name_is_plain_and_cut() -> None:
    body, _ = _page("Acme\u202e SP\u2066" + "N" * 10_000)
    assert "\u202e" not in body and "\u2066" not in body
    assert "Acme SP " + "N" * (service.MAX_NAME - 9) + "\u2026" in body
    assert len(body) < 2_000
