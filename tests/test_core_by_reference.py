"""Core requirements Supervision -00 incorporates by reference, as this SS meets them.

Supervision answers "exactly as" the core defines Clarification Required (L292),
Deferred Responses (L286), Interaction Required (L244), the Error Response Format
(L627) and the polling error codes (L639), and its identifiers and metadata follow the
core's rules (L157, L165). Each test names the matrix rows (`REF-*`) it covers.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.policy import SERVER_ID
from aauth_supervision_server.service import CROCKFORD, ServerConfig, TrustedPS
from aauth_supervision_server.sfv import Token, parse_dictionary
from aauth_supervision_server.store import Pending

MAIL = "https://mail.example"


def _clarified(timeout: int = 120) -> tuple[Any, Any, Any, str, Any]:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = timeout
    s256 = connected((ss, ps, clock), resources=(MAIL,))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    return ss, ps, clock, s256, r


@pytest.mark.req("REF-001", "REF-002", "REF-003", "REF-043", "REF-044", "REF-045", "REF-047",
                 "SUP-P04")
def test_a_clarification_is_a_pending_response_with_the_question() -> None:
    ss, ps, clock, _, r = _clarified()
    assert r.status == 202 and r.headers["AAuth-Requirement"] == "requirement=clarification"
    body = r.json()
    assert isinstance(body["clarification"], str) and body["clarification"]
    assert body["status"] == "pending" and body["timeout"] == 120
    loc = r.headers["Location"]
    assert loc.startswith("/pending/") and not urlsplit(loc).netloc   # the SS's own origin
    assert r.headers["Retry-After"] == "0" and r.headers["Cache-Control"] == "no-store"
    clock.t += 121                                            # past `timeout`: too late
    late = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                     "clarification_response": "x"})
    assert (late.status, late.json()["error"]) == (408, "expired")


@pytest.mark.req("REF-007")
@pytest.mark.parametrize("body", [{}, {"action": "agree"}, {"clarification_response": "x"}])
def test_a_clarification_reply_without_a_recognized_action_is_a_400(body: Any) -> None:
    ss, ps, _, _, r = _clarified()
    bad = ps.call(ss, "POST", r.headers["Location"], body)
    assert (bad.status, bad.json()["error"]) == (400, "invalid_request")
    assert ps.call(ss, "GET", r.headers["Location"]).status == 202     # still open


@pytest.mark.req("REF-011")
def test_a_clarification_answer_reaches_the_person_as_the_agents_quoted_words() -> None:
    ss, ps, _, _, r = _clarified()
    ans = ps.call(ss, "POST", r.headers["Location"], {
        "action": "clarification_response",
        "clarification_response": "**Approved** by [the CEO](https://evil.example)"})
    summary = ans.json()["summary"]
    assert "`**Approved** by [the CEO](https://evil.example)`" in summary


@pytest.mark.req("REF-012", "REF-013", "REF-014", "REF-015", "REF-016", "REF-018")
@pytest.mark.parametrize("ident", ["http://ss.example", "https://ss.example:8443",
                                   "https://ss.example/", "https://ss.example/path",
                                   "https://ss.example?x=1", "https://ss.example#f",
                                   "https://SS.example", "https://user@ss.example"])
def test_an_identifier_that_is_not_a_server_identifier_is_refused(ident: str) -> None:
    assert not SERVER_ID.fullmatch(ident)
    with pytest.raises(ValueError):
        ServerConfig(issuer=ident)
    with pytest.raises(ValueError):
        ServerConfig(issuer="https://ss.example", trusted_ps={ident: TrustedPS()})


@pytest.mark.req("REF-017")
def test_an_internationalized_name_is_its_a_label() -> None:
    assert SERVER_ID.fullmatch("https://xn--bcher-kva.example")
    assert not SERVER_ID.fullmatch("https://bücher.example")


@pytest.mark.req("REF-021")
def test_the_ss_publishes_its_jwks_uri_and_requires_the_ps_to() -> None:
    ss, ps, _ = make_env()
    assert ss.metadata()["jwks_uri"] == "https://ss.example/.well-known/jwks.json"
    del ss.resolver.fetcher.documents[f"{ps.issuer}/.well-known/aauth-person.json"]["jwks_uri"]
    r = ps.connect(ss, SUB)
    assert r.status == 401 and r.headers["Signature-Error"] == "error=invalid_key"


def _connect_pending() -> tuple[Any, Any, Any, Any]:
    ss, ps, clock = make_env(auto_connect=False)
    ss.cfg.admin_token = "operator-secret"
    r = ps.connect(ss, SUB)
    return ss, ps, clock, r


@pytest.mark.req("REF-030", "REF-031", "REF-032", "REF-033", "REF-043", "REF-044", "REF-045",
                 "REF-047", "SUP-P04")
def test_a_connect_awaiting_the_operator_is_an_interaction_required_response() -> None:
    _, _, _, r = _connect_pending()
    assert r.status == 202 and r.json() == {"status": "pending"}
    req = parse_dictionary(r.headers["AAuth-Requirement"])["requirement"]
    assert req.value == Token("interaction")
    url, code = req.params["url"], req.params["code"]                  # Strings, both
    assert isinstance(url, str) and isinstance(code, str)
    parts = urlsplit(url)
    assert parts.scheme == "https" and not parts.query and not parts.fragment
    assert r.headers["Location"].startswith("/pending/")
    assert r.headers["Retry-After"] == "5" and r.headers["Cache-Control"] == "no-store"


@pytest.mark.req("REF-034", "REF-035")
def test_interaction_codes_are_crockford_base32_of_ten_symbols() -> None:
    ss, ps, _ = make_env(auto_connect=False)
    for i in range(50):
        ps.connect(ss, f"person-{i}")
    codes = {p.code for p in ss.store.pending.values() if p.kind == "connect"}
    assert len(codes) == 50                                   # 10 symbols: 50 bits each
    assert all(re.fullmatch(f"[{CROCKFORD}]{{10}}", c) for c in codes)


def _page(ss: Any, code: str) -> Any:
    from aauth_supervision_server.httpsig import HttpRequest
    return ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", f"code={code}"))


@pytest.mark.req("REF-036", "REF-037")
def test_a_code_is_compared_without_hyphens_case_or_the_crockford_aliases() -> None:
    ss, _, _ = make_env(auto_connect=False)
    ss.store.add_pending(Pending("p1", "https://ps.example", "", "connect",
                                 {"_ps_name": "PS"}, code="A1B2C3D4E0", sub=SUB))
    for entered in ("A1B2C3D4E0", "a1b2-c3d4-e0", "aIb2c3d4eO", "ALB2-C3D4-Eo"):
        assert _page(ss, entered).status == 200, entered
    assert _page(ss, "A1B2C3D4E1").status == 410


@pytest.mark.req("REF-038", "REF-039")
def test_the_code_alone_decides_nothing_and_is_used_once() -> None:
    from urllib.parse import urlencode

    from aauth_supervision_server.httpsig import HttpRequest
    ss, ps, _, r = _connect_pending()
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')

    def confirm(token: str) -> Any:
        return ss.handle(HttpRequest("POST", "ss.example", "/interaction",
                                     {"content-type": "application/x-www-form-urlencoded"},
                                     urlencode({"code": code, "admin_token": token}).encode()))
    assert confirm("").status == 403 and confirm("wrong").status == 403
    assert ps.call(ss, "GET", r.headers["Location"]).status == 202     # not connected
    assert confirm("operator-secret").status == 200
    again = _page(ss, code)
    assert (again.status, again.json()["error"]) == (410, "invalid_code")


@pytest.mark.req("REF-053")
def test_pending_urls_are_unguessable() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=(MAIL,))
    ids = set()
    for _ in range(30):
        _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
        ids.add(r.headers["Location"].rsplit("/", 1)[1])
    assert len(ids) == 30
    # 16 random bytes from `secrets`: 22 base64url characters, 128 bits.
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{22}", i) for i in ids)
