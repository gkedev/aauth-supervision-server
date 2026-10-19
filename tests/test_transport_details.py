"""Transport details the profile and the core define.

* RFC 9421 Section 2.1 replaces an obs-fold with one space and changes nothing else in a
  field value: other whitespace inside the value is kept as it is.
* A query on a signed endpoint is a component the SS requires, so it is required through
  the signature profile: a request that leaves it uncovered is answered 401
  `invalid_input` naming it (core L2242, L2245), and a second label that covers it is used.
* An interaction code is compared as core Interaction Code Format has it (L2390, L2392):
  hyphens dropped, case ignored, I and L read as 1 and O as 0.
"""
from __future__ import annotations

from conftest import SUB, make_env
from test_httpsig_semantics import _base

from aauth_supervision_server.httpsig import HttpRequest


def test_an_obs_fold_becomes_one_space_and_nothing_else_changes() -> None:
    req = HttpRequest("GET", "ss.example", "/", {"x-a": "a  b\r\n c"})
    assert '"x-a": a  b c\n' in _base(["x-a"], req)


def test_an_uncovered_query_is_an_invalid_input_naming_it() -> None:
    ss, ps, clock = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-q", "iat": int(clock()),
                                        "sub": SUB})
    req.query = "x=1"
    r = ss.handle(req)
    assert r.status == 401 and r.json()["error"] == "invalid_input"
    assert "required_input=" in r.headers["Signature-Error"]
    assert "@query" in r.headers["Signature-Error"]


def test_a_second_label_that_covers_the_query_is_used() -> None:
    from aauth_supervision_server.httpsig import sign_message
    ss, ps, clock = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-q2", "iat": int(clock()),
                                        "sub": SUB})
    req.query = "x=1"
    sk = (f'a=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}", '
          f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"')
    base = ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"]
    ha = sign_message(base, ps.key, sk, req, label="a", created=int(clock()))
    hs = sign_message(base + ["@query"], ps.key, sk, req, label="sig", created=int(clock()))
    req.headers["signature-key"] = sk
    for h in ("Signature-Input", "Signature"):
        req.headers[h.lower()] = ha[h] + ", " + hs[h]
    assert ss.handle(req).status == 200


def _confirm(ss, code: str):  # type: ignore[no-untyped-def]
    return ss.handle(HttpRequest("POST", "ss.example", "/interaction", {},
                                 f"code={code}&admin_token=operator-secret".encode()))


def test_an_interaction_code_is_read_as_the_core_format_has_it() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    assert ps.connect(ss, SUB).status == 202
    p = next(x for x in ss.store.pending.values() if x.kind == "connect")
    p.code = "AB01CD10EF"
    ss.store.add_pending(p)  # indexed under the code it now has
    typed = "ab-ol-cd-io-ef"  # lower case, hyphens, O for 0 and I/L for 1
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"",
                                 query=f"code={typed}"))
    assert page.status == 200
    assert _confirm(ss, typed).status == 200
    assert f"{ps.issuer}|{SUB}" in ss.store.connections
