"""A connect awaiting the person's confirmation, and its code, expire; what a signer only
open registration admits can hold is bounded.

Protocol L2400: a code MUST expire no later than the pending interaction it is bound to,
and once that has expired, presenting it MUST fail with `expired` (408, L2621); the PS may
start a fresh connect for a new code. A signer the SS does not trust, admitted under open
registration, holds at most a few connects at once and the SS at most a fixed number from
all such signers (`rate_limited` beyond, with `Retry-After`, Supervision L637); a record
past its lifetime is kept one more lifetime to answer `expired`, then removed with the id
that opened it. Identifiers are bounded in length.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, make_env

from aauth_supervision_server import service
from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import SimulatedPS

LIFE = service.CONNECT_LIFETIME


def _code(r: Any) -> str:
    return str(r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"'))


def _page(ss: Any, code: str) -> Any:
    return ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", f"code={code}"))


def _confirm(ss: Any, code: str) -> Any:
    return ss.handle(HttpRequest("POST", "ss.example", "/interaction",
                                 {"content-type": "application/x-www-form-urlencoded"},
                                 f"code={code}&admin_token=operator-secret".encode()))


@pytest.mark.req("REF-041")
def test_a_connect_and_its_code_expire() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    code, loc = _code(r), r.headers["Location"]
    clock.t += LIFE - 1
    assert ps.call(ss, "GET", loc).status == 202 and _page(ss, code).status == 200
    clock.t += 1
    page = _page(ss, code)
    assert page.status == 408 and page.json()["error"] == "expired"
    assert _confirm(ss, code).status == 408
    poll = ps.call(ss, "GET", loc)
    assert poll.status == 408 and poll.json()["error"] == "expired"
    assert ps.call(ss, "GET", loc).status == 410
    # A fresh connect gets a fresh code, which the person can confirm.
    again = ps.connect(ss, SUB)
    assert again.status == 202 and _code(again) != code
    assert _confirm(ss, _code(again)).status == 200
    assert Store.k(ps.issuer, SUB) in ss.store.connections


def test_a_connect_retried_after_its_lifetime_is_no_longer_pending() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    body = {"action": "connect", "id": "c-1", "iat": int(clock()), "sub": SUB}
    assert ps.call(ss, "POST", "/connect", body).status == 202
    clock.t += LIFE
    assert ps.call(ss, "POST", "/connect", body).json() == {"status": "disconnected"}


def _stranger(ss: Any, clock: Any, n: int = 0) -> SimulatedPS:
    other = SimulatedPS(issuer=f"https://other{n}.example", transport="current", clock=clock)
    other.install(ss.resolver.fetcher)
    other.ss_jwk = ss.key.public_jwk()
    ss.cfg.open_registration = True
    return other


def _open(ss: Any, ps: SimulatedPS, clock: Any, i: int) -> Any:
    return ps.call(ss, "POST", "/connect", {"action": "connect", "id": f"c-{i}",
                                            "iat": int(clock()), "sub": f"person-{i}"})


def test_a_signer_open_registration_admits_holds_a_bounded_number(monkeypatch: Any) -> None:
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 3)
    ss, ps, clock = make_env()
    other = _stranger(ss, clock)
    codes = []
    for i in range(3):
        r = _open(ss, other, clock, i)
        assert r.status == 202
        codes.append(_code(r))
        clock.t += 100
    full = _open(ss, other, clock, 3)
    assert full.status == 429 and full.json()["error"] == "rate_limited"
    # Until the oldest is removed: two lifetimes after it was opened.
    assert int(full.headers["Retry-After"]) == 2 * LIFE - 300
    # The refused id was not taken: the same request is answered once there is room.
    clock.t += 2 * LIFE
    assert _open(ss, other, clock, 3).status == 202
    held = [p for p in ss.store.pending.values() if p.iss == other.issuer]
    assert [p.sub for p in held] == ["person-3"]
    assert not any("|c-0|" in k or k.endswith("|c-0|connect") for k in ss.store.events_seen)
    # What was removed is found under nothing: its code, its person.
    assert _page(ss, codes[0]).status == 410
    assert _open(ss, other, clock, 7).status == 202     # person-7: a lookup by person
    # A trusted PS is not bounded by it.
    for i in range(5):
        assert ps.call(ss, "POST", "/connect", {"action": "connect", "id": f"t-{i}",
                                                "iat": int(clock()), "sub": f"p{i}"}).status == 200


def test_all_such_signers_together_hold_a_bounded_number(monkeypatch: Any) -> None:
    monkeypatch.setattr(service, "MAX_UNCONFIRMED", 4)
    ss, _, clock = make_env()
    strangers = [_stranger(ss, clock, n) for n in range(3)]
    codes = [_code(_open(ss, s, clock, i)) for i, s in enumerate(strangers)]
    assert _open(ss, strangers[0], clock, 9).status == 202          # four: the cap
    # A connect the person confirmed counts no more; at the cap again, the signer holding
    # the most is refused.
    assert _confirm(ss, codes[1]).status == 200
    assert _open(ss, strangers[0], clock, 10).status == 202
    assert _open(ss, strangers[0], clock, 11).status == 429
    assert len([p for p in ss.store.pending.values()
                if p.kind == "connect" and not p.resolved]) == 4


def test_an_expired_connect_of_a_trusted_ps_is_kept() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    clock.t += 3 * LIFE
    assert _open(ss, _stranger(ss, clock), clock, 0).status == 202  # removes what it may
    assert ps.call(ss, "GET", r.headers["Location"]).status == 408


@pytest.mark.parametrize("member", ["sub", "id", "tenant"])
def test_a_connect_identifier_past_the_bound_is_refused(member: str) -> None:
    ss, ps, clock = make_env()
    body = {"action": "connect", "id": "c-1", "iat": int(clock()), "sub": SUB}
    ok = dict(body, **{member: "x" * service.MAX_ID_LEN})
    assert ps.call(ss, "POST", "/connect", ok).status in (200, 202)
    long = dict(body, id="c-2")
    long[member] = "y" * (service.MAX_ID_LEN + 1)
    r = ps.call(ss, "POST", "/connect", long)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


@pytest.mark.parametrize("member", ["sdi", "agent", "mission_s256", "jti"])
def test_an_envelope_identifier_past_the_bound_is_refused(member: str) -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    b = {"event": "auth_token.issued", "id": "e-1", "iat": int(clock()), "sub": SUB,
         "agent": AGENT, "sdi": "d-1", "jti": "j-1", member: "z" * (service.MAX_ID_LEN + 1)}
    r = ps.call(ss, "POST", "/event", b)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
