"""What `auth_token.issued` tells the SS about a token's lifetime and its resource.

Two reports of issuance under one sdi are two tokens (or one reported twice), and the act
can take effect while either is live: the later report must not shorten the window. And a
replayed issuance names its resource in `aud`, which the SS accepts as a string or a JWT
audience array: the act is the act at that resource, whichever form carries it, and an
audience that is not a server identifier is refused, as it is in a decision request.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

A, B, C = "https://a.example", "https://b.example", "https://c.example"
OVER = dict(severity=["unclassified", "A", "B", "C"],
            rules=[{"resource": A, "class": "A"}, {"resource": B, "class": "B"},
                   {"resource": C, "class": "C"}],
            prohibited_pairs=[], prohibited_sequences=[["A", "B", "C"]], high_impact=[],
            r3_member=None, resource_budgets={}, budgets={})


def _env() -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(**OVER)
    return ss, ps, clock, connected((ss, ps, clock), resources=(A, B, C))


def _issued(ss: Any, ps: Any, clock: Any, s256: str, sdi: str, aud: Any,
            exp: int | None) -> int:
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": ps.nid("at"), "aud": aud,
            "issuer": ps.issuer}
    if exp is not None:
        body["exp"] = exp
    return int(ps.call(ss, "POST", "/event", body).status)


def _take(ss: Any, ps: Any, s256: str, res: str) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, res)
    d = str(r.json()["decision"])
    if d == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, res).status == 201
    return d


@pytest.mark.parametrize("exps", [(3600, 10), (None, 10)])
def test_a_second_issuance_under_one_sdi_never_shortens_the_window(exps: Any) -> None:
    ss, ps, clock, s256 = _env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, C)
    assert r.json()["decision"] == "allow"
    for e in exps:
        assert _issued(ss, ps, clock, s256, sdi, C,
                       None if e is None else int(clock()) + e) == 201
    clock.t += 20                       # the second token has expired, the first has not
    assert _take(ss, ps, s256, A) == "allow"
    assert _take(ss, ps, s256, B) == "deny"


def test_a_later_issuance_with_a_later_exp_extends_the_window() -> None:
    ss, ps, clock, s256 = _env()
    sdi, _, _ = ps.auth_token_request(ss, SUB, AGENT, s256, C)
    assert _issued(ss, ps, clock, s256, sdi, C, int(clock()) + 10) == 201
    assert _issued(ss, ps, clock, s256, sdi, C, int(clock()) + 3600) == 201
    entry = ss.store.history_for(ps.issuer, SUB, AGENT, s256)[-1]
    assert entry.token_exp == int(clock()) + 3600


@pytest.mark.parametrize("aud", [[A], [B, A]])
def test_a_replayed_audience_array_is_classified_by_its_resource(aud: list[str]) -> None:
    ss, ps, clock, s256 = _env()
    assert _issued(ss, ps, clock, s256, "d-old", aud, int(clock()) + 3600) == 201
    # A token for several audiences can be presented at each: one act per audience.
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [(h.action_class, h.resource, h.sdi) for h in hist] == [
        (r.removeprefix("https://")[0].upper(), r, "d-old") for r in aud]


@pytest.mark.parametrize("aud", ["https://A.example", "https://a.example/", "a.example",
                                 [A, "https://A.example"], []])
def test_a_replayed_audience_that_is_not_a_server_identifier_is_refused(aud: Any) -> None:
    ss, ps, clock, s256 = _env()
    assert _issued(ss, ps, clock, s256, "d-old", aud, int(clock()) + 3600) == 400
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []


def test_a_replayed_issuance_with_no_audience_is_refused() -> None:
    # Booked with no resource it would be unclassified and compose with nothing; refused,
    # the PS learns it left out a member L540 lists (tests/test_replay_tokens.py).
    ss, ps, clock, s256 = _env()
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-old", "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "j", "issuer": ps.issuer}
    assert ps.call(ss, "POST", "/event", body).status == 400
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []


def test_the_same_token_reported_again_with_an_earlier_exp_keeps_its_window() -> None:
    ss, ps, clock, s256 = _env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, C)
    for exp in (3600, 10):
        body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi,
                "iat": int(clock()), "sub": SUB, "agent": AGENT, "mission_s256": s256,
                "jti": "at-same", "aud": C, "exp": int(clock()) + exp, "issuer": ps.issuer}
        assert ps.call(ss, "POST", "/event", body).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert h.token_exp == int(clock()) + 3600


def test_an_exp_with_a_fraction_is_read_as_the_tokens_exp() -> None:
    """RFC 7519 Section 2: a NumericDate is a JSON number, and non-integer values can be
    represented; `auth_token.issued` reports the issued token's `exp` (Supervision L540).
    Refused as `invalid_request`, which the PS does not retry (L631), the issuance would
    never be recorded, and the token would stop composing once its allow left the open
    window. A fraction rounds `exp` up, so a token is never read as shorter lived than it
    is."""
    ss, ps, clock, s256 = _env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, C)
    assert r.json()["decision"] == "allow"
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi,
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "mission_s256": s256,
            "jti": "at-frac", "aud": C, "exp": int(clock()) + 3000.5, "issuer": ps.issuer}
    assert ps.call(ss, "POST", "/event", body).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert h.token_exp == int(clock()) + 3001
    clock.t += 3000                     # the C token is still live: A then B completes A, B, C
    assert _take(ss, ps, s256, A) == "allow"
    assert _take(ss, ps, s256, B) == "deny"


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_a_numericdate_that_is_not_finite_is_refused(bad: float) -> None:
    ss, ps, clock, s256 = _env()
    sdi, _, _ = ps.auth_token_request(ss, SUB, AGENT, s256, C)
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "j", "aud": C,
            "exp": bad, "issuer": ps.issuer}
    r = ps.call(ss, "POST", "/event", body)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
