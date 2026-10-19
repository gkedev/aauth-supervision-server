"""An issued token's `aud` array is bounded, and the history is looked up once per event.

A JWT audience may be an array (RFC 7519 Section 4.1.3), and a token reported without a
decision on record is one act per audience. The array is bounded (`MAX_AUD`), and each
audience is matched against what the history already holds through one index built per
event, so a report costs the history once, not once per audience.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, make_env

from aauth_supervision_server import service


def _report(ss: Any, ps: Any, clock: Any, event: str, aud: Any, eid: str = "e-1",
            jti: str = "j-1") -> Any:
    return ps.call(ss, "POST", "/event", {"event": event, "id": eid, "iat": int(clock()),
                                          "sub": SUB, "agent": AGENT, "sdi": "d-replayed",
                                          "jti": jti, "aud": aud, "exp": int(clock()) + 60})


@pytest.mark.parametrize("event", ["auth_token.issued", "person_token.issued"])
def test_an_audience_array_past_the_bound_is_refused(event: str) -> None:
    ss, ps, clock = make_env(allow_unlisted_resources=True,
                             serves_on_identity=["https://*.example"])
    assert ps.connect(ss, SUB).status == 200
    auds = [f"https://r{i}.example" for i in range(service.MAX_AUD + 1)]
    r = _report(ss, ps, clock, event, auds)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    assert _report(ss, ps, clock, event, auds[:-1], "e-2").status == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    assert sorted(h.resource for h in hist) == sorted(auds[:-1])


@pytest.mark.parametrize("event", ["auth_token.issued", "person_token.issued"])
def test_an_audience_named_twice_or_reported_again_is_one_act(event: str) -> None:
    ss, ps, clock = make_env(serves_on_identity=["https://records.example"])
    assert ps.connect(ss, SUB).status == 200
    rec, hr = "https://records.example", "https://hr.example"
    assert _report(ss, ps, clock, event, [rec, rec, hr]).status == 201
    assert _report(ss, ps, clock, event, [hr, rec], "e-2").status == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    want = [rec, hr] if event == "auth_token.issued" else [rec]
    assert sorted(h.resource for h in hist) == sorted(want)
    # Another token (another jti) at the same audience is another act.
    assert _report(ss, ps, clock, event, [rec], "e-3", jti="j-2").status == 201
    assert len(ss.store.history_for(ps.issuer, SUB, AGENT, "")) == len(want) + 1
