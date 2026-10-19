"""Issued tokens, as a new SS learns them by replay and as any SS learns them by events.

Supervision L619: on a routing change the PS sends the new SS `auth_token.issued` "for
each outstanding token". One decision can carry two tokens (L540: the issuer is the PS
or an AS), and each is an act that can take effect until its own `exp`. A new SS has no
decision on record, so it must count the tokens by their `jti`, as an SS with the record
does. An event names its person, agent and audience (L539-L540); one that contradicts the
decision under its `sdi`, or leaves out what the SS needs to classify it, is refused.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, Clock

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy, PolicyConfig
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.testing import SimulatedPS

R = {c: f"https://{c.lower()}.example" for c in "ABC"}
POLICY = {"severity": ["unclassified", "A", "B", "C"],
          "rules": [{"resource": R[c], "class": c} for c in "ABC"],
          "prohibited_sequences": [["A", "B", "C"]], "allow_unlisted_resources": True}


def _env() -> tuple[Any, Any, Clock, Any]:
    clock = Clock()
    fetcher = StaticFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)

    def new_ss() -> SupervisionServer:
        ss = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                            trusted_ps={ps.issuer: TrustedPS(True)}),
                               Policy(PolicyConfig.from_dict(POLICY)),
                               JwksUriResolver(fetcher), SigningKey.generate("k"), clock=clock)
        ps.ss_jwk = ss.key.public_jwk()
        return ss
    return new_ss, ps, clock, new_ss()


def _issued(ps: Any, ss: Any, clock: Clock, sdi: str, jti: str, aud: str, exp: int,
            mission: str = "", **over: Any) -> int:
    ev = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
          "sub": SUB, "agent": AGENT, "jti": jti, "aud": aud, "exp": exp, "issuer": ps.issuer}
    if mission:
        ev["mission_s256"] = mission
    ev.update(over)
    return int(ps.call(ss, "POST", "/event", ev).status)


@pytest.mark.parametrize("in_mission", [False, True])
def test_a_second_token_under_one_sdi_survives_a_routing_change(in_mission: bool) -> None:
    new_ss, ps, clock, old = _env()
    t0 = int(clock.t)
    assert ps.connect(old, SUB).status == 200
    mission = ""
    if in_mission:
        _, mission = ps.propose_and_approve(old, SUB, AGENT, "# Task", list(R.values()), [])
    sdi, r, _ = ps.auth_token_request(old, SUB, AGENT, mission, R["C"])
    assert r.json()["decision"] == "allow"
    assert _issued(ps, old, clock, sdi, "c1", R["C"], t0 + 30, mission) == 201
    clock.t = t0 + 1
    assert _issued(ps, old, clock, sdi, "c2", R["C"], t0 + 3600, mission) == 201
    clock.t = t0 + 10
    new = new_ss()
    ps.replay_to(new, SUB, AGENT)
    hist = new.store.history_for(ps.issuer, SUB, AGENT, mission)
    assert sorted((h.jti, h.token_exp - t0) for h in hist) == [("c1", 30), ("c2", 3600)]
    clock.t = t0 + 200  # past c1's exp and its margin; c2 still live
    sdi_a, ra, _ = ps.auth_token_request(new, SUB, AGENT, mission, R["A"])
    assert ra.json()["decision"] == "allow"
    assert _issued(ps, new, clock, sdi_a, "a1", R["A"], t0 + 3800, mission) == 201
    _, rb, _ = ps.auth_token_request(new, SUB, AGENT, mission, R["B"])
    assert rb.json()["decision"] == "deny", rb.json()


def test_a_token_reported_again_is_one_act_and_its_exp_only_widens() -> None:
    new_ss, ps, clock, ss = _env()
    t0 = int(clock.t)
    assert ps.connect(ss, SUB).status == 200
    for exp in (t0 + 600, t0 + 900, t0 + 100):  # replayed, reissued, reported again
        assert _issued(ps, ss, clock, "d-x", "t1", R["C"], exp) == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    assert [(h.sdi, h.jti, h.token_exp - t0) for h in hist] == [("d-x", "t1", 900)]


def test_a_token_first_reported_without_its_jti_takes_it_later() -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    for jti in ("", "t7"):
        assert _issued(ps, ss, clock, "d-w", jti, R["C"], int(clock()) + 60) == 201
    assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")] == ["t7"]


def test_a_replayed_token_for_two_audiences_is_one_act_at_each() -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    for _ in range(2):
        assert _issued(ps, ss, clock, "d-v", "t8", [R["A"], R["C"]], int(clock()) + 60) == 201
    assert sorted(h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")) == [
        R["A"], R["C"]]


def test_a_replayed_token_without_a_jti_is_one_act_per_sdi() -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    for _ in range(2):
        assert _issued(ps, ss, clock, "d-y", "", R["C"], int(clock()) + 60) == 201
    assert len(ss.store.history_for(ps.issuer, SUB, AGENT, "")) == 1


@pytest.mark.parametrize("aud", [None, "", []])
def test_a_replayed_token_of_unknown_audience_is_refused(aud: Any) -> None:
    # With no decision on record the audience is all the SS knows of the act.
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-z", "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "jti": "t9", "exp": int(clock()) + 60,
            "issuer": ps.issuer}
    if aud is not None:
        body["aud"] = aud
    assert ps.call(ss, "POST", "/event", body).status == 400
    assert ss.store.history_for(ps.issuer, SUB, AGENT, "") == []


def test_an_event_scope_that_is_not_a_string_is_refused() -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    assert _issued(ps, ss, clock, "d-s", "t9", R["C"], int(clock()) + 60,
                   scope=["a", "b"]) == 400


@pytest.mark.parametrize("field", ["sub", "agent", "mission_s256"])
def test_an_issuance_naming_another_person_or_agent_than_its_decision_is_refused(
        field: str) -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    assert ps.connect(ss, "someone-else").status == 200
    _, other = ps.propose_and_approve(ss, SUB, AGENT, "# Other", list(R.values()), [])
    envelope = {"sub": "someone-else", "agent": "aauth:x@agent.example",
                "mission_s256": other}[field]
    envelope = {field: envelope}
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", R["C"])
    assert r.json()["decision"] == "allow"
    assert _issued(ps, ss, clock, sdi, "t1", R["C"], int(clock()) + 60, **envelope) == 400
    assert ss.store.history_for(ps.issuer, SUB, AGENT, "") == []


def test_a_resource_token_scope_that_is_not_a_string_is_refused() -> None:
    new_ss, ps, clock, ss = _env()
    assert ps.connect(ss, SUB).status == 200
    rt = ps.resource_token(R["C"], "read")
    import json

    from aauth_supervision_server.jwk import b64u, b64u_decode
    h, p, sig = rt.split(".")
    claims = json.loads(b64u_decode(p))
    claims["scope"] = ["read", "write"]
    bad = ".".join([h, b64u(json.dumps(claims).encode()), sig])
    body = {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "agent_token": ps.agent_token(AGENT), "resource_token": bad,
            "presented_token": "a.b.c"}
    r = ps.call(ss, "POST", "/decision", body)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
