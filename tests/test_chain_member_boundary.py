"""Composition across the mission boundary for an agent acting in another agent's mission.

In a call chain the downstream agent acts under the upstream mission (core: the PS
"evaluates the request against that mission" and copies its `mission_s256`), with its own
agent identifier. Its acts in that mission and its acts outside any mission are the same
chain of what it did, and the mission's owner's acts outside any mission are part of the
mission's chain too: each side must see the other, in both directions.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

REC, CHAT, DOCS = "https://records.example", "https://chat.example", "https://docs.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": DOCS, "class": "write"}]
RELAY = "aauth:relay@tools.example"


def _env() -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[["read_sensitive", "send_internal"]],
                             prohibited_sequences=[], high_impact=[])
    return ss, ps, clock, connected((ss, ps, clock), resources=(REC, CHAT, DOCS))


def _take(ss: Any, ps: Any, agent: str, s256: str, res: str) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, agent, s256, res)
    d = str(r.json()["decision"])
    if d == "allow":
        assert ps.issued(ss, SUB, agent, s256, sdi, res).status == 201
    return d


def test_a_chain_member_in_the_mission_sees_the_owners_acts_outside_it() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, AGENT, "", REC) == "allow"     # the owner reads, outside missions
    assert _take(ss, ps, RELAY, s256, CHAT) == "deny"   # the relay sends, in the mission


def test_a_chain_member_outside_missions_sees_what_it_did_in_the_mission() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, RELAY, s256, REC) == "allow"   # the relay reads, in the mission
    assert _take(ss, ps, RELAY, "", CHAT) == "deny"     # then sends, outside missions


def test_a_chain_members_acts_outside_missions_reach_the_mission() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, RELAY, "", REC) == "allow"     # the relay reads, outside missions
    assert _take(ss, ps, RELAY, s256, DOCS) == "allow"  # then takes part in the mission
    assert _take(ss, ps, AGENT, s256, CHAT) == "deny"   # its read is in the mission's chain


def test_an_unrelated_agent_outside_missions_is_not_drawn_in() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, AGENT, s256, REC) == "allow"
    assert _take(ss, ps, "aauth:other@else.example", "", CHAT) == "allow"
