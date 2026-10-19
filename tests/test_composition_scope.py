"""What an act composes with is one scope, for history and for open acts alike.

- Certain: the act's own mission (outside missions: every mission its agent owns or
  has acted in), and the acts outside missions of every agent of that chain (the agent,
  the missions' owners and members), in both directions.
- Uncertain: the person's other missions where an agent of the chain, or of its agent
  provider, owns or has acted, and the acts outside missions of the provider's other
  agents.

An open act (an ask the person is deciding, an allow not yet reported issued) counts
wherever a recorded act would, always as uncertain (Supervision L211: a request may
arrive while another act is open).
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

REC, CHAT, DOCS = "https://records.example", "https://chat.example", "https://docs.example"
RULES = [{"resource": REC, "class": "read_sensitive"}, {"resource": CHAT, "class": "send_internal"},
         {"resource": DOCS, "class": "write"}]
SIBLING = "aauth:assistant-2@agent.example"
RELAY = "aauth:relay@tools.example"     # another provider


def _env() -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[["read_sensitive", "send_internal"]],
                             prohibited_sequences=[], high_impact=[])
    return ss, ps, clock, connected((ss, ps, clock), resources=(REC, CHAT, DOCS))


def _mission(ss: Any, ps: Any, agent: str = AGENT) -> str:
    r, s256 = ps.propose_and_approve(ss, SUB, agent, f"# Task {ps.nid('t')}", [REC, CHAT, DOCS], [])
    assert r.status == 200 and s256
    return str(s256)


def _take(ss: Any, ps: Any, agent: str, where: str, resource: str, issue: bool = True) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, agent, where, resource)
    d = r.json()["decision"]
    if issue and d == "allow":
        assert ps.issued(ss, SUB, agent, where, sdi, resource).status == 201
    return str(d)


@pytest.mark.parametrize("read_at,send_at", [
    ("other mission", "first"), ("first", "other mission"),
    ("sibling outside", "first"), ("sibling outside", ""), ("sibling mission", ""),
    ("first", "sibling outside")])
def test_an_open_act_in_the_uncertain_scope_is_asked(read_at: str, send_at: str) -> None:
    ss, ps, _, first = _env()
    places = {"first": (AGENT, first), "": (AGENT, ""),
              "other mission": (AGENT, _mission(ss, ps)),
              "sibling outside": (SIBLING, ""), "sibling mission": (SIBLING, _mission(ss, ps, SIBLING))}
    reader, read_where = places[read_at]
    sender, send_where = places[send_at]
    assert _take(ss, ps, reader, read_where, REC, issue=False) == "allow"  # open, not issued
    assert _take(ss, ps, sender, send_where, CHAT) == "ask"


@pytest.mark.parametrize("reader,sender", [(AGENT, RELAY), (RELAY, AGENT)])
def test_the_outside_acts_of_one_chain_compose_in_both_directions(reader: str,
                                                                 sender: str) -> None:
    # RELAY (another provider) took part in AGENT's mission (an act of no class in the
    # pair): one chain.
    ss, ps, _, first = _env()
    assert _take(ss, ps, RELAY, first, DOCS) == "allow"
    assert _take(ss, ps, reader, "", REC) == "allow"
    assert _take(ss, ps, sender, "", CHAT) == "deny"


def test_an_open_act_of_the_chain_outside_missions_is_asked() -> None:
    ss, ps, _, first = _env()
    assert _take(ss, ps, RELAY, first, DOCS) == "allow"
    assert _take(ss, ps, AGENT, "", REC, issue=False) == "allow"
    assert _take(ss, ps, RELAY, "", CHAT) == "ask"


def test_an_agent_outside_the_chain_and_the_provider_is_not_drawn_in() -> None:
    ss, ps, _, first = _env()
    assert _take(ss, ps, AGENT, "", REC, issue=False) == "allow"
    assert _take(ss, ps, RELAY, "", CHAT) == "allow"  # RELAY never acted in AGENT's missions


def test_an_act_of_the_agent_outside_missions_is_counted_once() -> None:
    # A sequence that repeats a class needs two acts of it; one act seen twice is not two.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[],
                             prohibited_sequences=[["write", "write", "send_internal"]],
                             high_impact=[])
    connected((ss, ps, clock), resources=(REC, CHAT, DOCS))
    assert _take(ss, ps, AGENT, "", DOCS) == "allow"
    assert _take(ss, ps, AGENT, "", CHAT) == "allow"
