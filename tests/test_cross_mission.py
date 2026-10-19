"""Composition across an agent's missions.

This SS approves a mission proposal by policy, so a second mission is not the person's
approval: an agent that reads in one mission and sends in another has done both, and a
token from the first mission stays usable until its `exp` even after that mission ends.
The acts of the agent's other missions (missions of the same person that the agent, or an
agent of its chain, has acted in) therefore compose with an act, as uncertain acts: a
prohibited composition that needs one is put to the person, never denied by the SS on its
own, and a "no" the person gave to it with reach is applied. Budgets stay per mission.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

REC, DOCS, CHAT = "https://records.example", "https://docs.example", "https://chat.example"
PAY = "https://pay.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": DOCS, "class": "write"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": PAY, "class": "payment"}]
TOOLS = [{"name": "WebSearch", "description": "Search"}]


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [["read_sensitive", "send_internal"]])
    over.setdefault("prohibited_sequences", [])
    over.setdefault("high_impact", [])
    ss, ps, clock = make_env(rules=RULES, **over)
    s256 = connected((ss, ps, clock), resources=(REC, DOCS, CHAT, PAY))
    return ss, ps, clock, s256


def _mission(ss: Any, ps: Any, agent: str = AGENT) -> str:
    # A description of its own: the same blob would be the same mission (the same s256).
    r, s256 = ps.propose_and_approve(ss, SUB, agent, f"# Another task {ps.nid('t')}",
                                     [REC, DOCS, CHAT, PAY], TOOLS)
    assert r.status == 200 and s256
    assert len({m.s256 for m in ss.store.missions.values()}) == len(ss.store.missions)
    return str(s256)


def _take(ss: Any, ps: Any, s256: str, resource: str, agent: str = AGENT) -> tuple[str, dict]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, agent, s256, resource)
    d = r.json()
    if d["decision"] == "allow":
        assert ps.issued(ss, SUB, agent, s256, sdi, resource).status == 201
    return sdi, d


def test_a_pair_split_across_two_missions_is_asked_never_denied() -> None:
    ss, ps, _, a = _env()
    b = _mission(ss, ps)
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    _, d = _take(ss, ps, b, CHAT)
    # Certain evidence on both sides: inside one mission this is denied (below).
    assert d["decision"] == "ask" and d["recommendation"] == "deny"
    assert "`read_sensitive`, then `send_internal`" in d["summary"]
    assert "another mission" in d["summary"]
    assert _take(ss, ps, a, CHAT)[1]["decision"] == "deny"


def test_a_mission_completed_first_still_composes_with_the_next() -> None:
    ss, ps, clock, a = _env()
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    done = ps.call(ss, "POST", f"/mission/{a}", {
        "action": "completion", "sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "summary": "Done."})
    assert done.json()["decision"] == "allow"
    assert ps.call(ss, "POST", f"/mission/{a}", {
        "action": "terminated", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "reason": "completed"}).status == 201
    b = _mission(ss, ps)
    assert _take(ss, ps, b, CHAT)[1]["decision"] == "ask"


def test_a_sequence_across_three_missions_is_asked() -> None:
    ss, ps, _, a = _env(prohibited_pairs=[],
                        prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    b, c = _mission(ss, ps), _mission(ss, ps)
    assert len({a, b, c}) == 3
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    assert _take(ss, ps, b, DOCS)[1]["decision"] == "allow"
    _, d = _take(ss, ps, c, CHAT)
    assert d["decision"] == "ask"
    assert "`read_sensitive`, then `write`, then `send_internal`" in d["summary"]


def test_an_act_outside_missions_that_joins_two_missions_is_asked() -> None:
    ss, ps, _, a = _env(prohibited_pairs=[],
                        prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    b = _mission(ss, ps)
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    assert _take(ss, ps, b, DOCS)[1]["decision"] == "allow"
    assert _take(ss, ps, "", CHAT)[1]["decision"] == "ask"


def test_a_no_given_across_missions_is_applied() -> None:
    ss, ps, _, a = _env()
    b = _mission(ss, ps)
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    sdi, d = _take(ss, ps, b, CHAT)
    assert d["decision"] == "ask"
    assert "mission" in [o["value"] for o in d["apply_options"]]
    assert ps.resolved(ss, SUB, AGENT, b, sdi, "deny", apply="mission").status == 201
    # The SS applies the person's answer with reach (Supervision L582), as offered.
    assert _take(ss, ps, b, CHAT)[1]["decision"] == "deny"


def test_budgets_stay_per_mission_across_missions() -> None:
    ss, ps, _, a = _env(budgets={"payment": {"max_count": 1}})
    b = _mission(ss, ps)
    assert _take(ss, ps, a, PAY)[1]["decision"] == "allow"
    assert _take(ss, ps, a, PAY)[1]["decision"] == "deny"
    assert _take(ss, ps, b, PAY)[1]["decision"] == "allow"


def test_the_mission_of_another_providers_agent_does_not_compose() -> None:
    # Another agent of the same provider does, as uncertain (tests/test_agent_provider.py).
    ss, ps, _, a = _env()
    other = "aauth:other@else.example"
    theirs = _mission(ss, ps, other)
    assert _take(ss, ps, theirs, REC, other)[1]["decision"] == "allow"
    assert _take(ss, ps, a, CHAT)[1]["decision"] == "allow"


def test_a_call_chain_agent_acting_in_another_mission_joins_its_chain() -> None:
    # The intermediary acted in mission A (a call chain under A's mission); its acts in
    # its own mission B compose with A, as uncertain.
    ss, ps, _, a = _env()
    mid = "aauth:intermediary@agent.example"
    assert _take(ss, ps, a, REC, mid)[1]["decision"] == "allow"
    b = _mission(ss, ps, mid)
    assert _take(ss, ps, b, CHAT, mid)[1]["decision"] == "ask"


def test_another_persons_mission_of_the_same_agent_does_not_compose() -> None:
    # (iss, sub) is one person (Supervision L199): an agent's mission for someone else is
    # not part of this person's chain.
    ss, ps, _, a = _env()
    other_sub = "another-person"
    assert ps.connect(ss, other_sub).status == 200
    r, theirs = ps.propose_and_approve(ss, other_sub, AGENT, "# Their task", [REC, CHAT], TOOLS)
    assert r.status == 200 and theirs
    sdi, rr, _ = ps.auth_token_request(ss, other_sub, AGENT, theirs, REC)
    assert rr.json()["decision"] == "allow"
    assert ps.issued(ss, other_sub, AGENT, theirs, sdi, REC).status == 201
    assert _take(ss, ps, a, CHAT)[1]["decision"] == "allow"


def test_an_old_no_outside_missions_applies_to_two_missions() -> None:
    # 0.1.x offered `mission` for a composition asked outside any mission, so a migrated
    # snapshot can hold such a "no" (a mission reach with no mission holds outside
    # missions). Recorded acts complete the composition, so the answer applies.
    from aauth_supervision_server.store import Reach
    ss, ps, _, a = _env(prohibited_pairs=[],
                        prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    b = _mission(ss, ps)
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    assert _take(ss, ps, b, DOCS)[1]["decision"] == "allow"
    ss.store.reach.append(Reach("mission", ps.issuer, SUB, AGENT, f"send_internal|{CHAT}", "",
                                ["read_sensitive", "write", "send_internal"], "deny"))
    assert _take(ss, ps, "", CHAT)[1]["decision"] == "deny"


def test_a_mission_answer_covers_the_rest_of_that_mission_and_no_other() -> None:
    # What composing across missions costs an honest agent: one question per mission and
    # composition, when the person answers with the reach the ask offers.
    ss, ps, clock, a = _env()
    assert _take(ss, ps, a, REC)[1]["decision"] == "allow"
    b = _mission(ss, ps)
    sdi, d = _take(ss, ps, b, CHAT)
    assert d["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, b, sdi, "allow", apply="mission").status == 201
    for _ in range(3):
        assert _take(ss, ps, b, CHAT)[1]["decision"] == "allow"
    c = _mission(ss, ps)
    assert _take(ss, ps, c, CHAT)[1]["decision"] == "ask"
