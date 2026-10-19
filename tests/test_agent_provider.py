"""The person's other agents from the same agent provider compose, as uncertain.

Every agent instance has its own identifier (Protocol L167), `aauth:local@domain`, where
`domain` is the agent provider's (L488). Instances of one provider may share what they
read, so an act composes with the acts of the person's other agents from the provider of
an agent in its chain: their acts outside missions and in their missions, each as
uncertain. Such a composition is put to the person, never denied, as across missions. An
agent of another provider, another person's agent, and an identifier of any other form
compose with nothing.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Store

REC, CHAT, PAY = "https://records.example", "https://chat.example", "https://pay.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": PAY, "class": "payment"}]
SIBLING = "aauth:assistant-2@agent.example"     # AGENT is aauth:assistant@agent.example
STRANGER = "aauth:bot@other.example"
TOOLS = [{"name": "WebSearch", "description": "Search"}]


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [["read_sensitive", "send_internal"]])
    over.setdefault("prohibited_sequences", [])
    over.setdefault("high_impact", [])
    # Not about Person Identity Access: approving a mission issues no person token that is
    # an act.
    over.setdefault("serves_on_identity", [])
    ss, ps, clock = make_env(rules=RULES, **over)
    s256 = connected((ss, ps, clock), resources=(REC, CHAT, PAY))
    return ss, ps, clock, s256


def _mission(ss: Any, ps: Any, agent: str, sub: str = SUB) -> str:
    r, s256 = ps.propose_and_approve(ss, sub, agent, f"# Task {ps.nid('t')}",
                                     [REC, CHAT, PAY], TOOLS)
    assert r.status == 200 and s256
    return str(s256)


def _take(ss: Any, ps: Any, agent: str, s256: str, resource: str,
          sub: str = SUB) -> dict[str, Any]:
    sdi, r, _ = ps.auth_token_request(ss, sub, agent, s256, resource)
    d = r.json()
    assert isinstance(d, dict)
    d["sdi"] = sdi
    if d["decision"] == "allow":
        assert ps.issued(ss, sub, agent, s256, sdi, resource).status == 201
    return d


@pytest.mark.parametrize("read_in,send_in", [
    ("", ""), ("", "own"), ("first", ""), ("first", "own")])
def test_a_pair_split_between_two_instances_is_asked_never_denied(read_in: str,
                                                                 send_in: str) -> None:
    ss, ps, _, first = _env()
    where = {"": "", "first": first, "own": _mission(ss, ps, SIBLING)}
    assert _take(ss, ps, AGENT, where[read_in], REC)["decision"] == "allow"
    d = _take(ss, ps, SIBLING, where[send_in], CHAT)
    assert d["decision"] == "ask", d
    assert d["recommendation"] == "deny"
    # The person is told what could complete it: the other instance's act, outside its
    # missions or in one of them.
    why = ("is in another mission" if read_in == "first"
           else "is by another agent from the same provider")
    assert d["summary"].endswith(f"as it cannot confirm every act that could complete it. "
                                 f"One of the acts {why}."), d["summary"]


def test_the_same_instance_is_still_denied() -> None:
    ss, ps, _, first = _env()
    assert _take(ss, ps, AGENT, "", REC)["decision"] == "allow"
    assert _take(ss, ps, AGENT, "", CHAT)["decision"] == "deny"


def test_an_agent_of_another_provider_does_not_compose() -> None:
    ss, ps, _, _ = _env()
    assert _take(ss, ps, AGENT, "", REC)["decision"] == "allow"
    assert _take(ss, ps, STRANGER, "", CHAT)["decision"] == "allow"
    assert _take(ss, ps, STRANGER, _mission(ss, ps, STRANGER), CHAT)["decision"] == "allow"


def _history(st: Store, agent: str, mission: str = "") -> list[Any]:
    return st.composition_history("https://ps.example", SUB, agent, mission)


def test_what_another_instance_brings_is_borrowed_and_uncertain() -> None:
    from aauth_supervision_server.store import HistoryEntry, Mission

    st = Store()
    st.add_history(st.history_for("https://ps.example", SUB, AGENT, ""),
                   HistoryEntry("read_sensitive", REC, "resource", detail="rule"), AGENT)
    m = Mission("m-2", SIBLING, SUB, "https://ps.example")
    st.missions[Store.k("https://ps.example", "m-2")] = m
    st.add_history(m.history, HistoryEntry("write", CHAT, "resource", detail="rule"), SIBLING)
    outside = _history(st, SIBLING)
    assert [(h.action_class, h.borrowed, h.scope, h.open, h.detail) for h in outside] == [
        ("read_sensitive", True, f"agent:{AGENT}", "agent",
         "uncertain: of another agent: rule"),
        ("write", True, "m-2", "", "rule")]
    inside = _history(st, SIBLING, "m-2")
    assert [(h.action_class, h.borrowed, h.scope, h.open) for h in inside] == [
        ("read_sensitive", True, f"agent:{AGENT}", "agent"), ("write", False, "", "")]
    assert [(h.action_class, h.scope, h.open, h.detail) for h in _history(st, AGENT)] == [
        ("read_sensitive", "", "", "rule"),
        ("write", "m-2", "mission", "uncertain: in another mission: rule")]


@pytest.mark.parametrize("odd", ["aauth:a|b%c@agent.example", "aauth:a%7Cb@agent.example"])
def test_an_identifier_the_store_key_escapes_is_read_back(odd: str) -> None:
    from aauth_supervision_server.store import HistoryEntry

    st = Store()
    st.add_history(st.history_for("https://ps.example", SUB, odd, ""),
                   HistoryEntry("read_sensitive", REC, "resource", detail="rule"), odd)
    assert [h.scope for h in _history(st, AGENT)] == [f"agent:{odd}"]


@pytest.mark.parametrize("send_in", ["", "own"])
def test_a_mission_of_another_instance_composes_whoever_acted_in_it(send_in: str) -> None:
    # The sibling owns a mission it never acted in; another provider's agent read in it
    # as a call chain. The mission is the sibling's, so it composes, as uncertain.
    ss, ps, _, _ = _env()
    theirs = _mission(ss, ps, SIBLING)
    assert _take(ss, ps, STRANGER, theirs, REC)["decision"] == "allow"
    where = _mission(ss, ps, AGENT) if send_in else ""
    assert _take(ss, ps, AGENT, where, CHAT)["decision"] == "ask"


@pytest.mark.parametrize("send_in", ["", "own"])
def test_an_instance_seen_through_another_providers_mission(send_in: str) -> None:
    # The sibling read only as a call chain, in a mission of another provider's agent.
    ss, ps, _, _ = _env()
    theirs = _mission(ss, ps, STRANGER)
    assert _take(ss, ps, SIBLING, theirs, REC)["decision"] == "allow"
    where = _mission(ss, ps, AGENT) if send_in else ""
    assert _take(ss, ps, AGENT, where, CHAT)["decision"] == "ask"


@pytest.mark.parametrize("first,second", [
    ("agent-1", "agent-2"), ("aauth:a@agent.example", "aauth:b@other.example"),
    ("aauth:a@agent.example", "agent.example")])
def test_identifiers_of_different_providers_or_no_provider_bring_nothing(
        first: str, second: str) -> None:
    from aauth_supervision_server.store import HistoryEntry

    st = Store()
    st.add_history(st.history_for("https://ps.example", SUB, first, ""),
                   HistoryEntry("read_sensitive", REC, "resource", detail="rule"), first)
    assert _history(st, second) == []


def test_another_persons_instance_does_not_compose() -> None:
    ss, ps, _, _ = _env()
    assert ps.connect(ss, "another-person").status == 200
    assert _take(ss, ps, AGENT, "", REC)["decision"] == "allow"
    assert _take(ss, ps, SIBLING, "", CHAT, sub="another-person")["decision"] == "allow"


def test_a_no_to_a_composition_across_instances_is_applied() -> None:
    # As across missions: the person's "no" with reach is applied (Supervision L582).
    ss, ps, clock, _ = _env()
    own = _mission(ss, ps, SIBLING)
    assert _take(ss, ps, AGENT, "", REC)["decision"] == "allow"
    d = _take(ss, ps, SIBLING, own, CHAT)
    assert d["decision"] == "ask" and "mission" in [o["value"] for o in d["apply_options"]]
    assert ps.resolved(ss, SUB, SIBLING, own, d["sdi"], "deny", apply="mission").status == 201
    assert _take(ss, ps, SIBLING, own, CHAT)["decision"] == "deny"


def test_budgets_stay_with_each_instance() -> None:
    ss, ps, _, _ = _env(budgets={"payment": {"max_count": 1}})
    assert _take(ss, ps, AGENT, "", PAY)["decision"] == "allow"
    assert _take(ss, ps, AGENT, "", PAY)["decision"] == "deny"
    assert _take(ss, ps, SIBLING, "", PAY)["decision"] == "allow"


def test_a_call_chain_brings_in_the_providers_of_its_members() -> None:
    # A relay of another provider acts in AGENT's mission; an instance of the relay's
    # provider then composes with that mission's chain, as uncertain.
    ss, ps, _, first = _env()
    relay, relay_twin = "aauth:relay@tools.example", "aauth:relay-2@tools.example"
    assert _take(ss, ps, relay, first, REC)["decision"] == "allow"
    assert _take(ss, ps, relay_twin, "", CHAT)["decision"] == "ask"


def test_composition_survives_a_restart(tmp_path: Any) -> None:
    state = str(tmp_path / "state.json")
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[["read_sensitive", "send_internal"]],
                             prohibited_sequences=[], high_impact=[])
    ss.store = Store(state)
    connected((ss, ps, clock), resources=(REC, CHAT))
    assert _take(ss, ps, AGENT, "", REC)["decision"] == "allow"
    ss.store = Store(state)  # what a restart reads back
    assert _take(ss, ps, SIBLING, "", CHAT)["decision"] == "ask"


@pytest.mark.parametrize("agent,domain", [
    ("aauth:assistant@agent.example", "agent.example"),
    ("aauth:a.b+c_d-e@Agent.Example", "agent.example"),
    ("aauth:@agent.example", ""), ("aauth:x@", ""), ("aauth:x", ""),
    ("agent.example", ""), ("x@agent.example", ""), ("assistant@agent.example", ""),
    ("", ""),
])
def test_the_provider_is_the_domain_of_an_aauth_identifier(agent: str, domain: str) -> None:
    from aauth_supervision_server.store import provider

    assert provider(agent) == domain


def test_a_decision_reads_only_its_own_person_s_agent_keys(monkeypatch: Any) -> None:
    # Finding the person's agents must not cost a pass over every person's keys: the
    # store indexes each key once, as it is added, and a decision reads its person's only.
    import aauth_supervision_server.store as store
    from aauth_supervision_server.store import HistoryEntry

    st = Store()
    for p in range(50):
        st.history_for("https://ps.example", f"other-{p}", AGENT, "")
    st.add_history(st.history_for("https://ps.example", SUB, AGENT, ""),
                   HistoryEntry("read_sensitive", REC, "resource", detail="rule"), AGENT)
    indexed: list[str] = []
    real_add = st._agents._add
    monkeypatch.setattr(st._agents, "_add", lambda k, v: indexed.append(k) or real_add(k, v))
    read: list[str] = []
    real = store._unescape
    monkeypatch.setattr(store, "_unescape", lambda part: read.append(part) or real(part))
    assert [h.scope for h in _history(st, SIBLING)] == [f"agent:{AGENT}"]
    assert len(indexed) == 52  # every key once: 51 for AGENT, and SIBLING's own, made now
    assert len(read) == 2      # this person's two keys only
    assert [h.scope for h in _history(st, SIBLING)] == [f"agent:{AGENT}"]
    assert (len(indexed), len(read)) == (52, 4)  # nothing indexed again
    st.history_for("https://ps.example", "other-x", STRANGER, "")
    _history(st, SIBLING)
    assert (len(indexed), len(read)) == (53, 6)


def test_the_agent_index_follows_a_history_that_replaces_the_old() -> None:
    # A snapshot load replaces `agent_history` with a new dict, possibly shorter.
    from aauth_supervision_server.store import HistoryEntry

    st = Store()
    for p in range(3):
        st.history_for("https://ps.example", f"other-{p}", AGENT, "")
    assert _history(st, SIBLING) == []
    entry = HistoryEntry("read_sensitive", REC, "resource", detail="rule", agent=AGENT, n=1)
    st.agent_history = {Store.k("https://ps.example", SUB, AGENT): [entry]}
    assert [h.scope for h in _history(st, SIBLING)] == [f"agent:{AGENT}"]


def test_the_agent_index_holds_only_agents_with_a_history_outside_missions() -> None:
    from aauth_supervision_server.store import HistoryEntry, Mission

    st = Store()
    st.add_history(st.history_for("https://ps.example", SUB, AGENT, ""),
                   HistoryEntry("read_sensitive", REC, "resource", detail="rule"), AGENT)
    m = Mission("m-2", SIBLING, SUB, "https://ps.example")
    st.missions[Store.k("https://ps.example", "m-2")] = m
    st.add_history(m.history, HistoryEntry("write", CHAT, "resource", detail="rule"), STRANGER)
    assert [h.scope for h in _history(st, AGENT, "")] == ["", "m-2"]
    assert st._agents_outside("https://ps.example", SUB) == {AGENT}
