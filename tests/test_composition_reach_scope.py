"""A person's answer covers the composition it was asked about, and only that one.

An act can complete several prohibited compositions at once (a pair and a sequence that
share classes). A reach granted for one of them must not allow the act while another,
never put to the person, is also completed.
"""
from __future__ import annotations

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import HistoryEntry, Reach

ISS, M = "https://ps.example", "m"


def res(c: str) -> str:
    return f"https://{c.lower()}.example"


def pol(on_certain: str = "ask", **kw: object) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "A", "B", "C"],
                               rules=[Rule(resource=res(c), cls=c) for c in "ABC"],
                               composition_on_certain=on_certain, **kw))  # type: ignore[arg-type]


def act(c: str) -> Act:
    return Act("auth_token", ISS, SUB, AGENT, M, resource=res(c),
               parameters_provenance="resource")


def h(c: str, uncertain: bool = False) -> HistoryEntry:
    return HistoryEntry(c, res(c), "resource", detail="uncertain: x" if uncertain else "rule")


def reach_for(comp: list[str], kind: str) -> Reach:
    # Given to an ask about a completion on certain evidence, as these histories are.
    return Reach("mission", ISS, SUB, AGENT, kind, M, comp, certain=True)


BOTH = {"prohibited_pairs": [("A", "C")], "prohibited_sequences": [("A", "B", "C")]}


def test_a_reach_for_the_pair_does_not_cover_the_sequence() -> None:
    p = pol(**BOTH)
    first = p.decide(act("C"), None, [h("A")], [], now=0)
    assert first.decision == "ask" and first.composition == ["A", "C"]
    reach = [reach_for(first.composition, first.kind)]
    assert p.decide(act("C"), None, [h("A")], reach, now=0).decision == "allow"
    then = p.decide(act("C"), None, [h("A"), h("B")], reach, now=0)
    assert then.decision == "ask" and then.composition == ["A", "B", "C"]


def test_a_reach_for_the_sequence_does_not_cover_the_pair() -> None:
    p = pol(**BOTH)
    kind = p.decide(act("C"), None, [h("A"), h("B")], [], now=0).kind
    d = p.decide(act("C"), None, [h("A"), h("B")], [reach_for(["A", "B", "C"], kind)], now=0)
    assert d.decision == "ask" and d.composition == ["A", "C"]


def test_reaches_for_every_completed_composition_allow_it() -> None:
    p = pol(**BOTH)
    kind = p.decide(act("C"), None, [h("A"), h("B")], [], now=0).kind
    reach = [reach_for(["A", "C"], kind), reach_for(["A", "B", "C"], kind)]
    d = p.decide(act("C"), None, [h("A"), h("B")], reach, now=0)
    assert d.decision == "allow" and d.composition == ["A", "C"]
    assert any("overrides composition ['A', 'B', 'C']" in t for t in d.trace)


def test_a_certain_open_composition_is_denied_even_after_an_uncertain_one() -> None:
    # The pair rests only on uncertain evidence, the sequence on certain evidence.
    p = pol("deny", prohibited_pairs=[("B", "C")], prohibited_sequences=[("A", "C")])
    d = p.decide(act("C"), None, [h("B", uncertain=True), h("A")], [], now=0)
    assert d.decision == "deny" and d.composition == ["A", "C"]
    # With only uncertain evidence open, it is put to the person.
    d = p.decide(act("C"), None, [h("B", uncertain=True)], [], now=0)
    assert d.decision == "ask" and d.composition == ["B", "C"]


def test_the_certain_composition_is_the_one_asked_about() -> None:
    p = pol("ask", prohibited_pairs=[("B", "C")], prohibited_sequences=[("A", "C")])
    d = p.decide(act("C"), None, [h("B", uncertain=True), h("A")], [], now=0)
    assert d.decision == "ask" and d.composition == ["A", "C"]


def test_e2e_mission_reach_for_one_composition_then_the_other_is_asked() -> None:
    rules = [{"resource": res(c), "class": c} for c in "ABC"]
    ss, ps, clock = make_env(rules=rules, severity=["unclassified", "A", "B", "C"],
                             high_impact=[], prohibited_pairs=[["A", "C"]],
                             prohibited_sequences=[["A", "B", "C"]],
                             composition_on_certain="ask", budgets={}, resource_budgets={})
    s256 = connected((ss, ps, clock), resources=[res(c) for c in "ABC"])

    def take(c: str) -> tuple[str, dict]:
        sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, res(c))
        d = r.json()
        if d.get("decision") == "allow":
            assert ps.issued(ss, SUB, AGENT, s256, sdi, res(c)).status == 201
        return sdi, d

    assert take("A")[1]["decision"] == "allow"
    assert take("B")[1]["decision"] == "allow"
    sdi, d = take("C")                               # completes the pair and the sequence
    assert d["decision"] == "ask" and d["apply_options"][1]["label"].endswith(
        "that complete `A`, then `C`, for the rest of this mission")
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission").status == 201
    assert ps.issued(ss, SUB, AGENT, s256, sdi, res("C")).status == 201
    sdi, d = take("C")                               # the pair is covered, the sequence is not
    assert d["decision"] == "ask"
    assert d["apply_options"][1]["label"].endswith(
        "that complete `A`, then `B`, then `C`, for the rest of this mission")


def test_a_mission_reach_given_outside_any_mission_does_not_reach_into_one() -> None:
    p = pol(**BOTH)
    kind = p.decide(act("C"), None, [h("A")], [], now=0).kind
    no_mission = Reach("mission", ISS, SUB, AGENT, kind, "", ["A", "C"], certain=True)
    inside = act("C")
    assert p.decide(inside, None, [h("A")], [no_mission], now=0).decision == "ask"
    outside = Act("auth_token", ISS, SUB, AGENT, "", resource=res("C"),
                  parameters_provenance="resource")
    assert p.decide(outside, None, [h("A")], [no_mission], now=0).decision == "allow"


def test_e2e_mission_reach_from_a_no_mission_ask_stays_outside_missions() -> None:
    hr, mail = "https://hr.example", "https://mail.example"
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(hr, mail))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", mail, scope="mail.send")
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow", apply="mission").status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, mail, scope="mail.send")
    assert r.json()["decision"] == "ask"
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", mail, scope="mail.send")
    assert r.json()["decision"] == "allow"


def test_with_two_certain_open_compositions_the_deny_names_the_first() -> None:
    p = pol("deny", **BOTH)
    d = p.decide(act("C"), None, [h("A"), h("B")], [], now=0)
    assert d.decision == "deny" and d.composition == ["A", "C"]
    assert "A" in (d.reason or "") and "C" in (d.reason or "")


def test_a_composition_answer_does_not_waive_the_high_impact_gate() -> None:
    # An answer for "A then C" does not cover the act where it completes no composition
    # and only the high-impact check applies.
    p = Policy(PolicyConfig(severity=["unclassified", "A", "C"], high_impact=["C"],
                            rules=[Rule(resource=res(c), cls=c) for c in "AC"],
                            prohibited_pairs=[("A", "C")], composition_on_certain="ask"))
    agent_said = Act("auth_token", ISS, SUB, AGENT, M, resource=res("C"),
                     parameters_provenance="agent")
    first = p.decide(agent_said, None, [h("A")], [], now=0)
    assert first.decision == "ask" and first.composition == ["A", "C"]
    reach = [reach_for(first.composition, first.kind)]
    alone = p.decide(agent_said, None, [], reach, now=0)
    assert alone.decision == "ask", alone.trace
    # An answer to the high-impact question itself (it names that gate) covers it.
    plain = Reach("mission", ISS, SUB, AGENT, first.kind, M, [], gate="high_impact")
    assert p.decide(agent_said, None, [], [plain], now=0).decision == "allow"
