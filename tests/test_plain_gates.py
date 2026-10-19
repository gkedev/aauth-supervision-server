"""An answer to one plain gate covers that gate only.

Two checks put an act to the person without a composition: the mission's intent (a
resource or tool outside it) and high impact without resource-asserted detail. The ask
names the reason it was put; an answer with reach (Supervision L582) is about that
question, so it covers that gate and not the other, which the person was never asked.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, make_env

from aauth_supervision_server.adversarial import MAIL, SEND
from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import Mission, Reach

PARTNER = SEND | {"parameters": {"to": "partner@vendor.example"}}
CAL = "https://calendar.example"  # serves on no person token: approving it is no act


def _take(ss: Any, ps: Any, s256: str, **kw: Any) -> tuple[str, dict[str, Any]]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send", **kw)
    return sdi, dict(r.json())


def test_an_intent_answer_does_not_answer_the_high_impact_question() -> None:
    ss, ps, _ = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# plan the week", [CAL], [])
    sdi, d = _take(ss, ps, s256, proposal=PARTNER)
    assert d["decision"] == "ask" and "not among the mission's approved resources" in d["summary"]
    assert "detail of it from the resource" not in d["summary"]
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "always").status == 201
    # Outside missions, a send whose recipients nobody asserted: the other gate.
    _, d2 = _take(ss, ps, "")
    assert d2["decision"] == "ask" and "detail of it from the resource" in d2["summary"], d2
    # The question the person did answer stays answered.
    _, d3 = _take(ss, ps, s256, proposal=PARTNER)
    assert d3["decision"] == "allow", d3


def test_a_high_impact_answer_does_not_answer_the_intent_question() -> None:
    ss, ps, _ = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    sdi, d = _take(ss, ps, "")
    assert d["decision"] == "ask" and "detail of it from the resource" in d["summary"]
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow", "always").status == 201
    assert _take(ss, ps, "")[1]["decision"] == "allow"
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# plan the week", [CAL], [])
    _, d2 = _take(ss, ps, s256, proposal=PARTNER)
    assert d2["decision"] == "ask" and "not among the mission's approved" in d2["summary"], d2


def _policy() -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "send"], rules=[Rule(cls="send")],
                               high_impact={"send"}))


def _act(**kw: Any) -> Act:
    return Act("auth_token", "i", "s", "a", mission_s256="m", resource=MAIL,
               parameters_provenance="agent", **kw)


def _mission(resources: list[str]) -> Mission:
    return Mission("m", "a", "s", "i", blob={"approved_resources": resources})


def _reach(gate: str, answer: str = "allow") -> Reach:
    return Reach("mission", "i", "s", "a", f"send|{MAIL}", "m", answer=answer, gate=gate)


def test_each_gate_reads_its_own_answer() -> None:
    p = _policy()
    inside, outside = _mission([MAIL]), _mission([])
    assert p.decide(_act(), inside, [], [_reach("intent")], now=0).decision == "ask"
    d = p.decide(_act(), inside, [], [_reach("high_impact")], now=0)
    assert d.decision == "allow" and "reach mission" in d.trace
    both = [_reach("intent"), _reach("high_impact")]
    assert p.decide(_act(), outside, [], both, now=0).decision == "allow"
    d = p.decide(_act(), outside, [], [_reach("intent")], now=0)
    assert d.decision == "ask" and d.gates == ["high_impact"]
    d = p.decide(_act(), outside, [], [], now=0)
    assert d.decision == "ask" and d.gates == ["intent", "high_impact"] and d.plain


def test_a_no_to_either_gate_asked_is_applied() -> None:
    p = _policy()
    outside = _mission([])
    for gate in ("intent", "high_impact"):
        d = p.decide(_act(), outside, [], [_reach(gate, "deny")], now=0)
        assert d.decision == "deny", gate
    # A "no" to a gate the act does not meet is not about it.
    d = p.decide(_act(), _mission([MAIL]), [], [_reach("intent", "deny")], now=0)
    assert d.decision == "ask"


def test_a_0_1_x_answer_with_no_gate_covers_neither() -> None:
    p = _policy()
    assert p.decide(_act(), _mission([MAIL]), [], [_reach("")], now=0).decision == "ask"


def test_an_intent_answer_is_in_the_trace() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "send"], rules=[Rule(cls="send")]))
    d = p.decide(_act(), _mission([]), [], [_reach("intent")], now=0)
    assert d.decision == "allow" and "reach mission" in d.trace


def test_answers_to_the_two_gates_are_kept_side_by_side() -> None:
    ss, ps, _ = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# plan the week", [CAL], [])
    sdi, d = _take(ss, ps, s256, proposal=PARTNER)           # outside the mission only
    assert d["decision"] == "ask" and "detail of it from the resource" not in d["summary"]
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission").status == 201
    sdi, d = _take(ss, ps, s256)                             # high impact only, now
    assert d["decision"] == "ask" and "not among" not in d["summary"], d
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission").status == 201
    # The second answer did not replace the first: both gates are answered.
    assert sorted(r.gate for r in ss.store.reach) == ["high_impact", "intent"]
    assert _take(ss, ps, s256)[1]["decision"] == "allow"
