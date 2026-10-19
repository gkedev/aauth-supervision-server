"""What an `ask` puts to the person, and what the person's answer then covers.

* Every gate that denies is checked before any gate that asks: a budget the SS cannot
  check, or a resource budget with no offer, must not hide a certain prohibited
  composition or a count this act would certainly pass, which policy denies and never
  puts to the person.
* A composition the policy denies on certain evidence (`composition_on_certain: deny`) is
  denied whatever the person answered to an ask about the same composition on uncertain
  evidence: they were asked whether it "may" complete, never about a certain completion.
* The ask names every reason it is asked for, and the reaches offered are the ones the SS
  will apply: no remembered answer passes a budget, so a budget ask offers `once` only; a
  composition ask outside any mission has no mission to bound it, so it offers `once`
  only; a composition label names the target the answer is keyed on.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import HistoryEntry, Reach, elsewhere_copy, kin_copy

REC, MAIL, PAY, HR = ("https://records.example", "https://mail.example", "https://pay.example",
                      "https://hr.example")
SEND_EXT = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "x@evil.example"}}


def _issue(ss: Any, ps: Any, s256: str, res: str, proposal: Any = None,
           scope: str = "", budget: Any = None) -> tuple[str, dict[str, Any]]:
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, res, scope=scope,
                                         proposal=proposal, budget=budget)
    d = r.json()
    if d.get("decision") == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, res, scope, prop).status == 201
    return sdi, d


# ------------------------------------------------------------------ denies come first


def test_a_budget_that_cannot_be_checked_does_not_hide_a_certain_composition() -> None:
    ss, ps, clock = make_env(prohibited_pairs=[["read_sensitive", "send_external"],
                                               ["read_sensitive", "payment"]])
    s256 = connected((ss, ps, clock), resources=(REC, PAY))
    assert _issue(ss, ps, s256, REC)[1]["decision"] == "allow"
    _, d = _issue(ss, ps, s256, PAY)                       # amount not visible
    assert d["decision"] == "deny", d
    assert "`read_sensitive`, then `payment`" in d["reason"]


def test_a_resource_budget_ask_does_not_hide_an_exhausted_count() -> None:
    ss, ps, clock = make_env(transport="forwarded", prohibited_pairs=[], high_impact=[],
                             resource_budgets={PAY: {"unit": "USD", "decimals": 2,
                                                     "max_amount": 10_000_000}})
    s256 = connected((ss, ps, clock), resources=(PAY,))
    offer = {"amount": 100, "unit": "USD", "decimals": 2}
    pay = {"operations": [{"operationId": "pay"}], "parameters": {"amount": 100}}
    for _ in range(3):
        assert _issue(ss, ps, s256, PAY, pay, budget=offer)[1]["decision"] == "allow"
    _, d = _issue(ss, ps, s256, PAY, pay)                  # no offer, count exhausted
    assert d["decision"] == "deny" and d["reason"] == (
        "Budget exhausted: no more `payment` acts in this mission."), d


def test_an_answer_on_uncertain_evidence_does_not_cover_a_certain_completion() -> None:
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=(HR, MAIL, REC))
    assert _issue(ss, ps, s256, REC)[1]["decision"] == "allow"
    sdi, d = _issue(ss, ps, s256, MAIL, scope="mail.send")  # may complete: asked
    assert d["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission").status == 201
    assert ps.issued(ss, SUB, AGENT, s256, sdi, MAIL, "mail.send").status == 201
    _, d = _issue(ss, ps, s256, MAIL, SEND_EXT)             # would complete: denied
    assert d["decision"] == "deny", d


# ------------------------------------------------------------------ what is offered


def test_a_budget_ask_offers_this_act_only() -> None:
    ss, ps, clock = make_env(prohibited_pairs=[])
    s256 = connected((ss, ps, clock), resources=(PAY,))
    sdi, d = _issue(ss, ps, s256, PAY)
    assert d["decision"] == "ask" and [o["value"] for o in d["apply_options"]] == ["once"]
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    assert ss.store.reach == []


def test_a_composition_ask_outside_any_mission_offers_this_act_only() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    assert _issue(ss, ps, "", HR)[1]["decision"] == "allow"   # uncertain read_sensitive
    sdi, d = _issue(ss, ps, "", MAIL, scope="mail.send")
    assert d["decision"] == "ask" and d["apply_options"] == [
        {"value": "once", "label": "This act only"}]


def test_a_composition_label_names_the_target_the_answer_is_keyed_on() -> None:
    ss, ps, clock = make_env(high_impact=[])
    s256 = connected((ss, ps, clock), resources=(HR, MAIL))
    assert _issue(ss, ps, s256, HR)[1]["decision"] == "allow"
    _, d = _issue(ss, ps, s256, MAIL, scope="mail.send")
    assert d["apply_options"][1] == {
        "value": "mission",
        "label": "`send_external` acts by this agent on https://mail.example that may complete "
                 "`read_sensitive`, then `send_external`, for the rest of this mission"}


def test_an_ask_for_a_composition_and_a_plain_gate_offers_both_and_covers_both() -> None:
    # The send is high impact with no resource evidence as well: the ask says so, the
    # label offers acts like it, and the answer covers the composition and the gate.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR, MAIL))
    assert _issue(ss, ps, s256, HR)[1]["decision"] == "allow"
    sdi, d = _issue(ss, ps, s256, MAIL, scope="mail.send")
    assert "may complete a combination the policy forbids" in d["summary"]
    assert "no detail of it from the resource" in d["summary"]
    assert d["apply_options"][1]["label"] == (
        "`send_external` acts by this agent on https://mail.example that the supervisor would "
        "ask you about for the same reason or that may complete `read_sensitive`, then "
        "`send_external`, for the rest of this mission")
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    assert sorted(r.composition_override for r in ss.store.reach) == [
        [], ["read_sensitive", "send_external"]]
    assert _issue(ss, ps, s256, MAIL, scope="mail.send")[1]["decision"] == "allow"


# ------------------------------------------------------------------ every reason is named


ISS, M = "https://ps.example", "m"


def _pol(**kw: Any) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "A", "B", "C"],
                               rules=[Rule(resource=f"https://{c.lower()}.example", cls=c)
                                      for c in "ABC"], composition_on_certain="ask", **kw))


def _act(c: str) -> Act:
    return Act("auth_token", ISS, SUB, AGENT, M, resource=f"https://{c.lower()}.example",
               parameters_provenance="resource")


def _h(c: str) -> HistoryEntry:
    return HistoryEntry(c, f"https://{c.lower()}.example", "resource", detail="uncertain: x")


BOTH = {"prohibited_pairs": [("A", "C")], "prohibited_sequences": [("A", "B", "C")]}


def test_an_ask_names_every_composition_the_act_completes() -> None:
    d = _pol(**BOTH).decide(_act("C"), None, [_h("A"), _h("B")], [], now=0)
    assert d.decision == "ask"
    assert "`A`, then `C`" in d.summary and "`A`, then `B`, then `C`" in d.summary
    assert d.compositions == [["A", "C"], ["A", "B", "C"]]
    # The answer covers the composition its label names; the other is asked next.
    assert d.apply_options[1]["label"] == (
        "`C` acts by this agent on https://c.example that may complete `A`, then `C`, "
        "for the rest of this mission")


def test_no_offered_reach_presupposes_the_answer() -> None:
    """Supervision L582: the SS remembers and applies the person's answer, allow or deny,
    with the reach they chose, and this SS does both. A label is the reach, not the
    answer (L592-L593: "This booking only", "Any refundable fare under $4,000 on this
    trip"), so it never reads "Allow ..." for an option the person may choose to deny."""
    asks = [_pol(**BOTH).decide(_act("C"), None, [_h("A"), _h("B")], [], now=0),
            _pol(**BOTH).decide(_act("C"), None, [_h("A")], [], now=0)]
    for d in asks:
        assert d.decision == "ask"
        for o in d.apply_options:
            assert not o["label"].lower().startswith(("allow", "deny")), o


def test_an_answer_covers_the_composition_it_was_offered_for_and_the_next_is_asked() -> None:
    ss, ps, clock = make_env(severity=["unclassified", "A", "B", "C"],
                             rules=[{"resource": f"https://{c.lower()}.example", "class": c,
                                     "if_unknown": c} for c in "ABC"],
                             composition_on_certain="ask", high_impact=[], budgets={},
                             resource_budgets={}, **{k: [list(x) for x in v]
                                                     for k, v in BOTH.items()})
    res = [f"https://{c}.example" for c in "abc"]
    s256 = connected((ss, ps, clock), resources=res)
    assert _issue(ss, ps, s256, res[0])[1]["decision"] == "allow"
    assert _issue(ss, ps, s256, res[1])[1]["decision"] == "allow"
    sdi, d = _issue(ss, ps, s256, res[2])
    assert d["decision"] == "ask"
    assert "`A`, then `C`" in d["summary"] and "`A`, then `B`, then `C`" in d["summary"]
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    assert [r.composition_override for r in ss.store.reach] == [["A", "C"]]
    sdi, d = _issue(ss, ps, s256, res[2])
    assert d["decision"] == "ask" and "`A`, then `C`" not in d["summary"]
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    assert _issue(ss, ps, s256, res[2])[1]["decision"] == "allow"


def test_an_ask_outside_the_mission_for_a_high_impact_act_names_both_reasons() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    _, d = _issue(ss, ps, s256, MAIL, scope="mail.send")
    assert d["decision"] == "ask"
    assert "not among the mission's approved resources" in d["summary"]
    assert "no detail of it from the resource" in d["summary"]


def test_a_reach_covering_the_compositions_still_needs_the_plain_gates() -> None:
    # A composition answer given where the act was inside the mission and not high impact
    # covers that composition, not an act of the kind the person was never asked about.
    p = _pol(high_impact=["C"], **BOTH)
    kind = p.decide(_act("C"), None, [_h("A")], [], now=0).kind
    reach = [Reach("mission", ISS, SUB, AGENT, kind, M, ["A", "C"])]
    # C is high impact and its class rests on configuration, not on resource-asserted
    # detail: the composition is answered, the high-impact gate is not.
    d = p.decide(_act("C"), None, [_h("A")], reach, now=0)
    assert d.decision == "ask" and d.kind == kind
    assert d.compositions == [] and d.plain
    assert "no detail of it from the resource" in d.summary


def test_a_permission_named_like_a_resource_is_neither_classified_nor_answered_as_it() -> None:
    # The agent names its own `action`: an answer about a tool so named must not open
    # the resource of that name, and a rule for the resource does not classify the tool.
    cal = "https://calendar.example"
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission", "iat": int(clock()),
                                          "sub": SUB, "agent": AGENT, "mission_s256": s256,
                                          "action": cal})
    assert r.json()["decision"] == "ask"
    rec = ss.store.decisions[f"{ps.issuer}|{sdi}"]
    assert rec.entry is not None and rec.entry.action_class == "unclassified"
    assert rec.kind == f"unclassified|tool:{cal}"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "always")
    assert _issue(ss, ps, s256, cal)[1]["decision"] == "ask"   # still outside the mission


# ------------------------------------------------------------------ why "may", not "would"

DOUBTS = {
    "act-word": "The agent's own details would make this act less severe, and the supervisor "
                "cannot check them.",
    "act-assumed": "This act's class is assumed, because the request does not show what the "
                   "policy's rules read.",
    "act-person-token": "This act is a person token, on which the resource may serve a request.",
    "word": "The agent's own details would make an earlier act less severe, and the supervisor "
            "cannot check them.",
    "assumed": "An earlier act's class was assumed, because what the supervisor received about "
               "it did not show what the policy's rules read.",
    "open": "An earlier act is not settled yet: it is still being decided, or it was allowed and "
            "its token is not yet reported issued.",
    "mission": "One of the acts is in another mission.",
    "agent": "One of the acts is by another agent from the same provider.",
    "person_token": f"A person token for {REC} may have let that resource serve a request.",
}
OUT = "https://out.example"
DOUBT_POLICY = Policy(PolicyConfig(
    severity=["read_sensitive", "send_internal", "send_external"],
    rules=[Rule(cls="read_sensitive", resource=REC),
           Rule(cls="send_external", resource=OUT),
           Rule(cls="send_internal", resource=MAIL, if_unknown="send_external"),
           Rule(cls="send_internal", tool="SendEmail", if_unknown="send_external")],
    prohibited_pairs=[["read_sensitive", "send_external"]],
    serves_on_identity=[OUT]))


def _read(**kw: Any) -> HistoryEntry:
    return HistoryEntry("read_sensitive", REC, kw.pop("provenance", "resource"),
                        detail=kw.pop("detail", "rule"), n=1, **kw)


def _why(d: Any) -> list[str]:
    assert d.decision == "ask" and "may complete a combination the policy forbids" in d.summary
    return [k for k, text in DOUBTS.items() if text in d.summary]


@pytest.mark.parametrize("entry,why", [
    (_read(provenance="agent", detail="uncertain: agent-asserted evidence cannot lower"), "word"),
    (_read(provenance="configured", detail="uncertain: data needed by a more specific rule is "
                                           "unavailable; assumed read_sensitive"), "assumed"),
    (_read(detail="uncertain: allow not yet settled: rule", open="other", borrowed=True), "open"),
    (elsewhere_copy(_read(), "m2"), "mission"),
    (kin_copy(_read(), "aauth:b@agent.example"), "agent"),
    (_read(provenance="configured", detail="uncertain: person token"), "person_token"),
])
def test_a_may_complete_ask_names_the_evidence_it_rests_on(entry: HistoryEntry,
                                                           why: str) -> None:
    act = Act("auth_token", ISS, SUB, AGENT, resource=OUT)
    assert _why(DOUBT_POLICY.decide(act, None, [entry], [], now=1000.0)) == [why]


@pytest.mark.parametrize("act,why", [
    (Act("auth_token", ISS, SUB, AGENT, resource=MAIL), "act-assumed"),
    (Act("permission", ISS, SUB, AGENT, tool="SendEmail", parameters={"to": "a@corp.example"},
         parameters_provenance="agent"), "act-word"),
    (Act("person_token", ISS, SUB, AGENT, resource=OUT), "act-person-token"),
])
def test_a_may_complete_ask_names_the_act_itself_when_its_class_is_uncertain(act: Act,
                                                                           why: str) -> None:
    assert _why(DOUBT_POLICY.decide(act, None, [_read()], [], now=1000.0)) == [why]


def test_a_composition_across_two_of_the_agents_missions_names_them() -> None:
    # Outside missions, each of the agent's missions composes certainly on its own; a
    # composition that needs two of them is only possible, and says so.
    policy = Policy(PolicyConfig(
        severity=["read_sensitive", "write", "send_external"],
        rules=[Rule(cls="send_external", resource=OUT)],
        prohibited_sequences=[["read_sensitive", "write", "send_external"]]))
    hist = [HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1, scope="m1",
                         borrowed=True),
            HistoryEntry("write", REC, "resource", detail="rule", n=2, scope="m2",
                         borrowed=True)]
    d = policy.decide(Act("auth_token", ISS, SUB, AGENT, resource=OUT), None, hist, [],
                      now=1000.0)
    assert _why(d) == ["mission"]


def test_a_payment_the_resource_describes_is_decided_on_the_resource_s_word() -> None:
    # The example's payment rule names the operation the resource's R3 proposal names and
    # reads the amount from it: the supervisor has the resource's detail of the payment,
    # so the high-impact gate does not put it to the person as if it had none.
    pay = {"operations": [{"operationId": "pay"}], "parameters": {"amount": 100}}
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=(PAY,))
    _, d = _issue(ss, ps, s256, PAY, proposal=pay)
    assert d["decision"] == "allow", d
    act = Act("auth_token", "ps", SUB, AGENT, s256, resource=PAY, operations=["pay"],
              parameters={"amount": 100}, parameters_provenance="resource")
    c = ss.policy.classify(act)
    assert (c.cls, c.provenance, c.amount) == ("payment", "resource", 100)


def test_a_high_impact_act_the_resource_describes_but_no_rule_classes_is_told_so() -> None:
    # No rule names the resource, and the policy makes its default class high impact: the
    # resource's R3 proposal describes the act, so the person is not told the supervisor
    # has no resource-asserted detail of it, but that no rule classes it from that detail.
    p = Policy(PolicyConfig.from_dict({**_example(), "high_impact": ["unclassified"],
                                       "serves_on_identity": []}))
    act = Act("auth_token", "ps", SUB, AGENT, "", resource="https://new.example",
              operations=["export"], parameters={"rows": 5000},
              parameters_provenance="resource")
    d = p.decide(act, None, [], [], now=0)
    assert d.decision == "ask"
    assert "no detail of it from the resource" not in d.summary
    assert ("no rule of the policy reads its class from the resource's description of it"
            in d.summary)
    bare = Act("auth_token", "ps", SUB, AGENT, "", resource="https://new.example")
    assert "no detail of it from the resource" in p.decide(bare, None, [], [], now=0).summary


def _example() -> dict[str, Any]:
    import json
    from pathlib import Path
    return json.loads((Path(__file__).resolve().parents[1] / "examples" / "policy.json")
                      .read_text(encoding="utf-8"))


def test_a_high_impact_class_assumed_on_a_described_act_is_told_as_assumed() -> None:
    # The resource's proposal names `forward_email` to an outside address, which no rule
    # reads: the class is assumed (the mail rule's `if_unknown`). The person is told it
    # may be that class, and not that the supervisor has no detail from the resource.
    from conftest import policy_cfg
    p = Policy(policy_cfg())
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=MAIL, scope="mail.send",
              operations=["forward_email"], parameters={"to": "drop@evil.example"},
              parameters_provenance="resource")
    d = p.decide(act, None, [], [], now=0)
    assert d.decision == "ask"
    assert "This may be a `send_external` act" in d.summary
    assert "no detail of it from the resource" not in d.summary
    # With no proposal at all, the class is assumed as well: told as one it may have.
    bare = Act("auth_token", "ps", SUB, AGENT, "", resource=MAIL, scope="mail.send")
    assert p.decide(bare, None, [], [], now=0).summary.startswith(
        "This may be a `send_external` act, and the supervisor has no detail of it from the resource")


def test_an_assumed_class_composes_as_the_class_it_would_have_too() -> None:
    # A mail.send token with no proposal is assumed send_external (`if_unknown`), but
    # with its recipients known it could be send_internal. Live when a write is decided
    # after a sensitive read, it may take the send_internal step of read, write, send:
    # the write is asked, not allowed.
    from conftest import policy_cfg
    p = Policy(policy_cfg())
    send = p.classify(Act("auth_token", "ps", SUB, AGENT, "", resource=MAIL, scope="mail.send"))
    assert send.cls == "send_external" and send.uncertain
    assert [(a.cls, a.assumed) for a in send.blind] == [("send_internal", True)]
    hist = [HistoryEntry(send.cls, MAIL, send.provenance, at=10, n=1, token_exp=10**9,
                         detail="uncertain: " + send.detail, blind=list(send.blind)),
            HistoryEntry("read_sensitive", REC, "configured", at=20, n=2, token_exp=10**9,
                         detail="rule")]
    d = p.decide(Act("auth_token", "ps", SUB, AGENT, "", resource="https://calendar.example"),
                 None, hist, [], now=30)
    assert d.decision == "ask" and "`read_sensitive`, then `write`, then `send_internal`" in d.summary
    assert "class was assumed" in d.summary


def test_a_person_token_a_composition_rests_on_is_named_by_its_resource() -> None:
    # Records serve on a person token alone, and one was issued: a send that may complete
    # read_sensitive then send_external through it says which resource the token was for,
    # not "the resource", which the person would read as the send's own.
    from conftest import policy_cfg
    rec = "https://records.example"
    p = Policy(policy_cfg(serves_on_identity=[rec]))
    token = HistoryEntry("read_sensitive", rec, "configured", at=10, n=1, token_exp=10**9,
                         detail="uncertain: person token")
    send = Act("auth_token", "ps", SUB, AGENT, "", resource="https://mail.example",
               scope="mail.send", operations=["send_email"],
               parameters={"to": "x@evil.example"}, parameters_provenance="resource")
    d = p.decide(send, None, [token], [], now=30)
    assert d.decision in ("ask", "deny"), d
    text = d.summary or d.reason
    assert f"A person token for {rec}" in text, text
