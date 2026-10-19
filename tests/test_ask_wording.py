"""What the person reads: the policy's classes as names, the doubts a combination rests on,
and sentences a person can read.

An ask's `summary` and its labels are Markdown the PS shows the person (Supervision L266,
L584). A class is the policy's own name for a kind of act, so it is shown as one, in a code
span; a combination the policy forbids is called that. Why the supervisor cannot settle one
is told as the kinds of doubt it rests on: this act's, and those of earlier acts whose class
could take one of the combination's other steps, never of one that could take only this
act's step (`tests/test_ask_doubts.py`). Such an earlier act is named even where the order
of the acts, or a certain act of its class, leaves it no step. Where the other acts are
certain and only this act is in doubt, the ask says so, once for all such combinations.
Each reason is a sentence of its own. Each label says what the answer is kept by and where
it applies: the act's class and target (`Decision.kind`), this agent, the scope it names,
and where the same question would be asked again.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from conftest import AGENT, SUB, connected, make_env, policy_cfg

from aauth_supervision_server import policy as policy_mod
from aauth_supervision_server.adversarial import MAIL, SEND, _records, start
from aauth_supervision_server.policy import Act, HistoryEntry, Policy, PolicyConfig, ResourceBudget, Rule

ROOT = Path(__file__).resolve().parents[1]
COMBINATION = "`read_sensitive`, then `send_external`"
ISS, INFERENCE = "https://ps.example", "https://inference.example"


def _send(config: str) -> dict[str, Any]:
    # The customer records read, then a mail to an outside address: the split exfiltration.
    run = start(config)
    _records(run)
    d: dict[str, Any] = run.act(MAIL, SEND | {"parameters": {"to": "drop@evil.example"}},
                                scope="mail.send")["d"]
    return d


def _abc(**kw: Any) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "A", "B", "C"],
                               rules=[Rule(resource=f"https://{c.lower()}.example", cls=c)
                                      for c in "ABC"], composition_on_certain="ask", **kw))


def _act(c: str) -> Act:
    return Act("auth_token", ISS, SUB, AGENT, "m", resource=f"https://{c.lower()}.example",
               parameters_provenance="resource")


def _assumed(c: str) -> HistoryEntry:
    return HistoryEntry(c, f"https://{c.lower()}.example", "configured", detail="uncertain: x")


def test_where_only_this_act_is_uncertain_the_other_acts_are_said_to_be_certain() -> None:
    # A certain records read and an approval's person token for records: the read alone
    # takes that step, so only the send's assumed class leaves the combination open.
    d = _send("apc/current")
    assert d["decision"] == "ask"
    assert d["summary"].startswith(
        f"Together with other acts, this act may complete a combination the policy forbids: "
        f"{COMBINATION}. The supervisor is certain of the other acts, not of this one. This "
        f"act's class is assumed, because the request does not show what the policy's rules "
        f"read.")
    assert "person token" not in d["summary"]


def test_where_other_acts_are_uncertain_each_is_told_in_a_sentence() -> None:
    d = _abc(prohibited_pairs=[("A", "C")]).decide(_act("C"), None, [_assumed("A")], [],
                                                   now=0)
    assert d.decision == "ask"
    assert d.summary == (
        "Together with other acts, this act may complete a combination the policy forbids: "
        "`A`, then `C`. The supervisor can neither confirm nor rule it out, as it cannot "
        "confirm every act that could complete it. An earlier act's class was assumed, "
        "because what the supervisor received about it did not show what the policy's rules "
        "read.")


def test_combinations_resting_on_the_same_doubt_are_told_once() -> None:
    d = _abc(prohibited_pairs=[("A", "C")], prohibited_sequences=[("A", "B", "C")]).decide(
        _act("C"), None, [_assumed("A"), _assumed("B")], [], now=0)
    assert d.decision == "ask" and d.compositions == [["A", "C"], ["A", "B", "C"]]
    assert d.summary.startswith(
        "Together with other acts, this act may complete combinations the policy forbids: "
        "`A`, then `C`; and `A`, then `B`, then `C`. The supervisor can neither confirm nor "
        "rule it out")
    assert d.summary.count("An earlier act's class was assumed") == 1


def test_a_class_held_above_the_agent_s_details_is_told_so() -> None:
    doubts = dict(policy_mod._DOUBTS)
    assert doubts["act-word"] == ("The agent's own details would make this act less severe, "
                                  "and the supervisor cannot check them.")
    assert doubts["word"] == ("The agent's own details would make an earlier act less "
                              "severe, and the supervisor cannot check them.")


def test_a_combination_the_record_does_not_settle_is_told_in_short_sentences() -> None:
    text = Policy._comp_summary([["read_sensitive", "write", "send_internal"]], None)
    assert text == (
        "The supervisor cannot tell whether this act completes a combination the policy "
        "forbids: `read_sensitive`, then `write`, then `send_internal`. What is recorded does "
        "not settle the order of those acts, or whether a token was still live at one of "
        "them, or settling it would take more work than the supervisor allows for one "
        "decision. It is treated as possible.")


def test_a_certain_combination_is_refused_in_the_same_words() -> None:
    d = _send("apc/forwarded")  # the proposal shows the recipient: certain
    assert d["decision"] == "deny"
    assert d["reason"] == (f"Together with other acts, this act would complete a "
                           f"combination the policy forbids: {COMBINATION}.")


def test_no_sentence_the_person_reads_runs_past_forty_words() -> None:
    texts = [r["why"] for r in json.loads((ROOT / "docs" / "adversarial-results.json")
                                          .read_text(encoding="utf-8")) if r["why"]]
    texts += [_send(c).get("summary", "") for c in ("apc/current", "apc/forwarded+issued")]
    for text in texts:
        for sentence in re.split(r"(?<=[.?!])\s+(?=[A-Z0-9`])", text):
            assert len(sentence.split()) <= 40, sentence


def test_each_label_says_where_the_answer_applies() -> None:
    # An answer given with a reach is applied where the supervisor would put the same
    # question again (a "no" too: it never refuses an act the supervisor would allow), so
    # each label says where that is: for a resource the mission does not include, every
    # mission that does not; for a high-impact act, wherever it would ask for that reason.
    d = _send("apc/current")
    assert {o["value"]: o["label"] for o in d["apply_options"]}["mission"] == (
        f"`send_external` acts by this agent on {MAIL} that the supervisor would ask you "
        f"about for the same reason or that may complete {COMBINATION}, for the rest of this "
        f"mission")
    labels = [o["label"] for o in policy_mod._apply_options(MAIL, cls="write")]
    assert labels == ["This act only",
                      f"`write` acts by this agent on {MAIL}, for the rest of this mission",
                      f"`write` acts by this agent on {MAIL}, in any mission that does not "
                      f"include it, from now on"]
    labels = [o["label"] for o in policy_mod._apply_options(
        MAIL, cls="send_external", gates=["high_impact"], in_mission=False)]
    why = f"`send_external` acts by this agent on {MAIL} that the supervisor would ask you about"
    assert labels[1:] == [f"{why} for the same reason, outside missions, from now on",
                          f"{why} for the same reason, in any mission or none, from now on"]
    labels = [o["label"] for o in policy_mod._apply_options(
        MAIL, cls="send_external", gates=["intent", "high_impact"])]
    assert labels[1] == f"{why} for one of the same reasons, for the rest of this mission"
    for certain, verb in ((False, "may complete"), (True, "complete")):
        (label,) = (o["label"] for o in policy_mod._apply_options(
            MAIL, ["a", "b"], cls="b", gates=[], certain=certain) if o["value"] == "mission")
        assert label == (f"`b` acts by this agent on {MAIL} that {verb} `a`, then `b`, for the "
                         f"rest of this mission")
    rec = "https://records.example"
    assert [o["label"] for o in policy_mod._apply_options(rec, identity=True)][1:] == [
        f"Identifying you to {rec} when this agent asks, for the rest of this mission",
        f"Identifying you to {rec} when this agent asks in a mission that does not include "
        f"it, from now on"]


def test_acts_not_yet_reported_are_told_in_the_person_s_terms() -> None:
    limit = "the `payment` budget of 500000"
    assert policy_mod._waiting_text(1, "`payment` act", limit) == (
        f"An earlier `payment` act is allowed or still being decided, and has not been "
        f"reported done yet. If it goes ahead, it and this act together would take {limit} "
        f"past its limit.")
    assert policy_mod._waiting_text(2, "`payment` act", limit) == (
        f"2 earlier `payment` acts are allowed or still being decided, and have not been "
        f"reported done yet. If they go ahead, they and this act together would take {limit} "
        f"past its limit.")
    assert policy_mod._waiting_text(1, "`payment` act", limit, known=False).endswith(
        f"If it goes ahead, it and this act together may take {limit} past its limit.")


def test_a_metered_resource_is_told_without_protocol_terms() -> None:
    p = Policy(policy_cfg())
    rb = ResourceBudget(unit="USD", decimals=2, max_amount=2500)

    def told(**kw: Any) -> str:
        act = Act("auth_token", ISS, SUB, AGENT, "m", resource=INFERENCE, **kw)
        out = p._resource_budget(act, rb, [], [], [])
        assert out is not None
        return out[1]
    assert told() == (f"{INFERENCE} is metered against the 25.00 USD mission ceiling, of "
                      f"which 25.00 USD is left, but it offered no budget for this act, so the "
                      f"spend cannot be bounded.")
    assert told(budget_amount=1000, budget_unit="EUR/2") == (
        f"{INFERENCE} offers 10.00 EUR, but its ceiling is set in USD with 2 decimal places: "
        f"25.00 USD of the 25.00 USD mission ceiling is left.")
    assert told(budget_amount=3000, budget_unit="USD/2") == (
        f"{INFERENCE} offers 30.00 USD, but only 25.00 USD of the 25.00 USD mission ceiling "
        f"is left. The supervisor has no way to grant a smaller amount.")


def test_a_local_tool_is_told_as_the_agent_s_account() -> None:
    p = Policy(policy_cfg(rules=[{"tool": "WireMoney", "class": "send_external"}],
                          prohibited_pairs=[], prohibited_sequences=[], budgets={}))
    act = Act("permission", ISS, SUB, AGENT, "", tool="WireMoney", parameters={},
              parameters_provenance="agent")
    d = p.decide(act, None, [], [], now=0)
    assert d.decision == "ask"
    assert ("This is a `send_external` act, done with the agent's own tool, and the supervisor "
            "has only the agent's account of it.") in d.summary


def test_a_proposal_ask_says_what_approving_it_as_proposed_does_not_grant() -> None:
    d = Policy(policy_cfg()).decide_proposal(
        {"description": "x", "tools": [{"name": "DeleteRepo"}], "resources": []}, now=0)
    assert d.decision == "ask"
    assert d.summary == ("The proposed refinement leaves out tools that need your approval, "
                         "so approving it as proposed does not grant them: `DeleteRepo`.")


def test_a_proposal_or_update_ask_offers_this_answer_only() -> None:
    # The SS keeps no reach for a proposal or an update, so it names the one reach it
    # applies: without `apply_options` the PS may offer `mission` and `always` (L599).
    ss, ps, clock = make_env(ask_on_mission_update=True)
    assert ps.connect(ss, SUB).status == 200
    r = ps.call(ss, "POST", "/mission", {
        "sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# Clean up",
        "tools": [{"name": "DeleteRepo", "description": "x"}], "resources": []})
    assert r.json()["apply_options"] == [{"value": "once", "label": "This proposal only"}]
    s256 = connected((ss, ps, clock))
    u = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": "d-u",
                                                 "iat": int(clock()), "sub": SUB,
                                                 "agent": AGENT, "description": "More"})
    assert u.json()["decision"] == "ask"
    assert u.json()["apply_options"] == [{"value": "once", "label": "This change only"}]


def test_no_reason_needs_the_supervisor_s_code_to_be_understood() -> None:
    internal = ("a rule needs", "did not decide", "linked to this one by", "resource-asserted",
                "prohibited composition", "rests on", "Supervision -00", "resource token")
    texts = [text for _, text in policy_mod._DOUBTS]
    texts += [Policy._comp_summary([["a", "b"]], u, ["X."]) for u in (None, True, False)]
    for text in texts:
        assert not any(phrase in text for phrase in internal), text
