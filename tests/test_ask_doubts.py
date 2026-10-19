"""Which doubts an ask names: each one true of an act that could take a step.

An ask the supervisor cannot settle says why (Supervision L266: the `summary` the PS shows
the person). A doubt is named for the act being decided, or for an earlier act that could
take one of the combination's other steps: never for an earlier act of the step this act
takes, never as the wrong kind (an act whose class was assumed told as one resting on the
agent's details, or the reverse), and the mission is named only where the combination
needs the acts of more than one. Where only this act is in doubt, through any of its
classes, the ask says the other acts are certain.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, make_env, policy_cfg

from aauth_supervision_server.adversarial import CAL, MAIL, SEND, _records, start
from aauth_supervision_server.policy import Act, HistoryEntry, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import Alias

ISS = "https://ps.example"
REC, CHAT, CALENDAR = "https://records.example", "https://chat.example", "https://calendar.example"
ASSUMED_EARLIER = ("An earlier act's class was assumed, because what the supervisor received "
                   "about it did not show what the policy's rules read.")
WORD_EARLIER = "The agent's own details would make an earlier act less severe"
CERTAIN_OTHERS = "The supervisor is certain of the other acts, not of this one."


def _abc(**kw: Any) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "A", "B", "C"],
                               rules=[Rule(resource=f"https://{c.lower()}.example", cls=c)
                                      for c in "ABC"], composition_on_certain="ask", **kw))


def _act(c: str, mission: str = "m") -> Act:
    return Act("auth_token", ISS, SUB, AGENT, mission, resource=f"https://{c.lower()}.example",
               parameters_provenance="resource")


def _entry(c: str, detail: str = "rule", **kw: Any) -> HistoryEntry:
    return HistoryEntry(c, f"https://{c.lower()}.example", "configured", detail=detail, **kw)


def _send(params: dict[str, Any]) -> Act:
    return Act("permission", ISS, SUB, AGENT, "", tool="SendEmail", parameters=params,
               parameters_provenance="agent")


def _read_then_write() -> list[HistoryEntry]:
    return [HistoryEntry("read_sensitive", REC, "configured", at=1, detail="rule read_sensitive"),
            HistoryEntry("write", CALENDAR, "configured", at=2, detail="rule write")]


def test_an_audit_record_with_no_details_is_told_as_assumed_not_as_the_agent_s_word() -> None:
    # Parameters are OPTIONAL in an audit record (Protocol L1256): one with none gave the
    # agent's word for nothing, so the send's class was assumed, not lowered by the agent.
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "action": "SendEmail"}).status == 201
    clock.t += 5
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    d = r.json()
    assert d["decision"] == "ask"
    assert ASSUMED_EARLIER in d["summary"] and WORD_EARLIER not in d["summary"]


def test_an_act_held_above_the_agent_s_details_is_not_also_told_as_assumed() -> None:
    # The agent names an internal recipient: its details would make the send less severe,
    # and that is the one doubt; the request did show what the rules read.
    d = Policy(policy_cfg()).decide(_send({"to": "colleague@corp.example"}), None,
                                    _read_then_write(), [], now=10)
    assert d.decision == "ask"
    assert CERTAIN_OTHERS in d.summary
    assert "The agent's own details would make this act less severe" in d.summary
    assert "This act's class is assumed" not in d.summary


def test_a_class_kept_only_with_the_agent_s_details_set_aside_is_told_as_such() -> None:
    # The agent names an outside recipient, so the rules read the send as external. Only
    # with its details set aside is it the internal send a read, write, send completes:
    # the request showed what the rules read, so its class is not "assumed".
    d = Policy(policy_cfg(prohibited_pairs=[])).decide(_send({"to": "x@evil.example"}), None,
                                                       _read_then_write(), [], now=10)
    assert d.decision == "ask"
    assert CERTAIN_OTHERS in d.summary and "This act's class is assumed" not in d.summary
    assert "Without the details the agent gave, this act may have another class." in d.summary


def test_an_earlier_class_kept_only_with_the_agent_s_details_set_aside_is_told_as_such() -> None:
    earlier = _entry("A", blind=[Alias("B", assumed=True, set_aside=True)])
    d = _abc(prohibited_pairs=[("B", "C")]).decide(_act("C"), None, [earlier], [], now=10)
    assert d.decision == "ask"
    assert "Without the details the agent gave, an earlier act may have another class." in \
        d.summary
    assert "assumed" not in d.summary


def test_only_this_act_in_doubt_through_a_further_class_is_told_once() -> None:
    # A certain records read and calendar write, then a mail send whose class is assumed
    # (`send_external`, and `send_internal` that it may be): both combinations rest on
    # this act alone, so they are told together, with its doubt once.
    run = start("apc/current")
    _records(run)
    run.complete(run.act(CAL))
    d: dict[str, Any] = run.act(MAIL, SEND | {"parameters": {"to": "drop@evil.example"}},
                                scope="mail.send")["d"]
    assert d["decision"] == "ask"
    s = d["summary"]
    assert s.count(CERTAIN_OTHERS) == 1 and "neither confirm" not in s
    assert s.count("This act's class is assumed") == 1 and "person token" not in s
    assert "`read_sensitive`, then `write`, then `send_internal`" in s


def test_an_earlier_act_of_the_step_this_act_takes_is_no_doubt() -> None:
    # An assumed A, and an earlier C not settled yet (a send asked and left open): this
    # act takes the C step, so only the assumed A is in doubt.
    still_open = _entry("C", detail="uncertain: allow not yet settled: rule", open="own")
    d = _abc(prohibited_pairs=[("A", "C")]).decide(
        _act("C"), None, [_entry("A", "uncertain: x"), still_open], [], now=10)
    assert d.decision == "ask"
    assert ASSUMED_EARLIER in d.summary and "not settled" not in d.summary


def test_the_mission_is_named_only_where_the_combination_needs_more_than_one() -> None:
    # Outside missions, a mission of the agent's composes certainly with the act on its
    # own: an assumed A there is in doubt for being assumed, not for its mission.
    pair = _abc(prohibited_pairs=[("A", "C")]).decide(
        _act("C", mission=""), None, [_entry("A", "uncertain: x", scope="m1", borrowed=True)],
        [], now=10)
    assert pair.decision == "ask"
    assert ASSUMED_EARLIER in pair.summary and "another mission" not in pair.summary
    # A certain A in one mission and a certain B in another: only both missions together
    # complete A, B, C, and that is the doubt.
    seq = _abc(prohibited_sequences=[("A", "B", "C")]).decide(
        _act("C", mission=""), None,
        [_entry("A", at=1, scope="m1", borrowed=True), _entry("B", at=2, scope="m2",
                                                             borrowed=True)], [], now=10)
    assert seq.decision == "ask"
    assert "One of the acts is in another mission." in seq.summary
