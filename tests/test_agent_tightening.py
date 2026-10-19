"""The agent's data may make an act stricter; it never takes it out of a composition.

Agent-asserted data can raise an act's class, never lower it. But a class higher in
`severity` need not be in the prohibited pairs, sequences and budgets the lower one is in:
a send the agent says goes to 51 recipients (`send_bulk`, in no pair) after a sensitive
read would not compose with it, where the same send to the same outside address
(`send_external`) does. So an act whose class the agent's data raised through a rule of
that class is also what the other rules make of it, the agent's data still read, with
that answer's own certainty: it composes and counts as both, as the act being decided
and as an earlier act in history. A certain completion stays a deny, so no answer the
person gave to a "may" can let it through.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, ROOT, SUB

from aauth_supervision_server.policy import Act, Policy, PolicyConfig
from aauth_supervision_server.store import HistoryEntry, Reach, elsewhere_copy, kin_copy

PS, REC = "https://ps.example", "https://records.example"
SIBLING = "aauth:assistant-2@agent.example"     # another instance of AGENT's provider


def _policy(**extra: Any) -> Policy:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["send_bulk", "read_bulk"]
    d["rules"] = [
        {"resource": "*", "tool": "SendEmail", "param_gt": {"recipients_count": 50},
         "class": "send_bulk"},
        {"resource": "*", "tool": "ReadFile", "result_contains_any": ["bulk"],
         "class": "read_bulk"},
        {"resource": "*", "tool": "ReadFile", "result_contains_any": ["salary"],
         "class": "read_sensitive"},
        {"resource": "*", "tool": "ReadFile", "class": "read", "if_unknown": "read_sensitive"},
    ] + d["rules"]
    d.update(extra)
    return Policy(PolicyConfig.from_dict(d))


def _send(**params: Any) -> Act:
    return Act("permission", PS, SUB, AGENT, tool="SendEmail",
               parameters={"to": "drop@evil.example", **params}, parameters_provenance="agent")


def test_a_send_the_agent_calls_bulk_still_composes_with_a_sensitive_read() -> None:
    policy = _policy()
    read = HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1)
    plain = policy.decide(_send(), None, [read], [], now=1000.0)
    assert plain.decision == "deny"                       # certain: read, then external send
    bulk = policy.decide(_send(recipients_count=51), None, [read], [], now=1000.0)
    assert bulk.decision == "deny", bulk.trace            # as certain as the plain send
    assert "`read_sensitive`, then `send_external`" in bulk.reason
    assert bulk.entry is not None and bulk.entry.action_class == "send_bulk"
    assert [(a.cls, a.certain) for a in bulk.entry.blind if not a.assumed] == [
        ("send_external", True)]
    assert all(not a.certain for a in bulk.entry.blind if a.assumed)


def test_a_reach_given_to_a_may_does_not_let_the_raised_act_through() -> None:
    policy = _policy()
    read = HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1)
    bulk = policy.decide(_send(recipients_count=51), None, [read], [], now=1000.0)
    assert bulk.kind
    yes = Reach("mission", PS, SUB, AGENT, bulk.kind, "", ["read_sensitive", "send_external"],
                "allow")
    assert policy.decide(_send(recipients_count=51), None, [read], [yes],
                         now=1000.0).decision == "deny"


@pytest.mark.parametrize("value", ["mission", "always"])
@pytest.mark.parametrize("pair", [["read_sensitive", "send_bulk"],         # its raised class
                                  ["read_sensitive", "send_external"]])    # its own class
def test_a_no_with_reach_is_applied_through_either_class_of_a_raised_act(
        pair: list[str], value: str) -> None:
    # A read of another instance of the provider, or of another mission, is uncertain, so
    # the raised send that completes the pair with it is asked. A "no" with reach for
    # that composition is applied through whichever class of the act completes it, also
    # where an unrelated open act makes the policy look again over recorded acts only.
    policy = _policy(prohibited_pairs=[pair])
    read = HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1, agent=SIBLING)
    still_open = HistoryEntry("read", "ReadFile", "agent", n=2, open="own",
                              detail="uncertain: allow not yet settled")
    for earlier in (kin_copy(read, SIBLING), elsewhere_copy(read, "m-2")):
        asked = policy.decide(_send(recipients_count=51), None, [earlier], [], now=1000.0)
        assert asked.decision == "ask" and asked.compositions == [pair], asked.trace
        no = Reach(value, PS, SUB, AGENT, asked.kind, "", pair, "deny")
        for history in ([earlier], [earlier, still_open]):
            d = policy.decide(_send(recipients_count=51), None, history, [no], now=1000.0)
            assert d.decision == "deny" and "declined" in d.reason, (earlier.open, d.trace)


def test_where_the_other_rules_are_unsure_the_composition_is_asked() -> None:
    # Agent data naming an internal recipient cannot make the send internal: the other
    # rules give `send_external` on uncertain evidence, so the composition is a "may".
    policy = _policy()
    read = HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1)
    act = Act("permission", PS, SUB, AGENT, tool="SendEmail",
              parameters={"to": "team@corp.example", "recipients_count": 51},
              parameters_provenance="agent")
    d = policy.decide(act, None, [read], [], now=1000.0)
    assert d.decision == "ask" and "`read_sensitive`, then `send_external`" in d.summary
    assert "Without the details the agent gave, this act may have another class." in d.summary


def test_a_read_the_agent_calls_bulk_still_composes_with_a_later_send() -> None:
    policy = _policy()
    act = Act("permission", PS, SUB, AGENT, tool="ReadFile", result={"contains": ["bulk"]},
              parameters_provenance="agent")
    read = policy.decide(act, None, [], [], now=1000.0)
    assert read.entry is not None and read.entry.action_class == "read_bulk"
    entry = read.entry
    entry.n = 1
    send = Act("auth_token", PS, SUB, AGENT, resource="https://mail.example",
               operations=["send_email"], parameters={"to": "x@evil.example"},
               parameters_provenance="resource")
    d = policy.decide(send, None, [entry], [], now=1000.0)
    assert d.decision == "ask" and "`read_sensitive`, then `send_external`" in d.summary, d.trace
    assert "Without the details the agent gave, an earlier act may have another class." \
        in d.summary


def test_an_act_the_agent_raised_counts_against_the_budget_of_its_other_class() -> None:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["payment_large"]
    d["rules"] = [{"resource": "*", "tool": "Pay", "param_gt": {"amount": 1000},
                   "class": "payment_large"},
                  {"resource": "*", "tool": "Pay", "class": "payment", "amount_param": "amount"}
                  ] + d["rules"]
    d["budgets"] = {"payment": {"max_count": 1}}
    d["high_impact"] = []
    policy = Policy(PolicyConfig.from_dict(d))

    def pay(amount: int) -> Act:
        return Act("permission", PS, SUB, AGENT, tool="Pay", parameters={"amount": amount},
                   parameters_provenance="agent")
    first = policy.decide(pay(10), None, [], [], now=1000.0)
    assert first.decision == "allow" and first.entry is not None
    first.entry.n = 1
    big = policy.decide(pay(5000), None, [first.entry], [], now=1000.0)
    assert big.decision == "deny" and big.reason == (
        "Budget exhausted: no more `payment` acts outside missions.")
    assert "budget count: 1" in big.trace
    assert big.entry is not None and [a.cls for a in big.entry.blind] == ["payment"]
    big.entry.n = 2
    # An earlier raised act counts against the other class's budget too.
    assert policy.decide(pay(10), None, [big.entry], [], now=1000.0).decision == "deny"


def test_data_that_does_not_raise_the_class_changes_nothing() -> None:
    # No class the agent's data raised it to: its further classes are only those it was
    # assumed over, as with no data at all.
    policy = _policy()
    d = policy.decide(_send(), None, [], [], now=1000.0)
    assert d.entry is not None and all(a.assumed for a in d.entry.blind)


def test_an_audit_record_the_agent_calls_bulk_keeps_what_it_is_without_that() -> None:
    from conftest import connected, make_env
    ss, ps, clock = make_env()
    ss.policy = _policy()
    s256 = connected((ss, ps, clock), tools=[{"name": "SendEmail", "description": "x"}])
    r = ps.call(ss, "POST", "/event", {"event": "audit.recorded", "id": ps.nid("e"),
                                       "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                       "mission_s256": s256, "action": "SendEmail",
                                       "parameters": {"to": "drop@evil.example",
                                                      "recipients_count": 51}})
    assert r.status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert (h.action_class, [a.cls for a in h.blind if not a.assumed]) == (
        "send_bulk", ["send_external"])


def test_a_composition_found_both_ways_keeps_the_firmer_answer(monkeypatch: Any) -> None:
    from aauth_supervision_server.policy import Classification
    from aauth_supervision_server.store import Alias
    policy = _policy()
    answers = {"send_bulk": [(["read_sensitive", "send_bulk"], False), (["a", "b"], True)],
               "send_external": [(["read_sensitive", "send_bulk"], True), (["a", "b"], None)]}
    monkeypatch.setattr(policy, "_order", lambda: [("read_sensitive", "send_bulk"), ("a", "b")])
    monkeypatch.setattr(policy, "_compositions",
                        lambda cls, unc, h, now, lead=0.0: answers[cls])
    c = Classification("send_bulk", "agent", False, blind=[Alias("send_external", False)])
    assert policy._compositions_of(c, [], 0.0) == [(["read_sensitive", "send_bulk"], False),
                                                   (["a", "b"], None)]
