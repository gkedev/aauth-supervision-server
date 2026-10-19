"""Every class the agent's data raised an act through, down to the class it has without.

An act whose class the agent's data raised through a rule of that class is also what the
other rules make of it. Where a second rule raises it again, it is that class too, and so
on down to the class the act has with no raising rule, held to the class it has with the
agent's data unknown. It is one act under all of them: it composes as any, counts against
each one's budget with the amount that class's rule reads, and meets the high-impact gate
if any of them is high impact. Data that would lower the class leaves it the class it has
with the data unknown, as certain as that class is.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, ROOT, SUB

from aauth_supervision_server.policy import Act, Policy, PolicyConfig, _doubts
from aauth_supervision_server.store import Alias, HistoryEntry

PS, REC = "https://ps.example", "https://records.example"
READ = HistoryEntry("read_sensitive", REC, "resource", detail="rule", n=1)


def _policy(**extra: Any) -> Policy:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["send_bulk", "send_large"]
    d["rules"] = [
        {"resource": "*", "tool": "SendEmail", "param_gt": {"recipients_count": 50},
         "class": "send_bulk"},
        {"resource": "*", "tool": "SendEmail", "param_gt": {"attachments_mb": 10},
         "class": "send_large"},
    ] + d["rules"]
    d.update(extra)
    return Policy(PolicyConfig.from_dict(d))


def _send(**params: Any) -> Act:
    return Act("permission", PS, SUB, AGENT, tool="SendEmail",
               parameters={"to": "drop@evil.example", **params}, parameters_provenance="agent")


def test_a_high_impact_class_under_the_raised_one_meets_the_gate() -> None:
    p = _policy(prohibited_pairs=[], prohibited_sequences=[])
    assert p.decide(_send(), None, [], [], now=0).decision == "ask"
    d = p.decide(_send(recipients_count=51), None, [], [], now=0)
    assert d.decision == "ask", d.trace
    assert "This is a `send_external` act" in d.summary


def test_two_raising_rules_keep_every_class_down_to_the_one_without() -> None:
    p = _policy()
    c = p.classify(_send(recipients_count=51, attachments_mb=20))
    assert c.cls == "send_bulk"
    # (with the classes the act was assumed over, uncertain, as without the agent's data)
    assert [(a.cls, a.certain) for a in c.blind if not a.assumed] == [("send_large", True),
                                                                      ("send_external", True)]
    assert all(not a.certain for a in c.blind if a.assumed)
    d = p.decide(_send(recipients_count=51, attachments_mb=20), None, [READ], [], now=0)
    assert d.decision == "deny" and "`read_sensitive`, then `send_external`" in d.reason


def test_a_raised_twice_act_in_history_composes_with_a_later_read() -> None:
    p = _policy()
    send = p.decide(_send(recipients_count=51, attachments_mb=20), None, [], [], now=0)
    assert send.entry is not None
    send.entry.n = 1
    read = Act("auth_token", PS, SUB, AGENT, resource=REC, parameters_provenance="resource")
    assert p.decide(read, None, [send.entry], [], now=0).decision == "deny"


def test_each_class_counts_against_its_budget_with_its_own_amount() -> None:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["flagged_payment"]
    d["rules"] = [{"resource": "*", "tool": "Transfer", "param_gt": {"risk": 5},
                   "class": "flagged_payment", "amount_param": "fee"},
                  {"resource": "*", "tool": "Transfer", "class": "payment",
                   "amount_param": "amount"}] + d["rules"]
    d["budgets"] = {"payment": {"max_amount": 500000}}
    d["high_impact"] = []
    p = Policy(PolicyConfig.from_dict(d))

    def transfer(**params: Any) -> Act:
        return Act("permission", PS, SUB, AGENT, tool="Transfer",
                   parameters={"amount": 400000, "fee": 1, **params},
                   parameters_provenance="agent")
    first = p.decide(transfer(risk=9), None, [], [], now=0)
    assert first.decision == "allow" and first.entry is not None
    assert [(a.cls, a.amount, a.amount_known) for a in first.entry.blind] == [
        ("payment", 400000, True)]
    first.entry.n = 1
    second = p.decide(transfer(risk=9), None, [first.entry], [], now=0)
    assert second.decision == "deny" and second.reason == (
        "Budget exceeded: this act's amount would take the `payment` budget outside missions "
        "past its limit.")
    assert "budget amount: 400000 + 400000 of 500000" in second.trace


def test_data_that_would_lower_a_certain_class_leaves_it_certain() -> None:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["rules"] = [{"resource": "*", "tool": "ReadFile", "result_contains_any": ["public"],
                   "class": "read"},
                  {"resource": "*", "tool": "ReadFile", "class": "read_sensitive"}] + d["rules"]
    p = Policy(PolicyConfig.from_dict(d))
    c = p.classify(Act("permission", PS, SUB, AGENT, tool="ReadFile",
                       result={"contains": ["public"]}, parameters_provenance="agent"))
    assert (c.cls, c.uncertain) == ("read_sensitive", False)


def _transfer_policy(r0_amount: str | None) -> Policy:
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = ["unclassified", "read", "fee_transfer"] + d["severity"][1:]
    r0: dict[str, Any] = {"resource": "*", "tool": "Transfer", "param_gt": {"fee": 0},
                          "class": "fee_transfer"}
    if r0_amount:
        r0["amount_param"] = r0_amount
    d["rules"] = [r0, {"resource": "*", "tool": "Transfer", "class": "payment",
                       "amount_param": "amount"}] + d["rules"]
    d["high_impact"] = []
    return Policy(PolicyConfig.from_dict(d))


def test_data_that_would_lower_a_class_counts_the_amount_that_class_s_rule_reads() -> None:
    # The fee rule would make a payment a fee transfer: the act stays a payment, and as
    # one it counts the amount the payment rule reads, not the fee.
    act = Act("permission", PS, SUB, AGENT, tool="Transfer",
              parameters={"amount": 400000, "fee": 1}, parameters_provenance="agent")
    for r0_amount in ("fee", None):
        p = _transfer_policy(r0_amount)
        c = p.classify(act)
        assert (c.cls, c.amount, c.uncertain) == ("payment", 400000, False)
        paid = HistoryEntry("payment", "", "agent", amount=400000, amount_known=True,
                            detail="rule payment", n=1)
        d = p.decide(act, None, [paid], [], now=0)
        assert d.decision == "deny" and "Budget exceeded" in d.reason, d.trace


def test_an_open_person_token_spends_no_class_budget() -> None:
    p = _policy(budgets={"read_sensitive": {"max_count": 1}})
    token = HistoryEntry("read_sensitive", REC, "configured", open="own", borrowed=True,
                         detail="uncertain: allow not yet settled: uncertain: person token")
    read = Act("auth_token", PS, SUB, AGENT, resource=REC, parameters_provenance="resource")
    assert p.decide(read, None, [token], [], now=0).decision != "deny"
    assert "budget" not in " ".join(p.decide(read, None, [token], [], now=0).trace)


def test_a_person_token_in_another_mission_is_named_as_both() -> None:
    from aauth_supervision_server.policy import Classification
    send = Classification("send_external", "resource", False)
    pt = HistoryEntry("read_sensitive", REC, "configured", scope="m2", open="mission",
                      detail="uncertain: person token")
    assert _doubts(["read_sensitive", "send_external"], send, [pt]) == [
        "One of the acts is in another mission.",
        f"A person token for {REC} may have let that resource serve a request."]
    # In a mission of the agent's own, for an act outside missions, that mission composes
    # certainly with the act on its own: only the person token is in doubt.
    own = HistoryEntry("read_sensitive", REC, "configured", scope="m2",
                       detail="uncertain: person token")
    assert _doubts(["read_sensitive", "send_external"], send, [own]) == [
        f"A person token for {REC} may have let that resource serve a request."]


def test_an_alias_is_one_of_the_act_s_classes_in_the_search() -> None:
    p = _policy(prohibited_pairs=[],
                prohibited_sequences=[["read_sensitive", "send_large", "send_external"]])
    live = 10 ** 10
    send = HistoryEntry("send_bulk", "SendEmail", "agent", detail="rule", token_exp=live,
                        blind=[Alias("send_large", True), Alias("send_external", True)])
    read = Act("auth_token", PS, SUB, AGENT, resource=REC, parameters_provenance="resource")
    # One act cannot take two steps; with a second one, the sequence completes.
    assert p.decide(read, None, [send], [], now=0).decision == "allow"
    other = HistoryEntry("send_external", "https://mail.example", "resource", detail="rule",
                         token_exp=live)
    assert p.decide(read, None, [send, other], [], now=0).decision == "deny"


def test_a_class_read_twice_counts_the_larger_amount() -> None:
    # The fee rule gives the act the class the payment rule does, metering the fee: the
    # agent's data cannot make a payment count as its fee.
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["rules"] = [{"resource": "*", "tool": "Transfer", "param_gt": {"fee": 0},
                   "class": "payment", "amount_param": "fee"},
                  {"resource": "*", "tool": "Transfer", "class": "payment",
                   "amount_param": "amount"}] + d["rules"]
    p = Policy(PolicyConfig.from_dict(d))
    c = p.classify(Act("permission", PS, SUB, AGENT, tool="Transfer",
                       parameters={"amount": 400000, "fee": 1}, parameters_provenance="agent"))
    assert (c.cls, c.amount) == ("payment", 400000)


def test_a_class_counts_the_amount_its_rule_reads_whatever_reading_is_certain() -> None:
    # The domain rule decides the class and reads no amount; the payment rule reads it,
    # under the class it falls back to. The amount is counted, not lost to the ask.
    d: dict[str, Any] = {
        "severity": ["routine", "payment", "payment_external"], "high_impact": [],
        "rules": [{"resource": "*", "tool": "Pay",
                   "param_domain_not_in": {"to": ["corp.example"]},
                   "class": "payment_external"},
                  {"resource": "*", "tool": "Pay", "class": "payment",
                   "if_unknown": "payment_external", "amount_param": "amount"}],
        "budgets": {"payment_external": {"max_amount": 100}},
        "prohibited_pairs": [], "prohibited_sequences": []}
    p = Policy(PolicyConfig.from_dict(d))
    for params in ({"amount": 500}, {"amount": 500, "to": "x@evil.example"}):
        act = Act("permission", PS, SUB, AGENT, tool="Pay", parameters=params,
                  parameters_provenance="agent")
        assert p.decide(act, None, [], [], now=0).decision == "deny", params


def _bank(budgets: dict[str, Any]) -> Policy:
    # A transfer is flagged where its risk is high (its fee is what is metered then), and a
    # payment of its amount otherwise; with the risk unknown, a payment is assumed.
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["flagged_payment"]
    d["rules"] = [{"resource": "https://bank.example", "operation": "transfer",
                   "param_gt": {"risk": 5}, "class": "flagged_payment", "amount_param": "fee"},
                  {"resource": "https://bank.example", "operation": "transfer",
                   "class": "payment", "amount_param": "amount", "if_unknown": "payment"}
                  ] + d["rules"]
    d["budgets"], d["high_impact"], d["serves_on_identity"] = budgets, [], []
    return Policy(PolicyConfig.from_dict(d))


def _transfer(**params: Any) -> Act:
    return Act("auth_token", PS, SUB, AGENT, resource="https://bank.example",
               operations=["transfer"], parameters={"amount": 50, "fee": 900, **params},
               parameters_provenance="resource")


def _twice(p: Policy, act: Act) -> Any:
    first = p.decide(act, None, [], [], now=0)
    assert first.entry is not None
    first.entry.n = 1
    return p.decide(act, None, [first.entry], [], now=0)


def test_an_assumed_class_counts_with_the_amount_its_own_rule_reads() -> None:
    # With the risk unknown, the transfer may be flagged: as flagged_payment its fee (900)
    # is what counts, never the payment's amount (50). Two may take the flagged fees past
    # 1000: the second is not allowed.
    p = _bank({"flagged_payment": {"max_amount": 1000}})
    c = p.classify(_transfer())
    assert c.cls == "payment" and c.uncertain
    assert [(a.cls, a.amount, a.amount_known, a.assumed) for a in c.blind] == [
        ("flagged_payment", 900, True, True)]
    assert _twice(p, _transfer()).decision != "allow"
    assert _twice(p, _transfer(risk=9)).decision == "deny"  # flagged for certain


def test_a_budget_only_an_assumed_class_reaches_is_asked_not_denied() -> None:
    # Whether a transfer with its risk unknown is flagged is not known: a budget of the
    # flagged class reached only through that assumption is put to the person, by count
    # and by amount; one reached by a transfer flagged for certain is a ceiling.
    for budgets, note in (({"flagged_payment": {"max_count": 1}}, "at most 1"),
                          ({"flagged_payment": {"max_amount": 1000}}, "1000")):
        p = _bank(budgets)
        second = _twice(p, _transfer())
        assert second.decision == "ask" and "flagged_payment" in second.summary, second
        assert note in second.summary
        assert _twice(p, _transfer(risk=9)).decision == "deny"


def test_a_high_impact_class_the_act_only_may_have_is_told_as_may() -> None:
    # 51 recipients and no `to`: send_bulk for certain (the agent's data), send_external
    # only as what the act may be with no recipient known. The gate meets send_external,
    # and the person is told the act may be one, never that it is; a composition through
    # a class assumed for the missing data names that doubt.
    p = _policy()
    act = Act("permission", PS, SUB, AGENT, tool="SendEmail",
              parameters={"recipients_count": 51}, parameters_provenance="agent")
    c = p.classify(act)
    assert c.cls == "send_bulk" and not c.uncertain
    d = p.decide(act, None, [], [], now=0)
    assert d.decision == "ask" and "This may be a `send_external` act" in d.summary, d.summary
    assert "This is a `send_external` act" not in d.summary
    assert any("assumed" in t for t in _doubts(["read_sensitive", "send_internal"], c, [READ]))


def test_an_earlier_act_composing_through_an_assumed_class_names_that_doubt() -> None:
    # An earlier send of certain class whose internal-send class was only assumed: a
    # composition through that class rests on the assumption, and says so.
    send = HistoryEntry("send_bulk", "SendEmail", "agent", detail="rule send_bulk", n=2,
                        blind=[Alias("send_internal", assumed=True)])
    c = _policy().classify(Act("permission", PS, SUB, AGENT, tool="WriteDoc"))
    texts = _doubts(["read_sensitive", "send_internal"], c, [READ, send])
    assert any("earlier act's class was assumed" in t for t in texts), texts


def test_a_certain_act_after_one_only_assumed_of_its_class_is_asked() -> None:
    # One flagged transfer allowed: a transfer whose risk was unknown (only assumed
    # flagged) does not use it up for certain, so one flagged for certain after it is put
    # to the person, not refused.
    p = _bank({"flagged_payment": {"max_count": 1}})
    first = p.decide(_transfer(), None, [], [], now=0)
    assert first.entry is not None
    first.entry.n = 1
    second = p.decide(_transfer(risk=9), None, [first.entry], [], now=0)
    assert second.decision == "ask" and "at most 1 `flagged_payment`" in second.summary


def _flagged_by_default(tool: bool) -> Policy:
    # As `_bank`, but a transfer whose risk is unknown is assumed flagged (`if_unknown`),
    # as auth tokens at the bank or as the agent's `Pay` tool.
    d = json.loads((ROOT / "examples" / "policy.json").read_text(encoding="utf-8"))
    d["severity"] = d["severity"] + ["flagged_payment"]
    where = {"resource": "*", "tool": "Pay"} if tool else {
        "resource": "https://bank.example", "operation": "transfer"}
    d["rules"] = [{**where, "param_gt": {"risk": 5}, "class": "flagged_payment",
                   "amount_param": "fee"},
                  {**where, "class": "payment", "amount_param": "amount",
                   "if_unknown": "flagged_payment"}] + d["rules"]
    d["budgets"] = {"flagged_payment": {"max_amount": 1000}}
    d["high_impact"], d["serves_on_identity"] = [], []
    return Policy(PolicyConfig.from_dict(d))


@pytest.mark.parametrize("tool", [False, True])
def test_a_class_assumed_as_its_own_counts_with_the_amount_its_rule_reads(tool: bool) -> None:
    # The risk left out, the act is assumed flagged: as flagged_payment it counts its fee
    # (900), the amount that class's rule reads, never the payment's amount (50), so two
    # pass the 1000 fee ceiling as two flagged for certain do. An agent cannot slip under
    # the ceiling by leaving the risk out.
    p = _flagged_by_default(tool)
    act = Act("permission", PS, SUB, AGENT, tool="Pay",
              parameters={"amount": 50, "fee": 900}, parameters_provenance="agent") \
        if tool else _transfer()
    c = p.classify(act)
    assert c.cls == "flagged_payment" and c.uncertain and c.amount == 900
    second = _twice(p, act)
    assert second.decision == "deny" and second.reason == (
        "Budget exceeded: this act's amount would take the `flagged_payment` budget outside "
        "missions past its limit.")
    assert "budget amount: 900 + 900 of 1000" in second.trace


@pytest.mark.parametrize("budget", [{"max_count": 2}, {"max_amount": 1800}])
def test_an_assumed_budget_ask_names_the_open_act_that_would_pass_it(budget: Any) -> None:
    # One transfer only assumed flagged, one flagged for certain, and a third flagged for
    # certain allowed but not yet reported: a fourth is asked, and the person is told the
    # open act would take the ceiling past its limit with this one, not only that an
    # earlier act may be flagged.
    import dataclasses
    p = _bank({"flagged_payment": budget})
    hist: list[HistoryEntry] = []
    for n, act in enumerate((_transfer(), _transfer(risk=9)), 1):
        e = p.decide(act, None, list(hist), [], now=0).entry
        assert e is not None
        e.n, e.token_exp = n, 10 ** 9
        hist.append(e)
    third = p.decide(_transfer(risk=9), None, list(hist), [], now=0).entry
    assert third is not None
    open_one = dataclasses.replace(third, n=3, token_exp=10 ** 9, borrowed=True, open="own",
                                   detail="uncertain: allow not yet settled: " + third.detail)
    fourth = p.decide(_transfer(risk=9), None, hist + [open_one], [], now=0)
    assert fourth.decision == "ask" and "has not been reported done yet" in fourth.summary
