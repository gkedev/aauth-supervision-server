"""`if_unknown` applies whenever no data rule decided the act on the resource's evidence.

A rule's `if_unknown` is the class to use when the data a more specific rule needs is not
there. A forwarded R3 proposal is more evidence, never less: if no data rule read it
(the proposal names another operation than the one the data rule is narrowed to), the
data the policy needs is still unknown, and the act is the fallback class, uncertain.
"""
from __future__ import annotations

from typing import Any

import pytest

from aauth_supervision_server.adversarial import MAIL, SEND, _records, start
from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule


def _send(proposal: dict[str, Any] | None, scope: str = "mail.send") -> str:
    run = start("apc/forwarded")
    _records(run)
    d = run.act(MAIL, proposal, scope=scope)["d"]
    return str(d["decision"])


@pytest.mark.parametrize("operation", [{"tool": "reply_email"}, {"operationId": "sendEmail"},
                                       {"tool": "forward_email"}])
def test_a_proposal_no_data_rule_read_falls_back(operation: dict[str, str]) -> None:
    proposal = {"operations": [operation], "parameters": {"to": "drop@evil.example"}}
    assert _send(proposal) == "ask"


def test_a_mail_token_with_no_scope_and_no_proposal_falls_back() -> None:
    assert _send(None, scope="") == "ask"


def test_a_proposal_a_data_rule_decided_keeps_its_class() -> None:
    assert _send(SEND | {"parameters": {"to": "team@corp.example"}}) == "allow"
    assert _send(SEND | {"parameters": {"to": "drop@evil.example"}}) == "deny"


def _classify(**kw: Any) -> tuple[str, bool]:
    p = Policy(PolicyConfig(severity=["unclassified", "send", "exfil"], rules=[
        Rule(cls="exfil", resource="https://m.example", operation="send",
             param_domain_not_in={"to": ["corp"]}),
        Rule(cls="send", resource="https://m.example", if_unknown="exfil")]))
    base: dict[str, Any] = {"act": "auth_token", "iss": "i", "sub": "s", "agent": "a",
                            "resource": "https://m.example"}
    c = p.classify(Act(**(base | kw)))
    return c.cls, c.uncertain


def test_the_fallback_is_taken_unless_a_data_rule_decided() -> None:
    assert _classify(operations=["reply"], parameters={"to": "x@evil"},
                     parameters_provenance="resource") == ("exfil", True)
    assert _classify(operations=["send"], parameters={"to": "x@corp"},
                     parameters_provenance="resource") == ("send", False)
    assert _classify(operations=["send"], parameters={"to": "x@evil"},
                     parameters_provenance="resource") == ("exfil", False)
    assert _classify() == ("exfil", True)  # no proposal: nothing to decide on


def test_a_data_rule_for_another_tool_or_resource_does_not_make_the_data_unknown() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "send", "exfil"], rules=[
        Rule(cls="exfil", resource="*", tool="Mailer", param_domain_not_in={"to": ["corp"]}),
        Rule(cls="exfil", resource="https://other.example", operation="send",
             param_domain_not_in={"to": ["corp"]}),
        Rule(cls="send", resource="https://m.example", if_unknown="exfil")]))
    # The tool rule's resource "*" matches every resource; it is about the Mailer tool.
    res = p.classify(Act("auth_token", "i", "s", "a", resource="https://m.example",
                         operations=["reply"], parameters={"to": "x@evil"},
                         parameters_provenance="resource"))
    assert (res.cls, res.uncertain) == ("send", False)


def _without_fallback(rules: list[Rule], **kw: Any) -> tuple[str, bool]:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send", "exfil"],
                            default_class="read", rules=[
                                Rule(cls="exfil", resource="https://m.example",
                                     operation="send", param_domain_not_in={"to": ["corp"]}),
                                *rules]))
    base: dict[str, Any] = {"act": "auth_token", "iss": "i", "sub": "s", "agent": "a",
                            "resource": "https://m.example", "parameters_provenance": "resource"}
    c = p.classify(Act(**(base | kw)))
    return c.cls, c.uncertain


SCOPED = [Rule(cls="read", resource="https://m.example", scope="m.read")]


def test_a_scope_rule_does_not_say_what_a_named_operation_does() -> None:
    # The token carries both a scope and a proposal (R3 L530). The scope rule classifies
    # the scope; the data rule that could have read the operation did not: the act may be
    # of that rule's class.
    assert _without_fallback(SCOPED, scope="m.read", operations=["reply"],
                             parameters={"to": "x@evil"}) == ("exfil", True)


def test_with_no_rule_reached_a_named_operation_no_data_rule_read_is_assumed() -> None:
    assert _without_fallback([], scope="m.write", operations=["reply"],
                             parameters={"to": "x@evil"}) == ("exfil", True)


def test_a_scope_rule_without_a_named_operation_is_what_it_says() -> None:
    assert _without_fallback(SCOPED, scope="m.read") == ("read", False)
    assert _without_fallback([], scope="m.write") == ("read", False)


def test_a_rule_naming_the_operation_is_what_it_says() -> None:
    rules = [Rule(cls="read", resource="https://m.example", operation="reply")]
    assert _without_fallback(rules, operations=["reply"], parameters={"to": "x@evil"}) == (
        "read", False)


def test_an_unread_data_class_below_the_rule_s_class_changes_nothing() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send", "exfil"], rules=[
        Rule(cls="read", resource="https://m.example", operation="list",
             result_contains_any=["secret"]),
        Rule(cls="send", resource="https://m.example", scope="m.send")]))
    c = p.classify(Act("auth_token", "i", "s", "a", resource="https://m.example",
                       scope="m.send", operations=["reply"], parameters={"to": "x"},
                       parameters_provenance="resource"))
    assert (c.cls, c.uncertain) == ("send", False)


def test_a_mail_read_token_naming_a_sending_operation_after_a_sensitive_read_is_asked() -> None:
    proposal = {"operations": [{"operationId": "reply_email"}],
                "parameters": {"to": "drop@evil.example"}}
    assert _send(proposal, scope="mail.read") == "ask"
    assert _send(None, scope="mail.read") == "allow"     # reading the mail, as it says


def test_a_data_rule_that_matched_but_could_not_read_the_act_is_unseen_too() -> None:
    # The operation is the data rule's own, but the recipient it needs is not there.
    assert _without_fallback(SCOPED, scope="m.read", operations=["send"],
                             parameters={}) == ("exfil", True)


def test_an_unread_class_no_more_severe_than_the_rule_s_is_the_rule_s_and_certain() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send"], rules=[
        Rule(cls="send", resource="https://m.example", operation="send",
             param_domain_not_in={"to": ["corp"]}),
        Rule(cls="send", resource="https://m.example", scope="m.send")]))
    c = p.classify(Act("auth_token", "i", "s", "a", resource="https://m.example",
                       scope="m.send", operations=["reply"], parameters={"to": "x"},
                       parameters_provenance="resource"))
    assert (c.cls, c.uncertain) == ("send", False)


def test_of_several_unread_data_rules_the_most_severe_class_is_assumed() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send", "exfil"], rules=[
        Rule(cls="exfil", resource="https://m.example", operation="send",
             param_domain_not_in={"to": ["corp"]}),
        Rule(cls="send", resource="https://m.example", operation="forward",
             param_domain_not_in={"to": ["corp"]}),
        Rule(cls="read", resource="https://m.example", scope="m.read")]))
    c = p.classify(Act("auth_token", "i", "s", "a", resource="https://m.example",
                       scope="m.read", operations=["reply"], parameters={"to": "x"},
                       parameters_provenance="resource"))
    assert (c.cls, c.uncertain) == ("exfil", True)


@pytest.mark.parametrize("op", ["get_message", "list_messages"])
def test_the_example_policy_names_its_read_operations(op: str) -> None:
    # A rule naming the operation says what it does: the unread send rule is not assumed.
    proposal = {"operations": [{"operationId": op}], "parameters": {"id": "m-1"}}
    assert _send(proposal, scope="mail.read") == "allow"


def test_a_lower_class_a_data_rule_could_not_read_is_one_the_act_may_have() -> None:
    # A proposal names `relay`; the rule for it reads a score the proposal does not carry
    # (the relay is internal above 5), and the rule after it, naming no operation and no
    # `if_unknown`, makes every other act of the resource an external send. With the score
    # unknown, the relay is still external for certain, and may be internal too: it takes
    # the internal-send step of read, write, send, as a class assumed for that data does.
    from aauth_supervision_server.store import HistoryEntry
    hub = "https://hub.example"
    p = Policy(PolicyConfig.from_dict({
        "severity": ["read", "read_sensitive", "write", "send_internal", "send_external"],
        "default_class": "read", "high_impact": [],
        "prohibited_sequences": [["read_sensitive", "write", "send_internal"]],
        "rules": [{"resource": hub, "operation": "relay", "param_gt": {"internal": 5},
                   "class": "send_internal"},
                  {"resource": hub, "class": "send_external"},
                  {"resource": "https://records.example", "class": "read_sensitive"},
                  {"resource": "https://calendar.example", "class": "write"}]}))
    relay = Act("auth_token", "ps", "sub", "agent", "", resource=hub, operations=["relay"],
                parameters={}, parameters_provenance="resource")
    c = p.classify(relay)
    assert c.cls == "send_external" and not c.uncertain
    assert [(a.cls, a.certain, a.assumed) for a in c.blind] == [("send_internal", False, True)]
    hist = [HistoryEntry(c.cls, hub, c.provenance, at=10, n=1, token_exp=10**9,
                         detail=c.detail, blind=list(c.blind)),
            HistoryEntry("read_sensitive", "https://records.example", "configured", at=20,
                         n=2, token_exp=10**9, detail="rule")]
    d = p.decide(Act("auth_token", "ps", "sub", "agent", "",
                     resource="https://calendar.example"), None, hist, [], now=30)
    assert d.decision == "ask" and "`read_sensitive`, then `write`, then `send_internal`" in d.summary


def test_a_high_impact_class_a_described_act_only_may_have_meets_the_gate() -> None:
    # The proposal describes a `forward`, but names no recipient: the rule for it reads
    # the recipients (outside corp.example, an external send) and could not; the rule
    # after it, naming no operation, makes the act a sensitive read. The resource's word
    # covers that class, not the external send it may also be: the gate asks.
    import json
    from pathlib import Path
    hub = "https://hub.example"
    d = json.loads((Path(__file__).resolve().parents[1] / "examples" / "policy.json")
                   .read_text(encoding="utf-8"))
    d["serves_on_identity"] = []
    d["severity"] = ["read", "read_internal", "write", "send_internal", "send_external",
                     "read_sensitive", "payment", "delete", "admin"]
    d["rules"] = [{"resource": hub, "operation": "forward",
                   "param_domain_not_in": {"to": ["corp.example"]}, "class": "send_external"},
                  {"resource": hub, "class": "read_sensitive"}] + d["rules"]
    p = Policy(PolicyConfig.from_dict(d))
    fwd = Act("auth_token", "ps", "sub", "agent", "", resource=hub, operations=["forward"],
              parameters={}, parameters_provenance="resource")
    c = p.classify(fwd)
    assert (c.cls, c.provenance, c.uncertain) == ("read_sensitive", "resource", False)
    d2 = p.decide(fwd, None, [], [], now=0)
    assert d2.decision == "ask" and "This may be a `send_external` act" in d2.summary, d2
