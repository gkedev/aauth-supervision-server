"""`param_domain_not_in` reads every recipient a parameter can name.

The rule makes an act external when a recipient is outside the listed domains. A mail
service sends to every recipient a field names, so the rule must see each of them: a list
written in one string ("a@x, b@y"), and every recipient parameter the rule names, of which
an act may carry only some. A recipient that is not plainly `local@domain` (a quoted or
routed local part, a comment, a stray `@`, a line break) is outside every domain.
"""
from __future__ import annotations

from typing import Any

import pytest

from aauth_supervision_server.adversarial import MAIL, SEND, _records, start
from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule

CORP = ["corp.example"]
RECIPIENTS = {"to": CORP, "cc": CORP, "bcc": CORP}


def classify(params: dict[str, Any] | None, rule: dict[str, list[str]] | None = None
             ) -> tuple[str, bool]:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send", "exfil"], rules=[
        Rule(cls="exfil", param_domain_not_in=rule or {"to": CORP}),
        Rule(cls="send", if_unknown="exfil")]))
    c = p.classify(Act("auth_token", "https://ps.example", "sub-1", "agent-1", "m-1",
                       "https://mail.example", parameters=params,
                       parameters_provenance="resource"))
    return c.cls, c.uncertain


@pytest.mark.parametrize("to", [
    "drop@evil.example, team@corp.example",
    "drop@evil.example; team@corp.example",
    "team@corp.example,drop@evil.example",
    "drop@evil.example\n@corp.example",
    '"drop@evil.example"@corp.example',
    "drop%evil.example@corp.example",
    "evil.example!drop@corp.example",
    "@evil.example:drop@corp.example",
    "drop@evil.example <team@corp.example>",
    "team@corp.example (drop@evil.example)",
    "Team <drop@evil.example>",
    '"drop"@corp.example',
    "x y@corp.example",
    "(c)team@corp.example",
    "team@corp.example>",
    "team@corp.example\ndrop@evil.example",
    "team:a@corp.example",
    "",
    ["team@corp.example", "drop@evil.example, x@corp.example"],
])
def test_a_recipient_outside_the_domains_is_seen_however_it_is_written(to: Any) -> None:
    assert classify({"to": to}) == ("exfil", False)


@pytest.mark.parametrize("to", [
    "team@corp.example",
    "TEAM@Corp.Example",
    "first.last+tag@corp.example",
    "a@corp.example, b@corp.example",
    "a@corp.example; b@corp.example",
    "a@corp.example,",
    "Team <team@corp.example>",
    '"Smith, John" <j@corp.example>, a@corp.example',
    "corp.example",
    ["a@corp.example", "Team <b@corp.example>"],
])
def test_recipients_all_inside_the_domains_are_internal(to: Any) -> None:
    assert classify({"to": to}) == ("send", False)


def test_every_recipient_parameter_the_rule_names_is_read() -> None:
    assert classify({"to": "a@corp.example"}, RECIPIENTS) == ("send", False)
    assert classify({"to": "a@corp.example", "bcc": "drop@evil.example"},
                    RECIPIENTS) == ("exfil", False)
    assert classify({"to": "a@corp.example", "cc": ["drop@evil.example"]},
                    RECIPIENTS) == ("exfil", False)
    assert classify({"cc": "drop@evil.example"}, RECIPIENTS) == ("exfil", False)
    assert classify({"to": "drop@evil.example", "cc": "a@corp.example"},
                    RECIPIENTS) == ("exfil", False)


def test_listed_domains_match_whatever_their_case() -> None:
    assert classify({"to": "a@corp.example"}, {"to": ["Corp.Example"]}) == ("send", False)


def test_each_named_parameter_has_its_own_domains() -> None:
    rule = {"to": CORP, "cc": ["partner.example"]}
    assert classify({"to": "a@corp.example", "cc": "b@partner.example"}, rule) == ("send", False)
    assert classify({"to": "a@partner.example", "cc": "b@partner.example"},
                    rule) == ("exfil", False)


def test_recipients_and_result_conditions_must_both_hold() -> None:
    p = Policy(PolicyConfig(severity=["unclassified", "read", "send", "exfil"], rules=[
        Rule(cls="exfil", result_contains_any=["pii"], param_domain_not_in={"to": CORP}),
        Rule(cls="send")]))

    def cls(result: dict[str, Any]) -> str:
        return p.classify(Act("auth_token", "https://ps.example", "sub-1", "agent-1", "m-1",
                              "https://mail.example", parameters={"to": "drop@evil.example"},
                              parameters_provenance="resource", result=result)).cls
    assert cls({"contains": ["pii"]}) == "exfil"
    assert cls({"contains": ["other"]}) == "send"


def test_with_none_of_the_named_parameters_the_recipients_are_unknown() -> None:
    # Nothing the rule names is present: the data it needs is unavailable, so the
    # conservative fallback applies, as for a single named parameter that is missing.
    assert classify({}, RECIPIENTS) == ("exfil", True)
    assert classify({"subject": "x"}, RECIPIENTS) == ("exfil", True)
    assert classify({"subject": "x"}) == ("exfil", True)
    assert classify(None, RECIPIENTS) == ("exfil", True)


def test_a_named_parameter_that_is_not_readable_keeps_the_act_unknown() -> None:
    assert classify({"to": "a@corp.example", "bcc": 5}, RECIPIENTS) == ("exfil", True)
    assert classify({"to": "a@corp.example", "bcc": {"s256": "x"}},
                    RECIPIENTS) == ("exfil", True)


@pytest.mark.parametrize("params", [
    {"to": "drop@evil.example, team@corp.example"},
    {"to": "team@corp.example", "bcc": "drop@evil.example"},
    {"to": "team@corp.example", "cc": ["drop@evil.example"]},
])
def test_example_policy_after_a_sensitive_export_the_smuggled_send_is_denied(
        params: dict[str, Any]) -> None:
    run = start("apc/forwarded")
    _records(run)
    d = run.act(MAIL, SEND | {"parameters": params}, scope="mail.send")["d"]
    assert d["decision"] == "deny", d


def test_example_policy_an_internal_list_after_a_sensitive_export_is_allowed() -> None:
    run = start("apc/forwarded")
    _records(run)
    d = run.act(MAIL, SEND | {"parameters": {"to": "a@corp.example, b@corp.example"}},
                scope="mail.send")["d"]
    assert d["decision"] == "allow", d
