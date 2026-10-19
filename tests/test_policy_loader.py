"""The policy loader: every member it accepts, every shape it refuses, at the boundaries.

A security policy with a misspelt or mistyped member must fail to load, not load with
a protection quietly missing. Each row names the member and the message it must give.
"""
from __future__ import annotations

from typing import Any

import pytest

from aauth_supervision_server.policy import PolicyConfig

RULE = {"class": "read"}

REJECT: list[tuple[dict[str, Any], str]] = [
    ({"severity": "read"}, "severity: must be an array of strings"),
    ({"high_impact": [1]}, "high_impact: must be an array of strings"),
    ({"deny_resources": None}, "deny_resources: must be an array of strings"),
    ({"allowed_tools": "*"}, "allowed_tools: must be an array of strings"),
    ({"ask_tools": [None]}, "ask_tools: must be an array of strings"),
    ({"allow_unlisted_resources": 1}, "allow_unlisted_resources: must be true or false"),
    ({"clarify_missing_justification": "no"},
     "clarify_missing_justification: must be true or false"),
    ({"ask_on_mission_update": None}, "ask_on_mission_update: must be true or false"),
    ({"default_class": ""}, "default_class: must be a non-empty string"),
    ({"default_class": 3}, "default_class: must be a non-empty string"),
    ({"composition_on_certain": ""}, "composition_on_certain: must be a non-empty string"),
    ({"max_mission_seconds": 0}, "max_mission_seconds: must be a positive integer"),
    ({"max_mission_seconds": -5}, "max_mission_seconds: must be a positive integer"),
    ({"max_mission_seconds": True}, "max_mission_seconds: must be a positive integer"),
    ({"max_mission_seconds": 1.5}, "max_mission_seconds: must be a positive integer"),
    ({"rules": {}}, "rules: must be an array"),
    ({"rules": ["read"]}, "rules[0]: must be an object"),
    ({"rules": [{}]}, "rules[0]: needs a non-empty string `class`"),
    ({"rules": [{"class": ""}]}, "rules[0]: needs a non-empty string `class`"),
    ({"rules": [RULE, {"class": 1}]}, "rules[1]: needs a non-empty string `class`"),
    ({"rules": [RULE | {"resource": 1}]}, "rules[0].resource: must be a string"),
    ({"rules": [RULE | {"if_unknown": None}]}, "rules[0].if_unknown: must be a string"),
    ({"rules": [RULE | {"result_contains_any": []}]},
     "rules[0].result_contains_any: must be a non-empty array of strings"),
    ({"rules": [RULE | {"result_contains_any": "pii"}]},
     "rules[0].result_contains_any: must be a non-empty array of strings"),
    ({"rules": [RULE | {"param_domain_not_in": {}}]},
     "rules[0].param_domain_not_in: must map parameter names to arrays of domains"),
    ({"rules": [RULE | {"param_domain_not_in": {"to": "corp.example"}}]},
     "rules[0].param_domain_not_in: must map parameter names to arrays of domains"),
    ({"rules": [RULE | {"param_domain_not_in": ["to"]}]},
     "rules[0].param_domain_not_in: must map parameter names to arrays of domains"),
    ({"rules": [RULE | {"param_gt": {}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": "100"}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": True}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"param_gt": [100]}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"clas": "x"}]}, "rules[0].clas: unknown member"),
    ({"prohibited_pairs": "a,b"}, "prohibited_pairs: must be an array of arrays of class names"),
    ({"prohibited_pairs": [["a", 1]]},
     "prohibited_pairs: must be an array of arrays of class names"),
    ({"prohibited_pairs": [["a", "b", "c"]]},
     "prohibited_pairs: each entry must name exactly 2 classes"),
    ({"prohibited_pairs": [["a"]]}, "prohibited_pairs: each entry must name exactly 2 classes"),
    ({"prohibited_sequences": [["a"], "b"]},
     "prohibited_sequences: must be an array of arrays of class names"),
    # An empty or one-class sequence would load and then raise IndexError on every
    # decision.
    ({"prohibited_sequences": [[]]}, "prohibited_sequences: each entry must name at least 2"),
    ({"prohibited_sequences": [["a", "b"], ["c"]]},
     "prohibited_sequences: each entry must name at least 2"),
    ({"budgets": []}, "budgets: must be an object keyed by class"),
    ({"budgets": {"send": {}}}, "budgets.send: must be an object with max_count"),
    ({"budgets": {"send": 3}}, "budgets.send: must be an object with max_count"),
    ({"budgets": {"send": {"max": 3}}}, "budgets.send.max: unknown member"),
    ({"budgets": {"send": {"max_count": -1}}}, "budgets.send.max_count: must be a non-negative"),
    ({"budgets": {"send": {"max_amount": True}}},
     "budgets.send.max_amount: must be a non-negative"),
    ({"budgets": {"send": {"max_amount": 2.5}}},
     "budgets.send.max_amount: must be a non-negative"),
    ({"high_imapct": []}, "high_imapct: unknown member"),
    ({"r3_member": ""}, "r3_member: must be a non-empty string or null"),
    ({"r3_member": 5}, "r3_member: must be a non-empty string or null"),
    # Entries that can never match a resource: identifiers are a lowercase https host
    # and nothing else (Protocol L1948-L1969), and patterns compare case-sensitively.
    ({"deny_resources": ["https://exfil.example/"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://x.example", "HTTPS://EXFIL.EXAMPLE"]},
     "deny_resources[1]: can never match"),
    ({"deny_resources": ["exfil.example"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://exfil.example:443"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["http://exfil.example"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://exfil.example/*"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://*.EXAMPLE"]}, "deny_resources[0]: can never match"),
    ({"serves_on_identity": ["https://Records.example"]},
     "serves_on_identity[0]: can never match"),
    ({"rules": [RULE | {"resource": "https://mail.example/"}]},
     "rules[0].resource: can never match"),
    ({"rules": [RULE | {"param_gt": {"amount": float("nan")}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": float("inf")}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": float("-inf")}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    # An integer past the float range is no number the SS can compare a value with.
    ({"rules": [RULE | {"param_gt": {"amount": 10 ** 400}}]},
     "rules[0].param_gt: must map parameter names to finite numbers"),
    # Values that load and then fail every decision that reads them.
    ({"max_mission_seconds": 10 ** 20}, "max_mission_seconds: must be a positive integer"),
    ({"resource_budgets": {"https://pay.example": {"unit": "USD", "decimals": 19,
                                                   "max_amount": 100}}},
     "resource_budgets.https://pay.example.decimals: must be an integer from 0 to 18"),
    ({"resource_budgets": {"https://pay.example": {"unit": "USD", "decimals": 2,
                                                   "max_amount": 10 ** 15}}},
     "resource_budgets.https://pay.example.max_amount: must be a non-negative integer of "
     "at most 15 digits"),
    # Patterns that load but can match no identifier: a label that starts or ends with a
    # hyphen, an empty label, an unclosed bracket, a class without the `h` of `https`.
    ({"deny_resources": ["https://exfil.example["]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://-exfil.example*"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://exfil..example*"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["[!h]*"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://*-"]}, "deny_resources[0]: can never match"),
    ({"rules": [RULE | {"resource": "https://*.-x"}]}, "rules[0].resource: can never match"),
    # However many wildcards a pattern has, one that can match nothing is refused.
    ({"deny_resources": ["https://*.*.*.*.*.*.*_"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://*.*.*.*.*.*.*.EXAMPLE"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["HTTPS://?**?[a-s][a-z]"]}, "deny_resources[0]: can never match"),
    ({"deny_resources": ["https://exfil.example/*/*/*/*/*/*/*"]},
     "deny_resources[0]: can never match"),
    # A label is at most 63 characters (RFC 1035 Section 2.3.4), whatever follows it.
    ({"deny_resources": ["https://" + "a" * 64 + "*"]}, "deny_resources[0]: can never match"),
]


@pytest.mark.parametrize(("policy", "message"), REJECT, ids=[m.split(":")[0] for _, m in REJECT])
def test_loader_refuses(policy: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError) as e:
        PolicyConfig.from_dict(policy)
    assert str(e.value).startswith(message)


def test_loader_refuses_a_non_object() -> None:
    for d in ([], "policy", None, 3):
        with pytest.raises(ValueError, match="policy: must be a JSON object"):
            PolicyConfig.from_dict(d)  # type: ignore[arg-type]


def test_loader_accepts_every_member_at_its_boundary() -> None:
    cfg = PolicyConfig.from_dict({
        "severity": ["read", "send"], "high_impact": ["send"],
        "rules": [{"class": "send", "resource": "https://mail.example", "operation": "send*",
                   "scope": "mail.send", "tool": "", "result_contains_any": ["pii"],
                   "param_domain_not_in": {"to": []}, "param_gt": {"amount": 0.5},
                   "amount_param": "amount", "if_unknown": "send"}],
        "prohibited_pairs": [["read", "send"]], "prohibited_sequences": [["read", "send"]],
        "budgets": {"send": {"max_count": 0, "max_amount": 0}},
        "deny_resources": [], "allowed_tools": [], "ask_tools": [],
        "allow_unlisted_resources": True, "clarify_missing_justification": True,
        "ask_on_mission_update": True, "max_mission_seconds": 1,
        "default_class": "read", "composition_on_certain": "ask", "r3_member": "x"})
    assert cfg.allow_unlisted_resources is True
    assert cfg.clarify_missing_justification is True
    assert cfg.ask_on_mission_update is True
    assert cfg.max_mission_seconds == 1
    assert cfg.budgets["send"].max_count == 0 and cfg.budgets["send"].max_amount == 0
    assert cfg.prohibited_pairs == [("read", "send")]
    assert cfg.prohibited_sequences == [("read", "send")]
    r = cfg.rules[0]
    assert (r.cls, r.operation, r.param_gt, r.if_unknown) == ("send", "send*", {"amount": 0.5},
                                                              "send")
    assert cfg.default_class == "read" and cfg.composition_on_certain == "ask"
    assert cfg.r3_member == "x"


def test_max_mission_seconds_may_be_null() -> None:
    assert PolicyConfig.from_dict({"max_mission_seconds": None}).max_mission_seconds is None


def test_rank_orders_by_severity_and_unknown_is_below_all() -> None:
    cfg = PolicyConfig(severity=["read", "write", "send"])
    assert [cfg.rank(c) for c in ("read", "write", "send")] == [0, 1, 2]
    assert cfg.rank("nope") == -1
    assert cfg.rank("nope") < cfg.rank("read")


@pytest.mark.parametrize("pattern", ["*", "https://mail.example", "https://*.example",
                                     "*.example", "https://mail.ex?mple", "https://[a-m]*",
                                     "https://xn--bcher-kva.example", "https://a.*.example",
                                     "https://*-*.example", "https://x*", "https://*.*",
                                     "https://???.example", "*mail*", "[h]ttps://*",
                                     "https://*?*?*?*?*?*", "https://[!]]x.example",
                                     "https://[]a]x.example", "http*", "https*", "https:*",
                                     "*://x.example", "h*.example", "http[a-z]://x.example",
                                     "https://*-*-*-*-*-*-*-*-*-*-x"])
def test_a_resource_pattern_that_can_match_is_accepted(pattern: str) -> None:
    cfg = PolicyConfig.from_dict({"deny_resources": [pattern], "serves_on_identity": [pattern],
                                  "rules": [RULE | {"resource": pattern}]})
    assert cfg.deny_resources == [pattern] and cfg.rules[0].resource == pattern


def test_a_rule_for_acts_without_a_resource_is_accepted() -> None:
    # An empty `resource` matches the acts that have none (a tool's permission).
    assert PolicyConfig.from_dict({"rules": [RULE | {"resource": ""}]}).rules[0].resource == ""


def test_the_bounds_are_accepted_at_their_limit() -> None:
    from aauth_supervision_server.policy import MAX_AMOUNT, MAX_DECIMALS, MAX_MISSION_SECONDS
    cfg = PolicyConfig.from_dict({
        "max_mission_seconds": MAX_MISSION_SECONDS,
        "resource_budgets": {"https://pay.example": {"unit": "USD", "decimals": MAX_DECIMALS,
                                                     "max_amount": MAX_AMOUNT}}})
    assert cfg.max_mission_seconds == MAX_MISSION_SECONDS
