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
     "rules[0].param_gt: must map parameter names to numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": "100"}}]},
     "rules[0].param_gt: must map parameter names to numbers"),
    ({"rules": [RULE | {"param_gt": {"amount": True}}]},
     "rules[0].param_gt: must map parameter names to numbers"),
    ({"rules": [RULE | {"param_gt": [100]}]},
     "rules[0].param_gt: must map parameter names to numbers"),
    ({"rules": [RULE | {"clas": "x"}]}, "rules[0].clas: unknown member"),
    ({"prohibited_pairs": "a,b"}, "prohibited_pairs: must be an array of arrays of class names"),
    ({"prohibited_pairs": [["a", 1]]},
     "prohibited_pairs: must be an array of arrays of class names"),
    ({"prohibited_pairs": [["a", "b", "c"]]},
     "prohibited_pairs: each entry must name exactly 2 classes"),
    ({"prohibited_pairs": [["a"]]}, "prohibited_pairs: each entry must name exactly 2 classes"),
    ({"prohibited_sequences": [["a"], "b"]},
     "prohibited_sequences: must be an array of arrays of class names"),
    # Regression: an empty or one-class sequence used to load and then raise IndexError
    # on every decision (found by mutation-testing follow-up, 2026-10-07).
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
