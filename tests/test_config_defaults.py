"""Configuration defaults are part of the public contract, and they are the safe ones.

An operator who omits a member gets the conservative behaviour: no auto-connect, no
open registration, no unlisted resources, the non-spec R3 extension off. A change to
any default is a behaviour change and must show up here.
"""
from __future__ import annotations

from aauth_supervision_server.policy import Act, Budget, Policy, PolicyConfig, Rule
from aauth_supervision_server.service import ServerConfig, TrustedPS


def test_trusted_ps_defaults() -> None:
    t = TrustedPS()
    assert t.auto_connect is False  # a connect needs the person, unless configured
    assert t.tenants == []
    assert TrustedPS().tenants is not t.tenants  # no shared mutable default


def test_server_config_defaults() -> None:
    c = ServerConfig(issuer="https://ss.example")
    assert c.name == "AAuth APC Supervisor"
    assert c.trusted_ps == {}
    assert c.open_registration is False
    assert c.signature_window == 60
    assert c.rate_limit_per_minute == 0  # 0: no limit
    assert c.clarification_rounds == 3
    assert c.clarification_timeout == 120
    assert c.admin_token == ""
    assert c.documentation_uri == ""
    assert ServerConfig.from_dict({"issuer": "https://ss.example"}) == c


def test_policy_config_defaults() -> None:
    p = PolicyConfig()
    assert p.severity == [] and p.high_impact == set() and p.rules == []
    assert p.prohibited_pairs == [] and p.prohibited_sequences == [] and p.budgets == {}
    assert p.deny_resources == [] and p.ask_tools == []
    assert p.allowed_tools == ["*"]
    assert p.allow_unlisted_resources is False
    assert p.clarify_missing_justification is False
    assert p.max_mission_seconds is None
    assert p.default_class == "unclassified"
    assert p.ask_on_mission_update is False
    assert p.composition_on_certain == "deny"
    assert p.r3_member is None  # non-spec extension off
    assert PolicyConfig.from_dict({}) == p


def test_rule_and_budget_defaults() -> None:
    r = Rule(cls="read")
    assert r.resource == "*"
    assert (r.operation, r.scope, r.tool, r.amount_param, r.if_unknown) == (None,) * 5
    assert (r.result_contains_any, r.param_domain_not_in, r.param_gt) == (None,) * 3
    assert r.needs_data is False
    assert Budget() == Budget(max_count=None, max_amount=None)


def test_a_rule_with_only_a_class_matches_every_act() -> None:
    # The default resource is a wildcard and the other conditions are absent, so a
    # bare rule is a catch-all.
    pol = Policy(PolicyConfig(severity=["low", "catch"], rules=[Rule(cls="catch")]))
    for res in ("https://mail.example", "https://hr.example/x"):
        act = Act("auth_token", "https://ps.example", "sub", "agent", "m", resource=res,
                  operations=["anything"], scope="s1 s2", tool="")
        assert pol.classify(act).cls == "catch"
