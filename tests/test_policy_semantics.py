"""Exact semantics of the APC policy engine, one behaviour per test, at its boundary.

The scenario suites (`test_policy.py`, the adversarial harness) show the policy makes the
right call on realistic missions. These pin each rule of the engine on its own, at the
edge where an off-by-one or a flipped condition would change a decision, so a regression
cannot hide behind a scenario that happens to still pass.
"""
from __future__ import annotations

from typing import Any

import pytest

from aauth_supervision_server.policy import Act, Budget, Classification, Decision, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import HistoryEntry, Mission, Reach

ISS, SUB, AGENT, M = "https://ps.example", "sub-1", "agent-1", "m-1"
MAIL = "https://mail.example"


def pol(**kw: Any) -> Policy:
    kw.setdefault("severity", ["unclassified", "read", "write", "send", "exfil"])
    return Policy(PolicyConfig(**kw))


def act(**kw: Any) -> Act:
    base: dict[str, Any] = {"act": "auth_token", "iss": ISS, "sub": SUB, "agent": AGENT,
                            "mission_s256": M, "resource": MAIL,
                            "parameters_provenance": "resource"}
    base.update(kw)
    return Act(**base)


def h(cls: str, uncertain: bool = False, amount: int = 0) -> HistoryEntry:
    return HistoryEntry(cls, MAIL, "resource", amount=amount,
                        detail="uncertain: x" if uncertain else "rule")


def mission(**blob: Any) -> Mission:
    return Mission(M, AGENT, SUB, ISS, blob={"approved_resources": [MAIL], **blob})


# ----------------------------------------------------------------- defaults


def test_act_and_decision_defaults() -> None:
    a = Act("auth_token", ISS, SUB, AGENT)
    assert (a.mission_s256, a.resource, a.scope, a.tool, a.justification) == ("",) * 5
    assert a.operations == [] and a.parameters is None and a.result is None
    assert a.parameters_provenance == ""
    d = Decision("allow")
    assert (d.reason, d.summary, d.recommendation, d.clarification, d.kind) == ("",) * 5
    assert d.apply_options == [] and d.narrow == {} and d.composition == [] and d.trace == []
    assert d.entry is None
    c = Classification("read", "configured", False)
    assert c.amount is None and c.detail == ""


def test_no_rule_matched_is_the_default_class_and_certain() -> None:
    c = pol(default_class="read").classify(act(resource="https://unknown.example"))
    assert (c.cls, c.provenance, c.uncertain, c.amount) == ("read", "configured", False, None)
    assert c.detail == "no rule matched"


# ----------------------------------------------------------- static matching


def test_operation_condition_must_match_an_operation() -> None:
    p = pol(rules=[Rule(cls="send", operation="send_*")])
    assert p.classify(act(operations=["send_email"])).cls == "send"
    assert p.classify(act(operations=["read_inbox"])).cls == "unclassified"


def test_scope_condition_must_match_a_scope_token() -> None:
    p = pol(rules=[Rule(cls="send", scope="mail.send")])
    assert p.classify(act(scope="mail.read mail.send")).cls == "send"
    assert p.classify(act(scope="mail.read")).cls == "unclassified"


def test_tool_condition_must_match_the_tool() -> None:
    p = pol(rules=[Rule(cls="write", resource="*", tool="Bash")])
    assert p.classify(act(act="permission", resource="", tool="Bash")).cls == "write"
    assert p.classify(act(act="permission", resource="", tool="Read")).cls == "unclassified"


# -------------------------------------------------------------- data rules


def test_result_contains_any_matches_listed_values_and_keys_only() -> None:
    p = pol(rules=[Rule(cls="exfil", result_contains_any=["pii"]), Rule(cls="read")])
    assert p.classify(act(result={"contains": ["pii", "x"]})).cls == "exfil"
    assert p.classify(act(result={"pii": True})).cls == "exfil"  # a key names a value too
    assert p.classify(act(result={"contains": ["public"]})).cls == "read"
    assert p.classify(act(result={"public": True})).cls == "read"


def test_param_gt_is_strictly_greater() -> None:
    p = pol(rules=[Rule(cls="send", param_gt={"amount": 100}), Rule(cls="read")])
    assert p.classify(act(parameters={"amount": 101})).cls == "send"
    assert p.classify(act(parameters={"amount": 100})).cls == "read"
    assert p.classify(act(parameters={"amount": 99.5})).cls == "read"


@pytest.mark.parametrize("value", [float("nan"), "NaN", "nan", float("-inf"), "-Infinity", float("inf")])
def test_param_gt_on_a_non_finite_value_is_not_visible(value: Any) -> None:
    # NaN compares false with any limit; read as "not over the limit" it would escape
    # `if_unknown`. A non-finite value is treated like an unreadable one.
    p = pol(rules=[Rule(cls="send", param_gt={"amount": 100}), Rule(cls="read", if_unknown="send")])
    c = p.classify(act(parameters={"amount": value}))
    assert (c.cls, c.uncertain) == ("send", True)


def test_param_gt_and_domain_conditions_must_all_hold() -> None:
    p = pol(rules=[Rule(cls="exfil", param_gt={"n": 1}, param_domain_not_in={"to": ["corp"]}),
                   Rule(cls="read")])
    assert p.classify(act(parameters={"n": 5, "to": "a@evil"})).cls == "exfil"
    assert p.classify(act(parameters={"n": 0, "to": "a@evil"})).cls == "read"
    assert p.classify(act(parameters={"n": 5, "to": "a@corp"})).cls == "read"


def test_a_non_string_recipient_is_not_visible() -> None:
    p = pol(rules=[Rule(cls="exfil", param_domain_not_in={"to": ["corp.example"]}),
                   Rule(cls="read", if_unknown="send")])
    c = p.classify(act(parameters={"to": 12345}))
    assert c.cls == "send" and c.uncertain  # unknown, so the conservative fallback


def test_domain_uses_the_last_at_and_ignores_display_brackets() -> None:
    p = pol(rules=[Rule(cls="exfil", param_domain_not_in={"to": ["corp.example"]}),
                   Rule(cls="read")])
    assert p.classify(act(parameters={"to": "Alice <a@Corp.Example>"})).cls == "read"
    assert p.classify(act(parameters={"to": "a@corp.example@evil.example"})).cls == "exfil"


# ---------------------------------------------------------------- provenance


def test_result_evidence_is_resource_provenance_even_for_agent_parameters() -> None:
    p = pol(rules=[Rule(cls="exfil", result_contains_any=["pii"])])
    c = p.classify(act(parameters_provenance="agent", result={"contains": ["pii"]}))
    assert (c.cls, c.provenance) == ("exfil", "resource")


def test_parameter_evidence_from_the_agent_is_agent_provenance() -> None:
    p = pol(rules=[Rule(cls="send", param_gt={"amount": 1})])
    c = p.classify(act(parameters_provenance="agent", parameters={"amount": 5},
                       result={"other": 1}))
    assert (c.cls, c.provenance) == ("send", "agent")


def test_agent_data_cannot_lower_a_class() -> None:
    # Without the agent's data the act is `send`; the agent's data would make it `read`.
    p = pol(rules=[Rule(cls="read", param_domain_not_in={"to": ["evil"]}),
                   Rule(cls="send", if_unknown="send")])
    c = p.classify(act(act="permission", resource="", tool="Mail",
                       parameters_provenance="agent", parameters={"to": "a@corp"}))
    assert (c.cls, c.provenance, c.uncertain) == ("send", "agent", True)


def test_agent_data_that_does_not_change_the_class_keeps_its_provenance() -> None:
    p = pol(rules=[Rule(cls="send", param_gt={"amount": 1}), Rule(cls="send")])
    c = p.classify(act(act="permission", resource="", tool="Pay",
                       parameters_provenance="agent", parameters={"amount": 5}))
    assert (c.cls, c.uncertain) == ("send", False)


def test_agent_parameters_alone_trigger_the_no_lowering_check() -> None:
    p = pol(rules=[Rule(cls="read", param_domain_not_in={"to": ["evil"]}),
                   Rule(cls="send", if_unknown="send")])
    c = p.classify(act(act="permission", resource="", tool="Mail",
                       parameters_provenance="agent", parameters={"to": "a@corp"}, result=None))
    assert c.cls == "send"


def test_equal_severity_fallback_does_not_mark_an_agent_act_uncertain() -> None:
    p = pol(rules=[Rule(cls="send", if_unknown="send")])
    c = p.classify(act(act="permission", resource="", tool="Mail",
                       parameters_provenance="agent", parameters={"x": 1}))
    assert (c.cls, c.provenance, c.uncertain) == ("send", "configured", False)


def test_resource_proposal_with_no_unknowns_uses_the_rule_not_the_fallback() -> None:
    p = pol(rules=[Rule(cls="read", if_unknown="exfil")])
    c = p.classify(act(parameters_provenance="resource"))
    assert (c.cls, c.uncertain) == ("read", False)


# ------------------------------------------------------------------- amounts


@pytest.mark.parametrize(("value", "amount"), [
    (0, 0), (7, 7), (7.0, 7), ("7", 7), (7.5, None), (-1, None), ("-1", None), (True, None),
    ("７", None), (None, None)])
def test_amount_is_a_visible_non_negative_whole_number(value: Any, amount: int | None) -> None:
    r = Rule(cls="send", amount_param="amount")
    assert Policy._amount(r, act(parameters={"amount": value})) == amount


def test_missing_amount_is_recorded_as_zero_spent() -> None:
    d = pol(rules=[Rule(cls="read")]).decide(act(), mission(), [], [], now=0)
    assert d.decision == "allow" and d.entry is not None and d.entry.amount == 0


# ------------------------------------------------------------------- budgets


def test_count_budget_allows_up_to_the_ceiling() -> None:
    p = pol(rules=[Rule(cls="send")], budgets={"send": Budget(max_count=2)})
    assert p.decide(act(), mission(), [h("send")], [], now=0).decision == "allow"
    assert p.decide(act(), mission(), [h("send"), h("send")], [], now=0).decision == "deny"


def test_amount_budget_allows_exactly_the_ceiling() -> None:
    p = pol(rules=[Rule(cls="send", amount_param="amount")],
            budgets={"send": Budget(max_amount=100)})
    a = act(parameters={"amount": 40})
    assert p.decide(a, mission(), [h("send", amount=60)], [], now=0).decision == "allow"
    assert p.decide(a, mission(), [h("send", amount=61)], [], now=0).decision == "deny"


# --------------------------------------------------------------- composition


def comp(p: Policy, cls: str, history: list[HistoryEntry],
         uncertain: bool = False) -> tuple[list[str], bool]:
    return p._composition(cls, uncertain, MAIL, history)


def test_a_pair_is_unordered() -> None:
    p = pol(prohibited_pairs=[("read", "send")])
    assert comp(p, "send", [h("read")]) == (["read", "send"], False)
    assert comp(p, "read", [h("send")]) == (["send", "read"], False)
    assert comp(p, "read", [h("write")]) == ([], False)


def test_pair_certainty_comes_from_both_the_act_and_the_history() -> None:
    p = pol(prohibited_pairs=[("read", "send")])
    assert comp(p, "send", [h("read")], uncertain=True)[1] is True
    assert comp(p, "send", [h("read", uncertain=True)])[1] is True
    assert comp(p, "send", [h("read", uncertain=True), h("read")])[1] is False


def test_sequence_needs_its_prefix_in_order() -> None:
    p = pol(prohibited_sequences=[("read", "write", "send")])
    assert comp(p, "send", [h("read"), h("write")]) == (["read", "write", "send"], False)
    assert comp(p, "send", [h("write"), h("read")]) == ([], False)
    assert comp(p, "send", [h("write")]) == ([], False)
    assert comp(p, "send", [h("read")]) == ([], False)
    assert comp(p, "send", [h("exfil"), h("unclassified")]) == ([], False)


def test_sequence_tolerates_repeats_and_noise() -> None:
    p = pol(prohibited_sequences=[("read", "send")])
    assert comp(p, "send", [h("read"), h("send"), h("write")]) == (["read", "send"], False)
    assert comp(p, "send", [h("read"), h("read")]) == (["read", "send"], False)


def test_only_sequences_ending_in_the_act_are_checked_and_all_are_tried() -> None:
    p = pol(prohibited_sequences=[("read", "write"), ("read", "send")])
    assert comp(p, "send", [h("read")]) == (["read", "send"], False)


def test_sequence_completed_only_through_uncertain_history_is_uncertain() -> None:
    p = pol(prohibited_sequences=[("read", "send")])
    assert comp(p, "send", [h("read", uncertain=True)]) == (["read", "send"], True)
    assert comp(p, "send", [h("read")], uncertain=True) == (["read", "send"], True)


def test_an_uncertain_entry_never_masks_a_later_certain_one() -> None:
    p = pol(prohibited_sequences=[("read", "send")])
    history = [h("write", uncertain=True), h("read")]
    assert comp(p, "send", history) == (["read", "send"], False)


def test_certain_composition_is_denied_with_the_certain_message() -> None:
    p = pol(rules=[Rule(cls="send")], prohibited_pairs=[("read", "send")])
    d = p.decide(act(), mission(), [h("read")], [], now=0)
    assert d.decision == "deny"
    assert d.reason == "This act would complete a prohibited composition: read then send."


def test_uncertain_composition_is_asked() -> None:
    p = pol(rules=[Rule(cls="send")], prohibited_pairs=[("read", "send")])
    d = p.decide(act(), mission(), [h("read", uncertain=True)], [], now=0)
    assert d.decision == "ask" and "cannot rule it out" in d.summary


# --------------------------------------------------------------------- reach


def reach(value: str = "mission", agent: str = AGENT, kind: str = f"send|{MAIL}",
          **kw: Any) -> Reach:
    return Reach(value, ISS, SUB, agent, kind, mission_s256=M, **kw)


def test_reach_is_bound_to_the_same_agent_and_kind() -> None:
    p = pol()
    assert p._reach([reach()], act(), f"send|{MAIL}", []) is not None
    assert p._reach([reach(agent="other")], act(), f"send|{MAIL}", []) is None
    assert p._reach([reach()], act(), f"read|{MAIL}", []) is None
    assert p._reach([reach("once")], act(), f"send|{MAIL}", []) is None


def test_reach_skips_every_non_matching_entry_to_find_a_match() -> None:
    p = pol()
    good = reach()
    for miss in (reach(agent="other"), reach("once"),
                 Reach("mission", ISS, SUB, AGENT, f"send|{MAIL}", mission_s256="m-other")):
        assert p._reach([miss, good], act(), f"send|{MAIL}", []) is good
    other_mission = act(mission_s256="m-2")
    always = reach("always")
    assert p._reach([reach("mission"), always], other_mission, f"send|{MAIL}", []) is always
    pair = reach(composition_override=["read", "send"])
    assert p._reach([reach(), pair], act(), f"send|{MAIL}", ["read", "send"]) is pair


def test_reach_mission_scope_and_composition_override() -> None:
    p = pol()
    other = act(mission_s256="m-2")
    assert p._reach([reach("mission")], other, f"send|{MAIL}", []) is None
    assert p._reach([reach("always")], other, f"send|{MAIL}", []) is not None
    assert p._reach([reach()], act(), f"send|{MAIL}", ["read", "send"]) is None
    ok = reach(composition_override=["read", "send"])
    assert p._reach([ok], act(), f"send|{MAIL}", ["read", "send"]) is ok


def test_allow_trace_records_the_reach_that_applied() -> None:
    p = pol(rules=[Rule(cls="send")], high_impact={"send"})
    d = p.decide(act(parameters_provenance="agent"), mission(), [], [reach()], now=0)
    assert d.decision == "allow" and "reach mission" in d.trace


# ------------------------------------------------------------ mission checks


def test_mission_expiry_is_inclusive() -> None:
    p = pol(rules=[Rule(cls="read")])
    m = mission(expires_at="1970-01-01T00:01:40Z")  # epoch 100
    assert p.decide(act(), m, [], [], now=99).decision == "allow"
    assert p.decide(act(), m, [], [], now=100).decision == "deny"


def test_allow_unlisted_resources_skips_the_intent_check() -> None:
    other = act(resource="https://other.example")
    assert pol(rules=[Rule(cls="read")]).decide(other, mission(), [], [], now=0).decision == "ask"
    p = pol(rules=[Rule(cls="read")], allow_unlisted_resources=True)
    assert p.decide(other, mission(), [], [], now=0).decision == "allow"


def test_ask_offers_reach_on_the_resource() -> None:
    d = pol(rules=[Rule(cls="read")]).decide(act(resource="https://other.example"), mission(),
                                              [], [], now=0)
    labels = [o["label"] for o in d.apply_options]
    assert "Acts like this on https://other.example for this mission" in labels


def test_clarify_is_the_default_for_high_impact_without_justification() -> None:
    p = pol(rules=[Rule(cls="send")], high_impact={"send"}, clarify_missing_justification=True)
    a = act(parameters_provenance="agent")
    assert p.decide(a, mission(), [], [], now=0).decision == "clarify"
    assert p.decide(a, mission(), [], [], now=0, clarify=False).decision == "ask"


def test_person_token_reach_on_identity_kind() -> None:
    p = pol()
    a = act(act="person_token", resource="https://other.example")
    d = p.decide(a, mission(), [], [], now=0)
    assert d.decision == "ask" and d.kind == "identity|https://other.example"
    r = reach(kind="identity|https://other.example")
    assert p.decide(a, mission(), [], [r], now=0).decision == "allow"


# ----------------------------------------------------------------- proposals


def test_proposal_arrays_are_both_required_to_be_arrays() -> None:
    p = pol()
    with pytest.raises(ValueError):
        p.decide_proposal({"resources": "x", "tools": []}, now=0)
    with pytest.raises(ValueError):
        p.decide_proposal({"resources": [], "tools": {}}, now=0)


def test_proposal_names_the_tools_it_asks_about() -> None:
    p = pol(ask_tools=["Bash"])
    d = p.decide_proposal({"resources": [], "tools": [{"name": "Bash"}, {"name": "Read"}]},
                          now=0)
    assert d.decision == "ask" and "tools that need your approval: Bash." in d.summary



# ------------------------------------------------------------ pinned by mutation testing


def test_a_result_decided_on_resource_evidence_takes_no_agent_fallback() -> None:
    """In `_scan`, an earlier result rule that was decidable (and false) means the act
    was decided on resource evidence, so the agent-provenance fallback does not apply."""
    p = pol(rules=[Rule(resource="*", tool="Export", result_contains_any=["pii"], cls="send"),
                   Rule(resource="*", tool="Export", cls="read", if_unknown="write")])
    a = act(act="permission", tool="Export", parameters_provenance="agent",
            result={"contains": ["public"]})
    c = p._scan(a)
    assert (c.cls, c.provenance, c.uncertain) == ("read", "resource", False)


@pytest.mark.parametrize("addr,dom", [
    ("a@corp.example", "corp.example"), ("A <x@Corp.Example>", "corp.example"),
    ("a@b@evil.example", "evil.example"), ("corp.example", "corp.example"),
])
def test_the_domain_of_an_address_is_after_its_last_at(addr: str, dom: str) -> None:
    from aauth_supervision_server.policy import _domain

    assert _domain(addr) == dom
