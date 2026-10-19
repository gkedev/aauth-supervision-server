"""What budgets tell the agent and the person.

A deny `reason` goes to the agent (Supervision L265), and AAuth Budgets keeps the person's
ceiling from it: the ceiling "may not be shared with the agent" (Budgets L218), and "A
ceiling the agent can read is a ceiling the agent plans against" (L1281). So a deny says
which budget stopped the act, never its figures; those stay in the trace. An ask goes to
the person, who decides on the amount (Budgets L538), so it gives the figures the
supervisor has: what is offered and what is left. A grant of 0 spends nothing (Budgets
L344, L913), so it fits any ceiling. Where the supervisor cannot know an amount, the person
is told the act "may" pass a limit, never that it "would".
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, policy_cfg

from aauth_supervision_server.policy import Act, Policy, ResourceBudget
from aauth_supervision_server.store import Alias, HistoryEntry

INF, PAY = "https://inference.example", "https://pay.example"
CEILING = {INF: {"unit": "USD", "decimals": 2, "max_amount": 2500}}
RB = ResourceBudget(unit="USD", decimals=2, max_amount=2500)


def _inference(mission: str = "m", **kw: Any) -> Act:
    return Act("auth_token", "https://ps.example", SUB, AGENT, mission, resource=INF, **kw)


def _committed(amount: int, unit: str = "USD/2") -> HistoryEntry:
    entry = HistoryEntry("read", INF, "configured", detail="rule read")
    entry.unit, entry.allocated = unit, amount
    return entry


def _blind() -> HistoryEntry:
    return HistoryEntry("read", INF, "replay", detail="replayed")  # no budget


def _paid(amount: int, n: int = 1) -> list[HistoryEntry]:
    return [HistoryEntry("payment", PAY, "resource", amount=amount, amount_known=True,
                         detail="rule payment on resource-asserted data") for _ in range(n)]


def _pay(**kw: Any) -> Act:
    return Act("auth_token", "https://ps.example", SUB, AGENT, "", resource=PAY, **kw)


def test_a_deny_never_tells_the_agent_the_ceiling_or_what_is_committed() -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    for offer in ({}, {"budget_amount": 100, "budget_unit": "EUR/2"},
                  {"budget_amount": 100, "budget_unit": "USD/2"}):
        d = p._resource_budget(_inference(**offer), RB, [_committed(2500)], [], [])
        assert d == ("deny", f"Budget exhausted at {INF}.",
                     "resource budget exhausted: 2500 of 2500 USD/2"), offer
    pays = Policy(policy_cfg(high_impact=[]))
    d = pays.decide(_pay(), None, _paid(250000, 2), [], now=0)
    assert d.decision == "deny" and d.reason == (
        "Budget exhausted: the `payment` budget outside missions is spent, and this act's "
        "amount is not visible to the supervisor.")
    assert "500000" in " ".join(d.trace)
    d = pays.decide(_pay(parameters={"amount": 300000}, parameters_provenance="resource"),
                    None, _paid(250000), [], now=0)
    assert d.decision == "deny" and d.reason == (
        "Budget exceeded: this act's amount would take the `payment` budget outside missions "
        "past its limit.")
    one = Policy(policy_cfg(high_impact=[], budgets={"payment": {"max_count": 1}}))
    d = one.decide(_pay(parameters={"amount": 1}, parameters_provenance="resource"), None,
                   _paid(1), [], now=0)
    assert d.decision == "deny" and d.reason == (
        "Budget exhausted: no more `payment` acts outside missions.")


def test_a_grant_of_nothing_fits_any_ceiling() -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    zero = _inference(budget_amount=0, budget_unit="USD/2")
    assert p._resource_budget(zero, RB, [_committed(2500)], [], []) is None
    assert p._resource_budget(zero, RB, [_committed(3000)], [], []) is None
    assert p._resource_budget(zero, RB, [_blind(), _committed(2500)], [], []) is None
    assert p._resource_budget(zero, RB, [_committed(2400)], [], [_committed(100)]) is None
    pays = Policy(policy_cfg(high_impact=[]))
    d = pays.decide(_pay(parameters={"amount": 0}, parameters_provenance="resource"), None,
                    _paid(600000), [], now=0)
    assert d.decision == "allow"


def test_a_spent_ceiling_refuses_whatever_earlier_act_it_cannot_account_for() -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    act = _inference(budget_amount=100, budget_unit="USD/2")
    for earlier in (_blind(), _committed(100, "EUR/2")):
        spent = p._resource_budget(act, RB, [earlier, _committed(2500)], [], [])
        assert spent is not None and spent[0] == "deny"
        room = p._resource_budget(act, RB, [earlier, _committed(2000)], [], [])
        assert room is not None and room[2] == "resource budget: unbounded history"


def test_the_waiting_text_says_may_where_the_earlier_amount_is_not_known() -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    act = _inference(budget_amount=100, budget_unit="USD/2")
    known = p._resource_budget(act, RB, [_committed(2000)], [], [_committed(1000)])
    assert known is not None and "it and this act together would take the 25.00 USD " \
        "mission ceiling" in known[1]
    unknown = p._resource_budget(act, RB, [_committed(2000)], [], [_blind()])
    assert unknown is not None and "it and this act together may take" in unknown[1]
    pays = Policy(policy_cfg(high_impact=[]))
    waiting = HistoryEntry("payment", PAY, "configured", amount_known=False,
                           detail="uncertain: x", open="own", borrowed=True)
    d = pays.decide(_pay(parameters={"amount": 1000}, parameters_provenance="resource"), None,
                    [waiting], [], now=0)
    assert d.decision == "ask" and "together may take the `payment` budget" in d.summary


def test_an_ask_gives_the_person_what_is_offered_and_what_is_left() -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    none = p._resource_budget(_inference(), RB, [_committed(2000)], [], [])
    assert none is not None and none[1] == (
        f"{INF} is metered against the 25.00 USD mission ceiling, of which 5.00 USD is left, "
        f"but it offered no budget for this act, so the spend cannot be bounded.")
    other = p._resource_budget(_inference(budget_amount=150, budget_unit="EUR/2"), RB,
                               [_committed(2000)], [], [])
    assert other is not None and other[1] == (
        f"{INF} offers 1.50 EUR, but its ceiling is set in USD with 2 decimal places: 5.00 "
        f"USD of the 25.00 USD mission ceiling is left.")
    blind = p._resource_budget(_inference(budget_amount=100, budget_unit="USD/2"), RB,
                               [_blind(), _committed(2000)], [], [])
    assert blind is not None and blind[1] == (
        f"An earlier act at {INF} has no budget the supervisor can account for, so the "
        f"mission's spend there is unknown. This act offers 1.00 USD, and 20.00 USD of the "
        f"25.00 USD mission ceiling is accounted for.")
    pays = Policy(policy_cfg(high_impact=[]))
    d = pays.decide(_pay(), None, _paid(250000), [], now=0)
    assert d.decision == "ask" and (
        "The `payment` amount is not visible to the supervisor, so the `payment` budget of "
        "500000 cannot be checked; 250000 of it is counted outside missions.") in d.summary


def test_an_act_that_may_be_of_a_spent_budget_s_class_is_told_it_is_spent() -> None:
    # Only assumed of the class, so not refused; but the person is told the budget is
    # spent, and that the act may not be of it.
    pays = Policy(policy_cfg(high_impact=[], budgets={"payment": {"max_amount": 100,
                                                                   "max_count": 1}}))
    act = Act("auth_token", "https://ps.example", SUB, AGENT, "", resource="https://x.example")
    from aauth_supervision_server.policy import Classification
    pays.classify = lambda a: Classification(  # type: ignore[method-assign]
        "write", "configured", True, None, "assumed",
        [Alias("payment", assumed=True)])
    d = pays.decide(act, None, _paid(100), [], now=0)
    assert d.decision == "ask"
    assert "This act may be a `payment` act, of an amount the supervisor cannot see; the " \
        "`payment` budget of 100 is already spent (100 counted outside missions)." in d.summary
    assert "at most 1 `payment` act outside missions" in d.summary


def test_an_amount_ask_says_when_an_earlier_amount_is_not_known_either() -> None:
    pays = Policy(policy_cfg(high_impact=[]))
    unseen = HistoryEntry("payment", PAY, "configured", amount_known=False, detail="rule")
    d = pays.decide(_pay(), None, [unseen], [], now=0)
    assert d.decision == "ask" and d.summary == (
        "The `payment` amount is not visible to the supervisor, so the `payment` budget of "
        "500000 cannot be checked; the amount of 1 earlier `payment` act is not known "
        "either.")


def test_an_offer_at_a_scale_past_any_ceiling_s_is_told_as_the_resource_gave_it() -> None:
    # A resource token may name any scale (its `decimals` is only bounded as an integer):
    # past the 18 places a ceiling may have, the offer is told as given, quoted.
    p = Policy(policy_cfg(resource_budgets=CEILING))
    d = p._resource_budget(_inference(budget_amount=100, budget_unit="USD/30"), RB,
                           [_committed(2000)], [], [])
    assert d is not None and d[1] == (
        f"{INF} offers 100 in `USD/30`, but its ceiling is set in USD with 2 decimal "
        f"places: 5.00 USD of the 25.00 USD mission ceiling is left.")


def test_a_person_token_s_other_classes_are_told_as_a_person_token_not_as_assumed() -> None:
    from aauth_supervision_server.policy import PERSON_TOKEN, Classification, _doubts
    token = Classification("read_sensitive", "configured", True, None, PERSON_TOKEN,
                           [Alias("write", assumed=True)])
    assert _doubts(["write", "send_internal"], token, []) == [
        "This act is a person token, on which the resource may serve a request."]


def test_a_metered_ask_counts_the_allocations_not_reported_yet() -> None:
    # 10.00 USD committed and 10.00 USD allowed but not reported issued: what is left is
    # 15.00 USD only if that allocation never goes ahead, and the person is told so.
    p = Policy(policy_cfg(resource_budgets=CEILING))
    held = " Allocations allowed or still being decided, not reported yet, may take 10.00 USD more."
    for kw in ({}, {"budget_amount": 2000, "budget_unit": "USD/2"},
               {"budget_amount": 100, "budget_unit": "EUR/2"}):
        d = p._resource_budget(_inference(**kw), RB, [_committed(1000)], [], [_committed(1000)])
        assert d is not None and d[0] == "ask" and d[1].endswith(held), (kw, d)
    blind = p._resource_budget(_inference(budget_amount=100, budget_unit="USD/2"), RB,
                               [_blind(), _committed(1000)], [], [_committed(100, "EUR/2")])
    assert blind is not None and blind[1].endswith(
        " Allocations allowed or still being decided, not reported yet, may take an amount "
        "in another unit or scale.")
    waiting = p._resource_budget(_inference(budget_amount=1000, budget_unit="USD/2"), RB,
                                 [_committed(1000)], [], [_committed(1000)])
    assert waiting is not None and waiting[1].endswith(
        "past its limit. This act offers 10.00 USD, and 15.00 USD of the 25.00 USD mission "
        "ceiling is left." + held)


def test_a_class_amount_ask_counts_the_acts_not_reported_yet() -> None:
    pays = Policy(policy_cfg(high_impact=[]))
    open_pay = HistoryEntry("payment", PAY, "resource", amount=300000, detail="rule",
                            open="own", borrowed=True)
    d = pays.decide(_pay(), None, [open_pay], [], now=0)
    assert d.decision == "ask" and d.summary.endswith(
        " Earlier `payment` acts not reported yet may count 300000 more.")
    d = pays.decide(_pay(parameters={"amount": 250000}, parameters_provenance="resource"), None,
                    [open_pay], [], now=0)
    assert d.decision == "ask" and d.summary.endswith(
        "past its limit. This act's amount is 250000, and 0 of the budget is counted outside "
        "missions. Earlier `payment` acts not reported yet may count 300000 more.")


def test_would_only_where_the_acts_surely_of_the_class_pass_the_limit() -> None:
    # An earlier act only assumed of the class, and one open act: without the assumed one,
    # the open act and this one stay within the limit, so it "may" pass it.
    count = Policy(policy_cfg(high_impact=[], budgets={"payment": {"max_count": 2}}))
    maybe = HistoryEntry("write", PAY, "configured", detail="uncertain: x",
                         blind=[Alias("payment", assumed=True)])
    open_pay = HistoryEntry("payment", PAY, "resource", amount=1, detail="rule", open="own",
                            borrowed=True)
    act = _pay(parameters={"amount": 1}, parameters_provenance="resource")
    d = count.decide(act, None, [maybe, open_pay], [], now=0)
    assert d.decision == "ask" and "together may take" in d.summary
    sure = HistoryEntry("payment", PAY, "resource", amount=1, detail="rule")
    d = count.decide(act, None, [sure, open_pay], [], now=0)
    assert d.decision == "ask" and "together would take" in d.summary
    assert "1 `payment` act is counted outside missions." in d.summary
