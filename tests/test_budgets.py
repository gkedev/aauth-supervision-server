"""AAuth Budgets: the SS reads the resource's `budget` offer and `budget_consumed` record.

A resource that meters puts its offer and, on a challenge, what it metered against the
presented token into the resource token, signed (Budgets, Resource Token Extensions). The
PS forwards that token in every `auth_token` supervision request, so under Supervision -00
as written the SS can hold a per-mission ceiling at the resource and account for it the
way Budgets has an issuer do: an allocation counts as fully consumed until a consumption
record for its token arrives, and a later record supersedes an earlier one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env, policy_cfg

from aauth_supervision_server.policy import Act, Policy, PolicyConfig, ResourceBudget, _money
from aauth_supervision_server.store import EXP_SKEW, HistoryEntry, Store

INF = "https://inference.example"
CEILING = {INF: {"unit": "USD", "decimals": 2, "max_amount": 2500}}  # 25.00 USD per mission


def usd(cents: int) -> dict[str, Any]:
    return {"amount": cents, "unit": "USD", "decimals": 2}


def env(**over: Any) -> tuple[Any, Any, str]:
    ss, ps, clock = make_env(resource_budgets=over.pop("ceiling", CEILING), **over)
    s256 = connected((ss, ps, clock), resources=("https://hr.example", INF))
    return ss, ps, s256


def request(ss: Any, ps: Any, s256: str, budget: Any = None, consumed: Any = None,
            resource: str = INF) -> tuple[str, dict[str, Any]]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource, scope="inference.completions",
                                      budget=budget, consumed=consumed)
    assert r.status == 200, r.body
    return sdi, r.json()


def issue(ss: Any, ps: Any, s256: str, sdi: str, jti: str) -> None:
    assert ps.issued(ss, SUB, AGENT, s256, sdi, INF, "inference.completions", jti=jti).status == 201


def history(ss: Any, ps: Any, s256: str) -> list[HistoryEntry]:
    return ss.store.history_for(ps.issuer, SUB, AGENT, s256)


# ----------------------------------------------------------- the ledger


@pytest.mark.req("BUD-005")
def test_an_offer_within_the_ceiling_is_allowed_and_recorded_as_an_allocation() -> None:
    ss, ps, s256 = env()
    sdi, d = request(ss, ps, s256, usd(1000))
    assert d["decision"] == "allow"
    issue(ss, ps, s256, sdi, "at-1")
    [h] = [h for h in history(ss, ps, s256) if h.resource == INF]
    assert (h.unit, h.allocated, h.jti, h.consumed) == ("USD/2", 1000, "at-1", None)


@pytest.mark.req("BUD-010")
def test_an_unreported_allocation_counts_as_fully_consumed() -> None:
    # Budgets, Unreported Allocations: "the issuer MUST account for the allocation as fully
    # consumed" until a figure arrives. 10 + 10 fit in 25; a third 10 does not.
    ss, ps, s256 = env()
    for jti in ("at-1", "at-2"):
        sdi, d = request(ss, ps, s256, usd(1000))
        assert d["decision"] == "allow"
        issue(ss, ps, s256, sdi, jti)
    _, d = request(ss, ps, s256, usd(1000))
    assert d["decision"] == "ask" and d["recommendation"] == "deny"
    assert d["summary"] == (f"{INF} offers 10.00 USD, but only 5.00 USD of the 25.00 USD mission "
                            f"ceiling is left. The supervisor has no way to grant a smaller amount.")


@pytest.mark.req("BUD-006")
def test_a_consumption_record_settles_nothing_for_a_live_token() -> None:
    """Budgets L841: "A consumption record settles nothing. ... the token stays valid, the
    agent may spend more on it"; L465: "the token may spend more before it expires". A
    record that at-1 spent 2.00 frees none of its 10.00: 10 + 10 + 10 = 30 > 25."""
    ss, ps, s256 = env()
    for jti in ("at-1", "at-2"):
        sdi, _ = request(ss, ps, s256, usd(1000))
        issue(ss, ps, s256, sdi, jti)
    _, d = request(ss, ps, s256, usd(1000), {"jti": "at-1", "consumed": 200})
    assert d["decision"] == "ask"
    assert {h.jti: h.consumed for h in history(ss, ps, s256) if h.jti} == {"at-1": 200, "at-2": None}


def test_a_consumption_record_above_the_allocation_raises_what_is_committed() -> None:
    """A record can only raise an allocation's figure (Budgets L841, L847): at-1 reported
    at 14.00 over its 10.00 leaves 14 + 10 = 24 committed, so a 2.00 offer fits in 25 and
    a 5.00 one does not."""
    ss, ps, s256 = env()
    for jti in ("at-1", "at-2"):
        sdi, _ = request(ss, ps, s256, usd(1000))
        issue(ss, ps, s256, sdi, jti)
    _, d = request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 1400})
    assert d["decision"] == "allow"
    _, d = request(ss, ps, s256, usd(500))
    assert d["decision"] == "ask"


def test_a_later_record_supersedes_an_earlier_one_and_a_retry_changes_nothing() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 300})
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 700})
    [h] = [h for h in history(ss, ps, s256) if h.jti == "at-1"]
    assert h.consumed == 700  # the latest figure, not a sum


def test_a_record_for_a_token_the_ss_does_not_know_is_ignored() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), {"jti": "at-unknown", "consumed": 0})
    assert [h.consumed for h in history(ss, ps, s256) if h.jti == "at-1"] == [None]


def test_a_record_for_another_resources_token_is_not_applied() -> None:
    ss, ps, s256 = env(ceiling=CEILING | {"https://hr.example": CEILING[INF]})
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 0}, resource="https://hr.example")
    assert [h.consumed for h in history(ss, ps, s256) if h.jti == "at-1"] == [None]


def test_a_spent_ceiling_is_a_deny() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(2500))
    issue(ss, ps, s256, sdi, "at-1")
    _, d = request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 2500})
    assert d == {"sdi": d["sdi"], "decision": "deny",
                 "reason": f"Budget exhausted at {INF}."}


def test_an_offer_that_exactly_fills_the_ceiling_is_allowed() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1500))
    issue(ss, ps, s256, sdi, "at-1")
    assert request(ss, ps, s256, usd(1000))[1]["decision"] == "allow"  # 15 + 10 == 25
    assert request(ss, ps, s256, usd(1001))[1]["decision"] == "ask"    # one cent over


def test_acts_at_other_resources_neither_count_nor_block() -> None:
    ss, ps, s256 = env()
    sdi, d = request(ss, ps, s256, None, resource="https://hr.example")
    assert d["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, "https://hr.example").status == 201
    assert request(ss, ps, s256, usd(2500))[1]["decision"] == "allow"


def test_a_person_token_for_a_metered_resource_is_not_a_spend() -> None:
    ss, ps, s256 = env()
    body = {"sdi": ps.nid("d"), "act": "person_token", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT), "resource": INF}
    assert ps.call(ss, "POST", "/decision", body).json()["decision"] == "allow"


def test_a_record_with_an_empty_jti_matches_nothing() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    history(ss, ps, s256).append(HistoryEntry("read", INF, "replay", unit="USD/2", allocated=1000))
    request(ss, ps, s256, usd(100), {"jti": "", "consumed": 0})
    assert [h.consumed for h in history(ss, ps, s256)] == [None, None]


def test_an_issuance_without_a_jti_leaves_the_allocation_counted_in_full() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(2000))
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": 1, "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "aud": INF, "exp": 2}
    assert ps.call(ss, "POST", "/event", body).status == 201
    [h] = [h for h in history(ss, ps, s256) if h.resource == INF]
    assert (h.jti, h.allocated) == ("", 2000)  # no record can ever name it
    assert request(ss, ps, s256, usd(1000))[1]["decision"] == "ask"


@pytest.mark.req("BUD-015")
def test_an_allowed_allocation_not_yet_issued_is_asked_about_never_denied() -> None:
    """Budgets, Concurrency: a PS "SHOULD size per-token budgets so that their sum stays
    within whatever standing ceiling it holds". Allowed but not yet reported issued, an
    allocation has granted nothing yet (it is never booked or denied against), but once
    issued it would count: behind two open 10.00 allocations a 5.00 one fills the 25.00
    ceiling exactly, and anything more is put to the person. An allow never issued stops
    counting once the `exp` cap it carries (an hour, Supervision L508, Protocol L1775)
    and the usable margin have passed."""
    ss, ps, s256 = env()
    for _ in range(2):
        assert request(ss, ps, s256, usd(1000))[1]["decision"] == "allow"
    assert request(ss, ps, s256, usd(500))[1]["decision"] == "allow"  # exactly 25 of 25
    _, d = request(ss, ps, s256, usd(1))
    assert d["decision"] == "ask" and d["recommendation"] == "deny"
    assert d["summary"] == ("3 earlier allocations are allowed or still being decided, and have not "
                            "been reported done yet. If they go ahead, they and this act together "
                            f"would take the 25.00 USD mission ceiling at {INF} past its limit. "
                            "This act offers 0.01 USD, and 25.00 USD of the 25.00 USD mission "
                            "ceiling is left. Allocations allowed or still being decided, not "
                            "reported yet, may take 25.00 USD more.")
    assert not [h for h in history(ss, ps, s256) if h.resource == INF]  # nothing booked
    ss.clock.t += Store.OPEN_ISSUANCE + EXP_SKEW
    assert request(ss, ps, s256, usd(1000))[1]["decision"] == "allow"


# --------------------------------------------------- what cannot be bounded


@pytest.mark.parametrize("budget,why", [
    (None, "offered no budget for this act, so the spend cannot be bounded."),
    ({"amount": 100, "unit": "USD"}, "offered no budget for this act"),                         # no decimals
    ({"amount": -1, "unit": "USD", "decimals": 2}, "offered no budget for this act"),
    ({"amount": 2 ** 53 + 1, "unit": "USD", "decimals": 2}, "offered no budget for this act"),  # Range Limits
    ({"amount": 10 ** 15, "unit": "USD", "decimals": 2}, "offered no budget for this act"),     # 16 digits
    ({"amount": 100, "unit": "USD", "decimals": -1}, "offered no budget for this act"),
    ({"amount": 100, "unit": 5, "decimals": 2}, "offered no budget for this act"),
    ({"amount": True, "unit": "USD", "decimals": 2}, "offered no budget for this act"),
    ({"amount": 100, "unit": "", "decimals": 2}, "offered no budget for this act"),
    ("100 USD", "offered no budget for this act"),
    ({"amount": 100, "unit": "EUR", "decimals": 2},
     "offers 1.00 EUR, but its ceiling is set in USD with 2 decimal places"),
    ({"amount": 100, "unit": "USD", "decimals": 6},
     "offers 0.000100 USD, but its ceiling is set in USD with 2 decimal places"),
])
@pytest.mark.req("BUD-002", "BUD-003", "BUD-004")
def test_an_offer_the_ss_cannot_compare_is_put_to_the_person(budget: Any, why: str) -> None:
    # Budgets: units are resource-declared and a figure in another scale is never converted.
    ss, ps, s256 = env()
    _, d = request(ss, ps, s256, budget)
    assert d["decision"] == "ask" and d["recommendation"] == "deny" and why in d["summary"]


@pytest.mark.req("BUD-002")
def test_an_offer_of_fifteen_digits_is_read() -> None:
    # Budgets, Range Limits: at most 999,999,999,999,999. The largest is read (and found
    # past the ceiling); one more digit is no budget at all (the test above).
    ss, ps, s256 = env()
    _, d = request(ss, ps, s256, usd(10 ** 15 - 1))
    assert d["decision"] == "ask" and "offers" in d["summary"]
    assert "offered no budget for this act" not in d["summary"]


@pytest.mark.req("BUD-007")
@pytest.mark.parametrize("consumed", [{"jti": "at-1"}, {"jti": "", "consumed": 0},
                                      {"jti": "at-1", "consumed": -5}, {"consumed": 0}, "0"])
def test_a_malformed_consumption_record_is_ignored(consumed: Any) -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), consumed)
    assert [h.consumed for h in history(ss, ps, s256) if h.jti == "at-1"] == [None]


@pytest.mark.req("BUD-008")
def test_a_record_without_an_offer_is_not_read() -> None:
    # Budgets: "A resource MUST NOT include budget_consumed unless budget is present".
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, None, {"jti": "at-1", "consumed": 0})
    assert [h.consumed for h in history(ss, ps, s256) if h.jti == "at-1"] == [None]


def test_an_earlier_act_without_a_budget_makes_the_spend_unknown() -> None:
    # An act at the resource from before the ceiling, or replayed to a new SS from an
    # `auth_token.issued` event (which carries no budget), cannot be accounted for.
    ss, ps, s256 = env()
    history(ss, ps, s256).append(HistoryEntry("unclassified", INF, "replay", sdi="d-old"))
    _, d = request(ss, ps, s256, usd(100))
    assert d["decision"] == "ask" and "has no budget the supervisor can account for" in d["summary"]


def test_a_resource_without_a_ceiling_ignores_budgets() -> None:
    ss, ps, s256 = env(ceiling={})
    assert request(ss, ps, s256, usd(10 ** 9))[1]["decision"] == "allow"
    assert request(ss, ps, s256, None)[1]["decision"] == "allow"


def test_the_allocation_survives_a_restart(tmp_path: Any) -> None:
    ss, ps, s256 = env()
    path = tmp_path / "state.json"
    ss.store.path = path
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 400})
    ss.store.save()
    again = Store(str(path))
    [h] = [h for h in again.history_for(ps.issuer, SUB, AGENT, s256) if h.jti == "at-1"]
    assert (h.unit, h.allocated, h.consumed) == ("USD/2", 1000, 400)


# ------------------------------------------------------------ configuration


def test_the_ceiling_is_loaded_from_the_policy_file() -> None:
    cfg = PolicyConfig.from_dict({"resource_budgets": CEILING})
    assert cfg.resource_budgets == {INF: ResourceBudget("USD", 2, 2500)}
    assert cfg.resource_budgets[INF].denomination == "USD/2"


@pytest.mark.parametrize("value,error", [
    ([], "resource_budgets: must be an object keyed by resource identifier"),
    ({"https://Inference.example": CEILING[INF]}, "the key must be a server identifier"),
    ({INF: {"unit": "USD", "max_amount": 1}}, "must be an object with exactly unit, decimals"),
    ({INF: CEILING[INF] | {"extra": 1}}, "must be an object with exactly unit, decimals"),
    ({INF: "25 USD"}, "must be an object with exactly unit, decimals"),
    ({INF: CEILING[INF] | {"unit": ""}}, f"resource_budgets.{INF}.unit: must be a non-empty string"),
    ({INF: CEILING[INF] | {"decimals": -1}}, f"resource_budgets.{INF}.decimals: must be an integer"),
    ({INF: CEILING[INF] | {"max_amount": 1.5}}, f"resource_budgets.{INF}.max_amount: must be a non-neg"),
])
def test_a_malformed_ceiling_is_refused(value: Any, error: str) -> None:
    with pytest.raises(ValueError, match=error.replace(".", r"\.").replace("(", r"\(")):
        PolicyConfig.from_dict({"resource_budgets": value})


@pytest.mark.parametrize("amount,decimals,text", [(2500, 2, "25.00 USD"), (5, 2, "0.05 USD"),
                                                  (7, 0, "7 USD"), (5_000_000, 6, "5.000000 USD")])
def test_money_is_printed_exactly(amount: int, decimals: int, text: str) -> None:
    assert _money(amount, ResourceBudget("USD", decimals, 0)) == text


def test_the_example_policy_sets_a_ceiling_at_the_example_inference_resource() -> None:
    from conftest import ROOT

    d = json.loads((ROOT / "examples" / "policy.json").read_text())
    assert d["resource_budgets"] == CEILING


def test_a_ceiling_outside_missions_is_not_called_a_mission_ceiling() -> None:
    # Outside any mission the ceiling holds for the acts outside missions: what the person
    # reads names that, not a mission.
    ss, ps, _ = env()
    _, d = request(ss, ps, "", usd(3000))
    assert d["decision"] == "ask"
    assert "mission ceiling" not in d["summary"] and "outside missions" in d["summary"]
    ss, ps, _ = env()
    assert request(ss, ps, "", usd(2000))[1]["decision"] == "allow"
    _, d = request(ss, ps, "", usd(1000))
    assert d["decision"] == "ask"
    assert "mission ceiling" not in d["summary"] and "outside missions" in d["summary"]


def test_an_unaccountable_act_outside_missions_is_not_called_a_mission_s_spend() -> None:
    ss, ps, _ = env()
    history(ss, ps, "").append(HistoryEntry("unclassified", INF, "replay", sdi="d-old"))
    _, d = request(ss, ps, "", usd(100))
    assert d["decision"] == "ask"
    assert "has no budget the supervisor can account for" in d["summary"]
    assert "mission's" not in d["summary"] and "outside missions" in d["summary"]


# ------------------------------------------------------------------ a spent ceiling holds
# No remembered answer passes a budget. Once a budget is spent, a request whose amount the
# supervisor cannot compare (no offer, another unit or scale, an amount it cannot see) can
# only take it further: it is refused, not put to the person. With room left such a request
# is asked, as an offer over the headroom is, and a "yes" lets that one act pass the limit.
# An act only assumed of a spent budget's class is still asked: it may not be of that class.

def _inference(**kw: Any) -> Any:
    return Act("auth_token", "https://ps.example", SUB, AGENT, "m", resource=INF, **kw)


def _committed(amount: int) -> HistoryEntry:
    entry = HistoryEntry("read", INF, "configured", detail="rule read")
    entry.unit, entry.allocated = "USD/2", amount
    return entry


@pytest.mark.parametrize("offer", [{}, {"budget_amount": 100, "budget_unit": "EUR/2"}])
def test_a_spent_resource_ceiling_refuses_what_it_cannot_compare(offer: dict[str, Any]) -> None:
    p = Policy(policy_cfg(resource_budgets=CEILING))
    rb = ResourceBudget(unit="USD", decimals=2, max_amount=2500)
    spent = p._resource_budget(_inference(**offer), rb, [_committed(2500)], [], [])
    assert spent is not None and spent[0] == "deny" and spent[1] == (
        f"Budget exhausted at {INF}.") and spent[2] == (
        "resource budget exhausted: 2500 of 2500 USD/2")
    room = p._resource_budget(_inference(**offer), rb, [_committed(2000)], [], [])
    assert room is not None and room[0] == "ask"  # with room left, the person decides


def test_a_spent_class_budget_refuses_an_amount_it_cannot_see() -> None:
    pay = "https://pay.example"
    p = Policy(policy_cfg(high_impact=[]))
    paid = [HistoryEntry("payment", pay, "resource", amount=250000, amount_known=True,
                         detail="rule payment on resource-asserted data") for _ in range(2)]
    act = Act("auth_token", "https://ps.example", SUB, AGENT, "", resource=pay)
    d = p.decide(act, None, paid, [], now=0)
    assert d.decision == "deny" and d.reason == (
        "Budget exhausted: the `payment` budget outside missions is spent, and "
        "this act's amount is not visible to the supervisor.")
    d = p.decide(act, None, paid[:1], [], now=0)
    assert d.decision == "ask" and "cannot be checked" in d.summary  # with room left
