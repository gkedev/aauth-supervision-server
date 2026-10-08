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
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.policy import PolicyConfig, ResourceBudget, _money
from aauth_supervision_server.store import HistoryEntry, Store

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


def test_an_offer_within_the_ceiling_is_allowed_and_recorded_as_an_allocation() -> None:
    ss, ps, s256 = env()
    sdi, d = request(ss, ps, s256, usd(1000))
    assert d["decision"] == "allow"
    issue(ss, ps, s256, sdi, "at-1")
    [h] = [h for h in history(ss, ps, s256) if h.resource == INF]
    assert (h.unit, h.allocated, h.jti, h.consumed) == ("USD/2", 1000, "at-1", None)


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
                            f"ceiling is left. The supervisor cannot grant less under Supervision -00.")


def test_a_consumption_record_replaces_the_assumption_for_its_token() -> None:
    ss, ps, s256 = env()
    for jti in ("at-1", "at-2"):
        sdi, _ = request(ss, ps, s256, usd(1000))
        issue(ss, ps, s256, sdi, jti)
    # The resource reports that at-1 spent only 2.00: 2 + 10 + 10 = 22 fits in 25.
    _, d = request(ss, ps, s256, usd(1000), {"jti": "at-1", "consumed": 200})
    assert d["decision"] == "allow"
    assert {h.jti: h.consumed for h in history(ss, ps, s256) if h.jti} == {"at-1": 200, "at-2": None}


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
                 "reason": f"Budget exhausted at {INF}: 25.00 USD of 25.00 USD committed."}


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


def test_an_allowed_but_never_issued_allocation_does_not_count() -> None:
    ss, ps, s256 = env()
    for _ in range(3):  # three allows of 10 with no issuance: nothing was granted
        assert request(ss, ps, s256, usd(1000))[1]["decision"] == "allow"


# --------------------------------------------------- what cannot be bounded


@pytest.mark.parametrize("budget,why", [
    (None, "carries no `budget`, so the spend cannot be bounded."),
    ({"amount": 100, "unit": "USD"}, "carries no `budget`"),                         # no decimals
    ({"amount": -1, "unit": "USD", "decimals": 2}, "carries no `budget`"),
    ({"amount": 2 ** 53 + 1, "unit": "USD", "decimals": 2}, "carries no `budget`"),  # Range Limits
    ({"amount": True, "unit": "USD", "decimals": 2}, "carries no `budget`"),
    ({"amount": 100, "unit": "", "decimals": 2}, "carries no `budget`"),
    ("100 USD", "carries no `budget`"),
    ({"amount": 100, "unit": "EUR", "decimals": 2}, "offers a budget in EUR/2, which is not the USD/2"),
    ({"amount": 100, "unit": "USD", "decimals": 6}, "offers a budget in USD/6, which is not the USD/2"),
])
def test_an_offer_the_ss_cannot_compare_is_put_to_the_person(budget: Any, why: str) -> None:
    # Budgets: units are resource-declared and a figure in another scale is never converted.
    ss, ps, s256 = env()
    _, d = request(ss, ps, s256, budget)
    assert d["decision"] == "ask" and d["recommendation"] == "deny" and why in d["summary"]


@pytest.mark.parametrize("consumed", [{"jti": "at-1"}, {"jti": "", "consumed": 0},
                                      {"jti": "at-1", "consumed": -5}, {"consumed": 0}, "0"])
def test_a_malformed_consumption_record_is_ignored(consumed: Any) -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(1000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), consumed)
    assert [h.consumed for h in history(ss, ps, s256) if h.jti == "at-1"] == [None]


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
    ({INF: CEILING[INF] | {"decimals": -1}}, f"resource_budgets.{INF}.decimals: must be a non-negative"),
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
