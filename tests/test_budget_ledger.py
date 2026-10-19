"""The budget ledger keeps what it does not know as unknown, and never rolls back.

* A class budget by amount cannot book an act whose amount the SS never saw as 0: the
  next act would be checked against a total that may be far too low. Budgets, Unreported
  Allocations (L831): "the party missing a figure assumes the maximum until a real one
  supersedes it". With no maximum to assume, the later acts are put to the person.
* A consumption record only ever raises what a token has metered: a token's total never
  decreases, so a stale record arriving last does not roll the ledger back (L465, L459).
* A record is read in its own token's scale (L459) and applies only to an allocation in
  that scale: never converted (README), so never applied across scales.
* An amount longer than any budget amount (Budgets L326: at most 15 digits) is not read
  as a number at all, so it cannot make the SS fail.
* Two tokens issued under one decision are two allocations (issuance is a fact).
* The count budget's reason names where it holds: a mission, or outside missions.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env
from test_budgets import INF, env, history, issue, request, usd

PAY = "https://pay.example"


def _pay(ss: Any, ps: Any, s256: str, amount: Any = None) -> tuple[str, str]:
    prop = None if amount is None else {"operations": [{"operationId": "pay"}],
                                        "parameters": {"amount": amount}}
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, PAY, proposal=prop)
    d = str(r.json()["decision"])
    return sdi, d


def test_an_act_of_unknown_amount_is_not_booked_as_zero() -> None:
    ss, ps, clock = make_env(transport="forwarded", high_impact=[])
    s256 = connected((ss, ps, clock), resources=(PAY,))
    sdi, d = _pay(ss, ps, s256)                          # amount not visible: asked
    assert d == "ask"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow")
    assert ps.issued(ss, SUB, AGENT, s256, sdi, PAY).status == 201
    _, d = _pay(ss, ps, s256, 450_000)                   # within 500000 only if that was 0
    assert d == "ask"


def test_with_every_amount_known_acts_within_the_ceiling_are_allowed() -> None:
    ss, ps, clock = make_env(transport="forwarded", high_impact=[])
    s256 = connected((ss, ps, clock), resources=(PAY,))
    sdi, d = _pay(ss, ps, s256, 10_000)
    assert d == "allow"
    ps.issued(ss, SUB, AGENT, s256, sdi, PAY)
    assert _pay(ss, ps, s256, 450_000)[1] == "allow"


def test_a_stale_record_does_not_roll_the_ledger_back() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(2000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 1800})
    request(ss, ps, s256, usd(100), {"jti": "at-1", "consumed": 200})   # older snapshot
    [h] = [h for h in history(ss, ps, s256) if h.jti == "at-1"]
    assert h.consumed == 1800


def test_a_record_in_another_scale_is_not_applied() -> None:
    ss, ps, s256 = env()
    sdi, _ = request(ss, ps, s256, usd(2000))
    issue(ss, ps, s256, sdi, "at-1")
    request(ss, ps, s256, {"amount": 5, "unit": "USD", "decimals": 0},
            {"jti": "at-1", "consumed": 19})                             # 19 whole dollars
    [h] = [h for h in history(ss, ps, s256) if h.jti == "at-1"]
    assert h.consumed is None                            # still counted in full


@pytest.mark.parametrize("amount", ["9" * 4301, 10 ** 15, "1" + "0" * 15],
                         ids=["4301-digit string", "16-digit number", "16-digit string"])
def test_an_amount_beyond_any_budget_amount_is_not_visible(amount: Any) -> None:
    ss, ps, clock = make_env(transport="forwarded", high_impact=[])
    s256 = connected((ss, ps, clock), resources=(PAY,))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, PAY, proposal={
        "operations": [{"operationId": "pay"}], "parameters": {"amount": amount}})
    assert r.status == 200 and r.json()["decision"] == "ask"


def test_an_offer_beyond_fifteen_digits_is_not_a_budget() -> None:
    ss, ps, s256 = env(ceiling={INF: {"unit": "USD", "decimals": 2,
                                      "max_amount": 999_999_999_999_999}})
    _, d = request(ss, ps, s256, usd(10 ** 15))
    assert d["decision"] == "ask" and "it offered no budget for this act" in d["summary"]


def test_two_tokens_under_one_decision_are_two_allocations() -> None:
    ss, ps, s256 = env()
    sdi, d = request(ss, ps, s256, usd(1500))
    assert d["decision"] == "allow"
    issue(ss, ps, s256, sdi, "at-1")
    issue(ss, ps, s256, sdi, "at-2")
    assert sorted(h.jti for h in history(ss, ps, s256) if h.jti) == ["at-1", "at-2"]
    _, d = request(ss, ps, s256, usd(1000))              # 15 + 15 + 10 > 25
    assert d["decision"] != "allow"


def test_the_count_reason_says_outside_missions_when_it_is() -> None:
    ss, ps, clock = make_env(transport="forwarded", high_impact=[],
                             budgets={"payment": {"max_count": 0}})
    assert ps.connect(ss, SUB).status == 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", PAY, proposal={
        "operations": [{"operationId": "pay"}], "parameters": {"amount": 1}})
    assert r.json()["reason"] == "Budget exhausted: no more `payment` acts outside missions."
