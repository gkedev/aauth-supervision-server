"""Acts the SS has answered but that are not history yet still compose, as uncertain.

The SS learns an auth token was issued from `auth_token.issued`, and an asked act's fate
from `decision.resolved`. Until then the act is open: the person may be deciding (for
minutes or hours), the agent may be answering a clarification, or the PS is about to
issue. Supervision L211 orders event delivery by when the acts occurred, so a concurrent
request of the same chain can legitimately arrive in between. If the open act is not
counted, that request is decided without it and a prohibited composition completes
without the person ever seeing it. Counted as an uncertain act, it can only make the SS
ask, never deny, and it never spends a budget (a ceiling it would cross once it happens
is asked about, see test_budgets).
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import EXP_SKEW, HistoryEntry, Store

REC, CHAT = "https://records.example", "https://chat.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": CHAT, "class": "send_internal"}]
PAIR = "`read_sensitive`, then `send_internal`"


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [["read_sensitive", "send_internal"]])
    over.setdefault("high_impact", [])
    over.setdefault("prohibited_sequences", [])
    ss, ps, clock = make_env(rules=RULES, **over)
    return ss, ps, clock, connected((ss, ps, clock), resources=(REC, CHAT))


def _req(ss: Any, ps: Any, s256: str, res: str) -> tuple[str, dict[str, Any]]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, res)
    assert r.status in (200, 202), r.body
    return sdi, r.json()


def _outside(ss: Any, ps: Any, s256: str, res: str) -> None:
    """Make `res` an act the person is asked about (outside the mission's resources)."""
    blob = ss.store.missions[f"{ps.issuer}|{s256}"].blob
    blob["approved_resources"] = [r for r in blob["approved_resources"] if r != res]


# ------------------------------------------------------------ what is open


def test_an_act_allowed_but_not_yet_reported_issued_is_counted() -> None:
    ss, ps, _, s256 = _env()
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow"                  # issuance not reported yet
    _, d = _req(ss, ps, s256, CHAT)
    assert d["decision"] == "ask" and PAIR in d["summary"]


def test_an_act_the_person_is_deciding_is_counted() -> None:
    ss, ps, _, s256 = _env()
    _outside(ss, ps, s256, CHAT)
    _, d = _req(ss, ps, s256, CHAT)                   # outside the mission: asked
    assert d["decision"] == "ask"
    _, d = _req(ss, ps, s256, REC)                    # while the person decides
    assert d["decision"] == "ask" and "`send_internal`, then `read_sensitive`" in d["summary"]


def test_an_open_act_never_makes_a_deny() -> None:
    # Pairs complete on certain evidence are denied outright; an open act is not evidence
    # that anything happened, so the most it does is ask.
    ss, ps, _, s256 = _env()
    for _ in range(3):
        _req(ss, ps, s256, REC)
    _, d = _req(ss, ps, s256, CHAT)
    assert d["decision"] == "ask"


def test_once_issued_it_counts_as_what_it_is() -> None:
    ss, ps, _, s256 = _env()
    sdi, _ = _req(ss, ps, s256, REC)
    assert ps.issued(ss, SUB, AGENT, s256, sdi, REC).status == 201
    _, d = _req(ss, ps, s256, CHAT)
    assert d["decision"] == "deny"                     # certain now


def test_the_act_being_decided_is_not_its_own_open_act() -> None:
    # A retry of an open request under its own sdi is the same act, never a second one.
    store = Store()
    assert store.open_acts("iss", SUB, AGENT, "", exclude_sdi="", now=0.0) == []
    ss, ps, clock, s256 = _env(prohibited_pairs=[["read_sensitive", "read_sensitive"]])
    sdi, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow"
    hist = ss.store.composition_history(ps.issuer, SUB, AGENT, s256, exclude_sdi=sdi,
                                        now=clock())
    assert [h for h in hist if h.open] == []


# ------------------------------------------------------- when it stops being open


def test_an_open_act_that_ends_without_happening_stops_counting() -> None:
    ss, ps, _, s256 = _env()
    _outside(ss, ps, s256, CHAT)
    sdi, _ = _req(ss, ps, s256, CHAT)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny")
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow"


def test_an_abandoned_ask_stops_counting() -> None:
    ss, ps, _, s256 = _env()
    _outside(ss, ps, s256, CHAT)
    sdi, _ = _req(ss, ps, s256, CHAT)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "abandoned")
    assert _req(ss, ps, s256, REC)[1]["decision"] == "allow"


def test_an_allow_never_reported_issued_stops_counting_once_its_cap_is_spent() -> None:
    # Supervision L508: the allow carries `exp`, capped an hour after the decision
    # (Protocol L1775: an auth token lives at most one hour), and the PS applies it. A
    # token issued after the cap plus the usable margin is spent, so the allow stops
    # counting then.
    ss, ps, clock, s256 = _env()
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow" and d["exp"] == int(clock()) + Store.OPEN_ISSUANCE
    clock.t += Store.OPEN_ISSUANCE + EXP_SKEW - 1
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "ask"
    clock.t += 1
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "allow"


def test_an_ask_the_person_allowed_is_awaited_from_the_answer_not_the_question() -> None:
    # The person may take hours to answer; the PS issues after that.
    ss, ps, clock, s256 = _env()
    _outside(ss, ps, s256, REC)
    sdi, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "ask"
    clock.t += 5 * 3600
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow")
    rec = ss.store.decisions[Store.k(ps.issuer, sdi)]
    assert rec.decision == "resolved_allow" and rec.resolved_at > rec.entry.at
    clock.t += Store.OPEN_ISSUANCE + EXP_SKEW - 1
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "ask"
    clock.t += 1
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "allow"


def test_a_permission_allowed_is_not_open_its_grant_is_the_act() -> None:
    store = Store()
    from aauth_supervision_server.store import DecisionRecord, HistoryEntry
    store.decisions["k"] = DecisionRecord("s", "iss", SUB, AGENT, "permission", "allow",
                                          entry=HistoryEntry("send_internal", "t", "agent"))
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []
    store.decisions["k"].decision = "deny"
    store.decisions["k"].act = "auth_token"
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []


def test_a_clarification_is_open_only_while_its_pending_url_is() -> None:
    from aauth_supervision_server.store import DecisionRecord, Pending, StoredResponse
    store = Store()
    store.decisions["k"] = DecisionRecord("s", "iss", SUB, AGENT, "auth_token", "clarify",
                                          entry=HistoryEntry("send_internal", CHAT, "agent"))
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []         # no pending URL
    store.add_pending(Pending("p", "iss", "other-sdi", "clarify"))
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []         # another request's
    store.add_pending(Pending("p", "iss", "s", "clarify", deadline=10.0))
    assert len(store.open_acts("iss", SUB, AGENT, "", "", 9.0)) == 1
    assert store.open_acts("iss", SUB, AGENT, "", "", 10.0) == []        # timed out
    store.pending["p"].cancelled = True
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []         # withdrawn
    store.pending["p"].cancelled = False
    store.pending["p"].resolved = StoredResponse(200, {}, "{}")
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []         # answered


def test_an_open_act_in_a_mission_outside_the_act_s_scope_is_not_its() -> None:
    # Another provider's agent's allow, open, in its own mission: no part of AGENT's scope.
    from aauth_supervision_server.store import DecisionRecord, Mission
    store = Store()
    store.add_mission(Store.k("iss", "m-of-r"), Mission("m-of-r", "aauth:r@q.example", SUB,
                                                        "iss"))
    store.decisions["k"] = DecisionRecord("s", "iss", SUB, "aauth:r@q.example", "auth_token",
                                          "allow", mission_s256="m-of-r",
                                          entry=HistoryEntry("read_sensitive", REC, "agent"))
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []
    assert len(store.open_acts("iss", SUB, "aauth:r@q.example", "m-of-r", "", 0.0)) == 1


def test_a_record_settled_but_not_yet_out_of_the_open_set_links_nothing() -> None:
    # Without a clock (the recorded history alone) the open set is not cleared first; a
    # record whose act is over still links no agent to its mission.
    from aauth_supervision_server.store import DecisionRecord
    store = Store()
    store.record_decision("k", DecisionRecord(
        "s", "iss", SUB, "aauth:r@q.example", "auth_token", "deny", mission_s256="m-of-r",
        entry=HistoryEntry("read_sensitive", REC, "agent")))
    assert store.open_records("iss", SUB) == ["k"]
    assert store._open_links("iss", SUB) == ({}, set())

# ------------------------------------------------------------- whose acts


def test_an_open_act_in_another_mission_is_counted_as_uncertain() -> None:
    # As a recorded act of another mission is (tests/test_composition_scope.py).
    ss, ps, clock, s256 = _env()
    r, other = ps.propose_and_approve(ss, SUB, AGENT, "# Another task", [REC, CHAT], [])
    assert r.status == 200 and other and other != s256
    _req(ss, ps, other, REC)
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "ask"


def test_an_open_act_of_another_person_or_agent_outside_missions_is_not_counted() -> None:
    store = Store()
    from aauth_supervision_server.store import DecisionRecord, HistoryEntry
    e = HistoryEntry("read_sensitive", REC, "configured", at=0)
    store.decisions["a"] = DecisionRecord("a", "iss", "someone-else", AGENT, "auth_token",
                                          "allow", entry=e)
    store.decisions["b"] = DecisionRecord("b", "iss", SUB, "another-agent", "auth_token",
                                          "allow", entry=e)
    store.decisions["c"] = DecisionRecord("c", "other-ps", SUB, AGENT, "auth_token",
                                          "allow", entry=e)
    assert store.open_acts("iss", SUB, AGENT, "", "", 1.0) == []
    store.decisions["d"] = DecisionRecord("d", "iss", SUB, AGENT, "auth_token", "allow", entry=e)
    [o] = store.open_acts("iss", SUB, AGENT, "", "", 1.0)
    assert (o.sdi, o.open, o.borrowed, o.scope) == ("d", "own", True, "")
    assert o.detail.startswith("uncertain: allow not yet settled")


def test_open_acts_cross_the_mission_boundary_like_recorded_ones() -> None:
    """An open act outside missions composes with the agent's mission, and the reverse,
    marked `other` (it is not in the decided act's own history, so no budget sees it);
    seen from outside, a mission's open act carries its mission as `scope`."""
    ss, ps, clock, s256 = _env()
    _req(ss, ps, "", REC)                              # outside any mission, allowed
    hist = ss.store.composition_history(ps.issuer, SUB, AGENT, s256, now=clock())
    assert [(h.action_class, h.open) for h in hist if h.open] == [("read_sensitive", "other")]
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "ask"
    hist = ss.store.composition_history(ps.issuer, SUB, AGENT, "", now=clock())
    assert {(h.action_class, h.open, h.scope) for h in hist if h.open} == {
        ("read_sensitive", "own", ""), ("send_internal", "other", s256)}


def test_an_open_clarification_counts_until_its_deadline() -> None:
    ss, ps, clock, s256 = _env(high_impact=["send_internal"], clarify_missing_justification=True)
    ss.cfg.clarification_timeout = 600
    _, d = _req(ss, ps, s256, CHAT)
    assert d["decision"] == "clarify"                  # the agent is asked what it is for
    assert _req(ss, ps, s256, REC)[1]["decision"] == "ask"
    clock.t += 600
    assert _req(ss, ps, s256, REC)[1]["decision"] == "allow"


# ------------------------------------------------------------------ budgets


def test_an_open_act_spends_no_budget_but_a_count_it_would_cross_is_asked() -> None:
    ss, ps, clock, s256 = _env(budgets={"read_sensitive": {"max_count": 1}},
                               prohibited_pairs=[])
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow"                    # not issued (yet, or ever)
    sdi, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "ask" and d["recommendation"] == "deny"
    assert ("An earlier `read_sensitive` act is allowed or still being decided, and has not been "
            "reported done yet.") in d["summary"]
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny")     # the ask is settled; the allow is not
    clock.t += Store.OPEN_ISSUANCE + EXP_SKEW
    assert _req(ss, ps, s256, REC)[1]["decision"] == "allow"


def test_an_open_act_across_the_mission_boundary_is_not_in_the_missions_budget() -> None:
    # A mission's ceilings are the mission's: an act outside it, open or not, composes
    # but does not count against them.
    ss, ps, _, s256 = _env(budgets={"read_sensitive": {"max_count": 1}}, prohibited_pairs=[])
    assert _req(ss, ps, "", REC)[1]["decision"] == "allow"   # outside missions, open
    assert _req(ss, ps, s256, REC)[1]["decision"] == "allow"


def _policy_with_open(entry: HistoryEntry, **over: Any) -> Any:
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Policy
    pol = Policy(policy_cfg(**({"prohibited_pairs": [], "prohibited_sequences": [],
                                "high_impact": []} | over)))
    open_copy = dataclasses.replace(entry, borrowed=True, open="own",
                                    detail="uncertain: ask not yet settled")
    return pol, [open_copy]


def test_an_open_allocation_the_ss_cannot_account_for_is_asked_about() -> None:
    # The open act had no offer the SS could compare (it was asked for that reason): if
    # it happens, the spend at the resource is unbounded, so a later offer that fits is
    # still put to the person.
    from aauth_supervision_server.policy import Act
    inf = "https://inference.example"
    pol, hist = _policy_with_open(HistoryEntry("unclassified", inf, "configured"))
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=inf, budget_unit="USD/2",
              budget_amount=100)
    d = pol.decide(act, None, hist, [], 0.0)
    assert d.decision == "ask" and "An earlier allocation is allowed or still being decided" in d.summary


def test_an_open_act_of_unknown_amount_is_asked_about_under_an_amount_budget() -> None:
    from aauth_supervision_server.policy import Act
    pay = "https://pay.example"
    pol, hist = _policy_with_open(
        HistoryEntry("payment", pay, "configured", amount_known=False),
        budgets={"payment": {"max_amount": 1000}})
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=pay,
              parameters={"amount": 10}, parameters_provenance="resource")
    d = pol.decide(act, None, hist, [], 0.0)
    assert d.decision == "ask" and "An earlier `payment` act is allowed or still being decided" in d.summary
    hist[0].amount_known, hist[0].amount = True, 990       # known, and it would fit exactly
    assert pol.decide(act, None, hist, [], 0.0).decision == "allow"
    hist[0].amount = 991
    assert pol.decide(act, None, hist, [], 0.0).decision == "ask"


# ------------------------------------------------------- a person's earlier "no"


def _declined(comp: list[str]) -> Any:
    from aauth_supervision_server.store import Reach
    return Reach("mission", "iss", SUB, AGENT, f"send_internal|{CHAT}", "m", comp, "deny")


def test_an_earlier_no_to_a_composition_only_an_open_act_completes_is_asked_not_applied() -> None:
    """The person declined `read_sensitive` then `send_internal` for the mission. A send
    while a read is only open (it may never
    happen) must not be denied on that answer: an open act makes the SS ask, never deny.
    It is asked, with the recommendation to deny."""
    from aauth_supervision_server.policy import Act
    pol, hist = _policy_with_open(HistoryEntry("read_sensitive", REC, "configured"),
                                  rules=RULES, prohibited_pairs=[["read_sensitive",
                                                                  "send_internal"]])
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=CHAT)
    reach = [_declined(["read_sensitive", "send_internal"])]
    d = pol.decide(act, None, hist, reach, 0.0)
    assert d.decision == "ask" and d.recommendation == "deny"
    assert pol.decide(act, None, [], reach, 0.0).decision == "allow"   # nothing open


def test_an_earlier_no_still_answers_for_a_recorded_uncertain_composition() -> None:
    # The same answer applies as before when the read is history, even on uncertain
    # evidence: the person is not asked again about what they declined.
    from aauth_supervision_server.policy import Act
    pol, _ = _policy_with_open(HistoryEntry("read_sensitive", REC, "configured"),
                               rules=RULES, prohibited_pairs=[["read_sensitive",
                                                               "send_internal"]])
    recorded = HistoryEntry("read_sensitive", REC, "configured", detail="uncertain: maybe")
    open_too = dataclasses.replace(recorded, borrowed=True, open="own",
                                   detail="uncertain: ask not yet settled")
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=CHAT)
    reach = [_declined(["read_sensitive", "send_internal"])]
    for hist in ([recorded], [recorded, open_too]):
        d = pol.decide(act, None, hist, reach, 0.0)
        assert d.decision == "deny" and "declined" in d.reason


def test_an_ask_the_person_never_answers_stays_open() -> None:
    # Unlike an allow, an ask is not given up on: the person may answer days later and
    # the PS then issues, so until `decision.resolved` (or the mission's end) it counts.
    ss, ps, clock, s256 = _env()
    _outside(ss, ps, s256, REC)
    assert _req(ss, ps, s256, REC)[1]["decision"] == "ask"
    clock.t += 2 * 86400
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "ask"


def test_a_record_stored_again_under_its_sdi_is_seen_open_again() -> None:
    # A record settled and then stored again under the same sdi with an open decision is
    # open again: settling it does not drop its sdi from the open set for good.
    from aauth_supervision_server.store import DecisionRecord
    store = Store()
    e = HistoryEntry("read_sensitive", REC, "configured")
    store.record_decision("k", DecisionRecord("d1", "iss", SUB, AGENT, "auth_token", "deny",
                                              entry=e))
    assert store.open_acts("iss", SUB, AGENT, "", "", 0.0) == []      # settled: dropped
    store.record_decision("k", DecisionRecord("d1", "iss", SUB, AGENT, "auth_token", "ask",
                                              entry=e))
    assert [o.sdi for o in store.open_acts("iss", SUB, AGENT, "", "", 0.0)] == ["d1"]


# ------------------------------------------------------------ bounds on what stays open


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat().replace("+00:00", "Z")


def test_an_ask_nobody_answers_stops_counting_when_its_mission_expires() -> None:
    # Protocol L1425: a PS treats a mission past `expires_at` as terminated on every
    # decision path and caps the tokens it issues under it there. An ask in that mission
    # can no longer lead to a usable token once it has expired, plus the usable margin.
    ss, ps, clock, s256 = _env()
    _outside(ss, ps, s256, REC)
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "ask"                     # nobody answers it
    end = int(clock()) + 600
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["expires_at"] = _iso(end)
    _, d = _req(ss, ps, "", CHAT)                     # outside the mission, same agent
    assert d["decision"] == "ask" and PAIR in d["summary"]
    clock.t = end + EXP_SKEW - 1
    assert _req(ss, ps, "", CHAT)[1]["decision"] == "ask"
    clock.t = end + EXP_SKEW
    assert _req(ss, ps, "", CHAT)[1]["decision"] == "allow"


def test_an_ask_outside_any_mission_keeps_counting() -> None:
    # No mission, no expiry the SS can rely on: the person may answer days later.
    ss, ps, clock, _ = _env()
    sdi, d = _req(ss, ps, "", REC)
    assert d["decision"] == "allow"
    # Turned into an ask nobody answers: only a mission's expiry bounds an ask.
    ss.store.decisions[Store.k(ps.issuer, sdi)].decision = "ask"
    clock.t += 30 * 24 * 3600
    _, d = _req(ss, ps, "", CHAT)
    assert d["decision"] == "ask" and PAIR in d["summary"]


def test_the_allow_cap_never_extends_a_shorter_mission_exp() -> None:
    # Supervision L508 and the mission's own cap (Protocol L1425): the earlier one wins.
    ss, ps, clock, s256 = _env()
    end = int(clock()) + 600
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["expires_at"] = _iso(end)
    _, d = _req(ss, ps, s256, REC)
    assert d["decision"] == "allow" and d["exp"] == end


def test_a_token_issued_after_its_cap_cannot_compose_unseen() -> None:
    # The PS applies the allow's `exp` (L508): a token for an allow lapsed from the open
    # count is issued already spent. The act decided in between was allowed, and the
    # spent token, once reported, is recorded with its real `exp`, not as never expiring.
    ss, ps, clock, s256 = _env()
    sdi, d = _req(ss, ps, s256, REC)
    cap = d["exp"]
    clock.t = cap + EXP_SKEW
    assert _req(ss, ps, s256, CHAT)[1]["decision"] == "allow"
    ps.issued(ss, SUB, AGENT, s256, sdi, REC)
    body = ps.sent[-1][1]
    assert body["event"] == "auth_token.issued" and body["exp"] == cap
    assert cap + EXP_SKEW <= body["iat"]              # spent on issue, even with the margin
    entry = next(h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
                 if h.sdi == sdi)
    assert entry.token_exp == cap


def _sequence_env() -> tuple[Any, Any, Any, str]:
    return _env(prohibited_pairs=[], prohibited_sequences=[["read_sensitive", "send_internal"]])


def _late_issued(ss: Any, ps: Any, s256: str, sdi: str, res: str, iat: int,
                 exp: int) -> None:
    r = ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": iat,
        "sub": SUB, "agent": AGENT, "jti": ps.nid("at"), "aud": res, "exp": exp,
        "issuer": ps.issuer, "mission_s256": s256})
    assert r.status == 201, r.body


def test_a_capped_token_issued_late_is_not_read_as_live_forever() -> None:
    # The later step's token is taken first and held, and the PS issues it after the cap
    # (the event's `iat` is the time of issuance, L198). Read as never expiring, the token
    # would complete the sequence with every later read, denying honest acts for good; it
    # is the cap applied, spent, and the read long after it is allowed as it would be had
    # the PS issued on time.
    ss, ps, clock, s256 = _sequence_env()
    sdi, d = _req(ss, ps, s256, CHAT)
    cap = d["exp"]
    clock.t = cap + EXP_SKEW + 1
    _late_issued(ss, ps, s256, sdi, CHAT, int(clock.t), cap)
    clock.t = cap + 7 * 24 * 3600
    assert _req(ss, ps, s256, REC)[1]["decision"] == "allow"


def test_an_exp_outside_the_cap_window_is_still_read_as_never_expiring() -> None:
    # Only an `exp` from the decision to the SS's own cap is that cap applied. A value
    # below the decision time (a lifetime sent as `exp`, a slip) says nothing about when
    # the token ends, so it still guards the order it might break.
    ss, ps, clock, s256 = _sequence_env()
    sdi, d = _req(ss, ps, s256, CHAT)
    clock.t = d["exp"] + EXP_SKEW + 1
    _late_issued(ss, ps, s256, sdi, CHAT, int(clock.t), 3600)
    clock.t += 7 * 24 * 3600
    assert _req(ss, ps, s256, REC)[1]["decision"] == "deny"


def test_an_exp_past_the_cap_is_not_the_cap_applied() -> None:
    # A token outliving the SS's cap was not narrowed by it (a federated AS, L508), so a
    # late report of it gets no benefit of the doubt.
    ss, ps, clock, s256 = _sequence_env()
    sdi, d = _req(ss, ps, s256, CHAT)
    clock.t = d["exp"] + 600
    _late_issued(ss, ps, s256, sdi, CHAT, int(clock.t), d["exp"] + 10)
    clock.t += 7 * 24 * 3600
    assert _req(ss, ps, s256, REC)[1]["decision"] == "deny"
