"""A `deny` the person gives a reach is remembered and applied, like an `allow`.

Supervision L582: the person's choice of reach comes back in `decision.resolved`, "and the
SS remembers and applies it to later acts". An answer given with `mission` or `always` is
applied, an `allow` or a `deny` alike, where the same question would be asked again: for a
resource or tool the mission leaves out, in a mission that leaves it out; for a
high-impact act, where it would be asked for the same reason; for a composition, in that
mission, where it would be asked about again (a `deny` only where acts already recorded
could complete it). Each label says where. A `deny` given with a reach answers for the
person only there: it never turns an act the SS would allow into a deny, and a later answer for
the same scope replaces it.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

HR, CAL, MAIL = "https://hr.example", "https://calendar.example", "https://mail.example"


def _take(ss: Any, ps: Any, s256: str, res: str, **kw: Any) -> tuple[str, dict[str, Any]]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, res, **kw)
    d = r.json()
    if d.get("decision") == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, res).status == 201
    return sdi, d


@pytest.mark.req("SUP-P11")
def test_a_mission_deny_is_applied_to_the_next_act_like_it() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, d = _take(ss, ps, s256, CAL)
    assert d["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="mission").status == 201
    _, d = _take(ss, ps, s256, CAL)
    assert d["decision"] == "deny" and "declined" in d["reason"]


def test_an_always_deny_holds_in_another_mission_that_leaves_the_resource_out() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, _ = _take(ss, ps, s256, CAL)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="always")
    r, other = ps.propose_and_approve(ss, SUB, AGENT, "# Other", [HR], [])
    assert _take(ss, ps, other, CAL)[1]["decision"] == "deny"


def test_a_deny_with_reach_applies_where_its_label_says_and_nowhere_else() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, d = _take(ss, ps, s256, CAL)
    assert {o["value"]: o["label"] for o in d["apply_options"]}["always"] == (
        f"`write` acts by this agent on {CAL}, in any mission that does not include it, "
        f"from now on")
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="always").status == 201
    assert _take(ss, ps, s256, CAL)[1]["decision"] == "deny"
    # Outside missions no mission leaves the resource out, so the question never arises.
    assert _take(ss, ps, "", CAL)[1]["decision"] == "allow"


def test_a_deny_never_turns_an_allowed_act_into_a_deny() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, _ = _take(ss, ps, s256, CAL)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="always")
    # Approved in this mission, the same kind of act is not asked, so not answered for.
    r, other = ps.propose_and_approve(ss, SUB, AGENT, "# Calendar work", [CAL], [])
    assert _take(ss, ps, other, CAL)[1]["decision"] == "allow"


def test_an_abandoned_answer_sets_nothing() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, _ = _take(ss, ps, s256, CAL)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "abandoned", apply="mission")
    assert ss.store.reach == []
    assert _take(ss, ps, s256, CAL)[1]["decision"] == "ask"


def test_a_later_answer_for_the_same_scope_replaces_the_earlier_one() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    sdi, _ = _take(ss, ps, s256, CAL)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission")
    # Asked again for another reason (a budget is never answered by reach), the person
    # now says no for the mission: that answer is the one that stands.
    rec = ss.store.decisions[f"{ps.issuer}|{sdi}"]
    rec.decision = "ask"
    ps.call(ss, "POST", "/event", {"event": "decision.resolved", "id": ps.nid("e"),
                                   "sdi": sdi, "iat": int(clock()), "sub": SUB,
                                   "agent": AGENT, "mission_s256": s256, "answer": "deny",
                                   "apply": "mission"})
    assert [(r.value, r.answer) for r in ss.store.reach] == [("mission", "deny")]
    assert _take(ss, ps, s256, CAL)[1]["decision"] == "deny"


def test_a_person_token_deny_is_remembered() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR,))
    body = {"act": "person_token", "iat": int(clock()), "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT), "resource": MAIL}
    sdi = ps.nid("d")
    assert ps.call(ss, "POST", "/decision", body | {"sdi": sdi}).json()["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="mission")
    again = ps.call(ss, "POST", "/decision", body | {"sdi": ps.nid("d")}).json()
    assert again["decision"] == "deny"


def test_a_deny_given_to_a_composition_is_applied_to_that_composition() -> None:
    hr, mail = "https://hr.example", "https://mail.example"
    ss, ps, clock = make_env(high_impact=[])
    s256 = connected((ss, ps, clock), resources=(hr, mail))
    sdi, d = _take(ss, ps, s256, hr)
    assert d["decision"] == "allow"
    sdi, d = _take(ss, ps, s256, mail, scope="mail.send")      # may complete the pair
    assert d["decision"] == "ask" and d["apply_options"][1]["value"] == "mission"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny", apply="mission")
    _, d = _take(ss, ps, s256, mail, scope="mail.send")
    assert d["decision"] == "deny" and "declined" in d["reason"]


def test_an_always_deny_replaces_an_earlier_mission_allow() -> None:
    ss, ps, clock = make_env()
    m1 = connected((ss, ps, clock), resources=(HR,))
    sdi, _ = _take(ss, ps, m1, CAL)
    ps.resolved(ss, SUB, AGENT, m1, sdi, "allow", apply="mission")
    assert _take(ss, ps, m1, CAL)[1]["decision"] == "allow"
    r, m2 = ps.propose_and_approve(ss, SUB, AGENT, "# Other", [HR], [])
    sdi, d = _take(ss, ps, m2, CAL)
    assert d["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, m2, sdi, "deny", apply="always")
    assert _take(ss, ps, m1, CAL)[1]["decision"] == "deny"
