"""A person token for a resource that serves on identity is decided as the act it can be.

Protocol L326-L346 (Person Identity Access): such a resource serves on the person token
alone. The SS never sees what is read there, so the token is an act of the most severe
class the policy gives the resource, uncertain: it composes (asked, never denied), it
meets the high-impact gate as an auth token without resource evidence does, it is open
until reported issued, and it spends no budget. A person token for any other resource
is an identity check and composes with nothing.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.adversarial import MAIL, REC, SEND
from aauth_supervision_server.store import Store

EVIL = SEND | {"parameters": {"to": "drop@evil.example"}}
EXPORT = {"operations": [{"operationId": "export"}], "parameters": {}}


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("serves_on_identity", [REC])
    over.setdefault("allow_unlisted_resources", True)
    ss, ps, clock = make_env(transport="forwarded", **over)
    # A mission that names no resource serving on identity: its approval issues no person
    # token that is an act (Supervision L417; `tests/test_approval_person_tokens.py`), so
    # these tests about decided person tokens start with nothing read.
    s256 = connected((ss, ps, clock), resources=(MAIL,))
    return ss, ps, clock, s256


def _take(ss: Any, ps: Any, s256: str, resource: str, issue: bool = True,
          **kw: Any) -> dict[str, Any]:
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, resource, **kw)
    d = r.json()
    if issue and d["decision"] == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource, kw.get("scope", ""),
                         prop).status == 201
    return d


def _person(ss: Any, ps: Any, clock: Any, s256: str, resource: str) -> tuple[str, Any]:
    sdi = ps.nid("d")
    b: dict[str, Any] = {"sdi": sdi, "act": "person_token", "iat": int(clock()), "sub": SUB,
                         "agent": AGENT, "agent_token": ps.agent_token(AGENT),
                         "resource": resource}
    if s256:
        b["mission_s256"] = s256
    return sdi, ps.call(ss, "POST", "/decision", b)


def _person_issued(ss: Any, ps: Any, clock: Any, s256: str, sdi: str, jti: str,
                   aud: str | None = REC) -> int:
    b: dict[str, Any] = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi,
                         "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": jti,
                         "exp": int(clock()) + 3600}
    if aud is not None:
        b["aud"] = aud
    if s256:
        b["mission_s256"] = s256
    return int(ps.call(ss, "POST", "/event", b).status)


@pytest.mark.parametrize("in_mission", [True, False])
def test_a_person_token_that_completes_a_pair_is_asked(in_mission: bool) -> None:
    ss, ps, clock, s256 = _env()
    where = s256 if in_mission else ""
    assert _take(ss, ps, where, MAIL, scope="mail.send", proposal=EVIL)["decision"] == "allow"
    _, r = _person(ss, ps, clock, where, REC)
    d = r.json()
    assert d["decision"] == "ask", d
    assert "`read_sensitive`, then `send_external`" in d["summary"] or \
        "`send_external`, then `read_sensitive`" in d["summary"]


def test_a_person_token_at_a_high_impact_resource_is_asked() -> None:
    ss, ps, clock, s256 = _env(rules=[{"resource": "https://admin.example", "class": "admin"}],
                               serves_on_identity=["https://admin.example"],
                               allow_unlisted_resources=True)
    _, r = _person(ss, ps, clock, s256, "https://admin.example")
    assert r.json()["decision"] == "ask"
    # What the resource serves on the token is not seen: it may be an admin act.
    assert "This may be a `admin` act" in r.json()["summary"]


def test_an_allowed_person_token_not_yet_issued_is_an_open_act() -> None:
    ss, ps, clock, s256 = _env()
    _, r = _person(ss, ps, clock, s256, REC)
    d = r.json()
    assert d["decision"] == "allow"
    assert d["exp"] <= int(clock()) + Store.OPEN_ISSUANCE
    assert _take(ss, ps, s256, MAIL, scope="mail.send", proposal=EVIL)["decision"] == "ask"


def test_the_issuance_of_a_decided_person_token_is_the_decided_act_once() -> None:
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, s256, REC)
    assert r.json()["decision"] == "allow"
    for _ in range(2):
        assert _person_issued(ss, ps, clock, s256, sdi, "pt-1") == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [(h.action_class, h.sdi, h.jti) for h in hist] == [("read_sensitive", sdi, "pt-1")]
    assert hist[0].detail.startswith("uncertain") and hist[0].detail.endswith("person token")


def test_a_decided_person_token_reported_without_aud_is_the_decided_resource() -> None:
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, s256, REC)
    assert r.json()["decision"] == "allow"
    assert _person_issued(ss, ps, clock, s256, sdi, "pt-2", aud=None) == 201
    assert [h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == [REC]


def test_a_person_token_without_aud_or_decision_is_refused() -> None:
    ss, ps, clock, s256 = _env()
    assert _person_issued(ss, ps, clock, s256, "d-unknown", "pt-3", aud=None) == 400


def test_the_identity_class_is_the_most_severe_the_policy_gives_the_resource() -> None:
    # Every rule for the resource is narrowed by scope or operation; what the token reads
    # there is not seen, so it is the most severe of them.
    rules = [{"resource": REC, "scope": "records.read", "class": "read_internal"},
             {"resource": REC, "operation": "export", "class": "read_sensitive"},
             {"resource": MAIL, "scope": "mail.send", "class": "send_external"},
             {"resource": "*", "tool": "Reader", "class": "admin"}]
    ss, ps, clock, s256 = _env(rules=rules)
    sdi, r = _person(ss, ps, clock, s256, REC)
    assert r.json()["decision"] == "allow"
    assert _person_issued(ss, ps, clock, s256, sdi, "pt-4") == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [h.action_class for h in hist] == ["read_sensitive"]
    assert _take(ss, ps, s256, MAIL, scope="mail.send")["decision"] == "ask"


def test_a_person_token_spends_no_budget() -> None:
    ss, ps, clock, s256 = _env(budgets={"read_sensitive": {"max_count": 1}})
    assert _take(ss, ps, s256, REC, proposal=EXPORT)["decision"] == "allow"
    _, r = _person(ss, ps, clock, s256, REC)
    assert r.json()["decision"] == "allow"


def test_a_person_token_for_another_resource_is_an_identity_check() -> None:
    ss, ps, clock, s256 = _env()
    assert _take(ss, ps, s256, MAIL, scope="mail.send", proposal=EVIL)["decision"] == "allow"
    sdi, r = _person(ss, ps, clock, s256, MAIL)
    d = r.json()
    assert d["decision"] == "allow"
    rec = ss.store.decisions[Store.k(ps.issuer, sdi)]
    assert rec.entry is None


def test_the_identity_class_counts_a_rule_s_fallback() -> None:
    rules = [{"resource": REC, "class": "read_internal", "if_unknown": "read_sensitive"},
             {"resource": MAIL, "scope": "mail.send", "class": "send_external"}]
    ss, ps, clock, s256 = _env(rules=rules)
    sdi, r = _person(ss, ps, clock, s256, REC)
    assert _person_issued(ss, ps, clock, s256, sdi, "pt-5") == 201
    assert [h.action_class for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == [
        "read_sensitive"]


def test_with_no_rule_for_the_resource_the_identity_class_is_the_default() -> None:
    ss, ps, clock, s256 = _env(rules=[], default_class="read_internal",
                               allow_unlisted_resources=True)
    sdi, r = _person(ss, ps, clock, s256, REC)
    assert _person_issued(ss, ps, clock, s256, sdi, "pt-6") == 201
    assert [h.action_class for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == [
        "read_internal"]


def test_a_person_token_at_a_metered_resource_spends_no_ceiling() -> None:
    ss, ps, clock, s256 = _env(resource_budgets={REC: {"unit": "USD", "decimals": 2,
                                                       "max_amount": 100}})
    _, r = _person(ss, ps, clock, s256, REC)
    assert r.json()["decision"] == "allow"


def test_a_person_token_reported_twice_without_a_jti_is_one_act() -> None:
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, s256, REC)
    for _ in range(2):
        assert _person_issued(ss, ps, clock, s256, sdi, "") == 201
    assert len(ss.store.history_for(ps.issuer, SUB, AGENT, s256)) == 1


@pytest.mark.parametrize("field", ["sub", "agent", "mission_s256"])
def test_a_person_token_issuance_naming_others_than_its_decision_is_refused(field: str) -> None:
    ss, ps, clock, s256 = _env()
    assert ps.connect(ss, "someone-else").status == 200
    _, other = ps.propose_and_approve(ss, SUB, AGENT, "# Other", [MAIL, REC], [])
    over = {field: {"sub": "someone-else", "agent": "aauth:x@agent.example",
                    "mission_s256": other}[field]}
    sdi, r = _person(ss, ps, clock, s256, REC)
    b: dict[str, Any] = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi,
                         "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": "pt-7",
                         "aud": REC, "exp": int(clock()) + 60, "mission_s256": s256} | over
    if field == "sub":
        del b["mission_s256"]  # the mission is not that person's: refused before the check
    assert ps.call(ss, "POST", "/event", b).status == 400
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []


def test_a_person_token_issued_after_its_cap_is_spent_not_unbounded() -> None:
    # The allow capped `exp` (L485); a token the PS issues after that time carries the cap
    # as its `exp`, which is then spent, not a slip read as never expiring.
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, s256, REC)
    cap = r.json()["exp"]
    clock.t = cap + 100
    b: dict[str, Any] = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi,
                         "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": "pt-late",
                         "aud": REC, "exp": cap, "mission_s256": s256}
    assert ps.call(ss, "POST", "/event", b).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert h.token_exp == cap


@pytest.mark.parametrize("late", [False, True])
def test_a_person_token_reported_after_a_later_act_floats_to_its_decision(late: bool) -> None:
    # Issued at t, reported after an act recorded since its decision (out of the order
    # Supervision L211 asks for): it may have been used at any moment since the decision.
    # Reported in order, it stands where it was reported.
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, "", REC)
    assert r.json()["decision"] == "allow"
    t = int(clock())
    report = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t,
              "sub": SUB, "agent": AGENT, "jti": "pt-late", "aud": REC, "exp": t + 3600}
    if not late:
        assert ps.call(ss, "POST", "/event", report).status == 201
    clock.t += 1
    assert _take(ss, ps, "", MAIL, scope="mail.read")["decision"] == "allow"
    clock.t += 4
    if late:
        assert ps.call(ss, "POST", "/event", report).status == 201
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.sdi == sdi)
    rec = ss.store.decisions[Store.k(ps.issuer, sdi)]
    assert h.after_n == (rec.recorded_n if late else 0) and (h.after_n > 0) is late


def test_a_person_token_ask_says_once_that_the_resource_may_serve_on_it() -> None:
    ss, ps, clock, s256 = _env()
    assert _take(ss, ps, "", MAIL, scope="mail.send", proposal=EVIL)["decision"] == "allow"
    _, r = _person(ss, ps, clock, "", REC)
    d = r.json()
    assert d["decision"] == "ask"
    assert d["summary"].startswith(f"The agent asks to identify you to {REC}, which may "
                                   f"serve a request on that alone. ")
    assert d["summary"].count("serve a request") == 1


def test_a_report_of_an_identity_check_on_record_needs_no_aud() -> None:
    # The decision under its sdi says where the token goes: a report that leaves `aud` out
    # (Supervision L539 lists it, but the record has it) is taken, and changes nothing, as
    # a person token for a resource that does not serve on identity never does.
    ss, ps, clock, s256 = _env()
    sdi, r = _person(ss, ps, clock, s256, MAIL)
    assert r.json()["decision"] == "allow"
    before = list(ss.store.history_for(ps.issuer, SUB, AGENT, s256))
    assert _person_issued(ss, ps, clock, s256, sdi, "pt-mail", aud=None) == 201
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == before
