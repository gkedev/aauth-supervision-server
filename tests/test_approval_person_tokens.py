"""The person tokens a mission's approval issues are acts where a resource serves on them.

Supervision L417: `approved_resources` are "the resources the PS is to issue person tokens
for at approval" (Protocol L1415). A resource the policy lists in `serves_on_identity`
may serve a request on such a token alone (Protocol L326-L346), so the proposal's answer
is the SS's one decision on that act. Each such token is decided as a `person_token`
decision would be: one the policy would not allow outright is left out of the proposed
refinement and the proposal is put to the person; one it allows is an open act until
`person_token.issued` reports it, so a request arriving in between composes with it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from conftest import AGENT, SUB, make_env

from aauth_supervision_server.jwk import b64u
from aauth_supervision_server.service import APPROVAL_DETAIL, _approval_key
from aauth_supervision_server.store import Store

REC, MAIL = "https://records.example", "https://mail.example"
EVIL = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "drop@evil.example"}}


def _env() -> tuple[Any, Any, Any]:
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC])
    assert ps.connect(ss, SUB).status == 200
    return ss, ps, clock


def _send(ss: Any, ps: Any, *, issue: bool = True) -> str:
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, "", MAIL, scope="mail.send",
                                         proposal=EVIL)
    d = r.json()["decision"]
    if issue and d == "allow":
        assert ps.issued(ss, SUB, AGENT, "", sdi, MAIL, "mail.send", prop).status == 201
    return str(d)


def _propose(ss: Any, ps: Any, clock: Any, resources: list[str]) -> dict[str, Any]:
    r = ps.call(ss, "POST", "/mission", {"sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB,
                                         "agent": AGENT, "agent_token": ps.agent_token(AGENT),
                                         "description": "# read the records",
                                         "resources": resources, "tools": []})
    assert r.status == 200
    return dict(r.json())


def test_a_proposal_whose_approval_token_completes_a_composition_is_asked() -> None:
    ss, ps, clock = _env()
    assert _send(ss, ps) == "allow"                    # an external send, live for an hour
    d = _propose(ss, ps, clock, [REC, MAIL])
    assert d["decision"] == "ask"
    assert REC in d["summary"] and "`send_external`, then `read_sensitive`" in d["summary"]
    assert d["proposed"]["approved_resources"] == [MAIL]    # the refinement leaves it out


def test_an_approval_token_is_an_open_act_until_reported() -> None:
    ss, ps, clock = _env()
    d = _propose(ss, ps, clock, [REC])
    assert d["decision"] == "allow" and d["approved_resources"] == [REC]
    # The PS has not reported the token yet: a send arriving now composes with it.
    assert _send(ss, ps, issue=False) == "ask"


def test_a_proposal_without_such_a_resource_is_allowed() -> None:
    ss, ps, clock = _env()
    assert _send(ss, ps) == "allow"
    assert _propose(ss, ps, clock, [MAIL])["decision"] == "allow"


def _report(ss: Any, ps: Any, clock: Any, sdi: str, s256: str, *, sub: str = SUB,
            agent: str = AGENT) -> int:
    return int(ps.call(ss, "POST", "/event", {
        "event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
        "sub": sub, "agent": agent, "jti": "pt-approval", "aud": REC,
        "exp": int(clock()) + 3600, "mission_s256": s256}).status)


def test_the_approval_token_once_reported_is_history_not_an_open_act() -> None:
    ss, ps, clock = _env()
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# read the records", [REC])
    sdi = r.json()["sdi"]
    assert _report(ss, ps, clock, sdi, s256) == 201
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [(h.resource, h.jti) for h in hist] == [(REC, "pt-approval")]
    opened = ss.store.open_acts(ps.issuer, SUB, AGENT, s256, "", clock())
    assert opened == []                       # not the same read twice, once open


def test_a_report_for_another_agent_leaves_the_approval_token_open() -> None:
    ss, ps, clock = _env()
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# read the records", [REC])
    sdi = r.json()["sdi"]
    assert _report(ss, ps, clock, sdi, "", agent="aauth:other@agent.example") == 201
    (h,) = _approval_acts(ss, ps, s256)
    assert h.resource == REC and h.jti == ""            # not refined by another agent's report


def _approval_acts(ss: Any, ps: Any, s256: str) -> list[Any]:
    """The person tokens booked in the mission at its approval."""
    return [h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
            if h.detail == APPROVAL_DETAIL]


CHAT = "https://chat.example"


def test_the_tokens_of_one_approval_are_decided_together() -> None:
    # Two identity resources whose classes form a pair: issued together, the second
    # completes the pair with the first, as two requests in a row would.
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC, CHAT],
                             rules=[{"resource": REC, "class": "read_sensitive"},
                                    {"resource": CHAT, "class": "send_internal"}],
                             prohibited_pairs=[["read_sensitive", "send_internal"]],
                             prohibited_sequences=[], high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    d = _propose(ss, ps, clock, [REC, CHAT])
    assert d["decision"] == "ask" and CHAT in d["summary"]
    assert d["proposed"]["approved_resources"] == [REC]


def test_the_tokens_of_one_approval_are_decided_together_after_earlier_acts() -> None:
    # With acts already in history, each token allowed still counts for the next.
    other = "https://wiki.example"
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC, CHAT, other],
                             rules=[{"resource": REC, "class": "read_sensitive"},
                                    {"resource": CHAT, "class": "send_internal"},
                                    {"resource": other, "class": "read_internal"}],
                             prohibited_pairs=[["read_sensitive", "send_internal"]],
                             prohibited_sequences=[], high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    assert _propose(ss, ps, clock, [other])["decision"] == "allow"   # an open act
    d = _propose(ss, ps, clock, [REC, CHAT])
    assert d["decision"] == "ask" and d["proposed"]["approved_resources"] == [REC]


def test_an_answer_outside_missions_does_not_reach_a_mission_s_approval_token() -> None:
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[MAIL])
    assert ps.connect(ss, SUB).status == 200
    assert _send(ss, ps) == "allow"                       # a live external send
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "person_token",
                                          "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                          "agent_token": ps.agent_token(AGENT),
                                          "resource": MAIL})
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow", "mission").status == 201
    # The answer covers person tokens for mail outside missions, not a mission's.
    assert _propose(ss, ps, clock, [MAIL])["decision"] == "ask"


def test_an_asked_proposal_decides_its_approval_tokens_too() -> None:
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC],
                             ask_tools=["DeleteRepo"])
    assert ps.connect(ss, SUB).status == 200

    def propose(sdi: str) -> dict[str, Any]:
        r = ps.call(ss, "POST", "/mission", {
            "sdi": sdi, "iat": int(clock()), "sub": SUB, "agent": AGENT,
            "agent_token": ps.agent_token(AGENT), "description": "# work",
            "resources": [REC, MAIL], "tools": [{"name": "DeleteRepo"}]})
        return dict(r.json())
    d = propose("d-asked")
    assert d["decision"] == "ask" and d["proposed"]["approved_resources"] == [REC, MAIL]
    assert Store.k(ps.issuer, "d-asked", REC) in ss.store.decisions   # open until reported
    assert _send(ss, ps, issue=False) == "ask"
    # With a live external send, the asked proposal names the token and leaves it out.
    ss2, ps2, clock2 = make_env(transport="forwarded", serves_on_identity=[REC],
                                ask_tools=["DeleteRepo"])
    assert ps2.connect(ss2, SUB).status == 200
    assert _send(ss2, ps2) == "allow"
    ss, ps, clock = ss2, ps2, clock2
    d = propose("d-asked-2")
    assert d["decision"] == "ask" and "DeleteRepo" in d["summary"] and REC in d["summary"]
    assert d["proposed"]["approved_resources"] == [MAIL]


def test_a_resource_named_twice_is_one_token_and_the_lists_are_bounded() -> None:
    from aauth_supervision_server import service
    ss, ps, clock = _env()
    d = _propose(ss, ps, clock, [REC] * 5)
    assert d["decision"] == "allow"
    assert sum(1 for rec in ss.store.decisions.values() if rec.act == "person_token") == 1
    assert _send(ss, ps) == "ask"                        # the open token composes with it
    held = _propose(ss, ps, clock, [REC, REC])
    assert held["decision"] == "ask" and f"for {REC}, on which " in held["summary"]   # named once
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-big", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# work",
        "resources": [MAIL] * (service.MAX_LIST + 1), "tools": []})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def _asked_env() -> tuple[Any, Any, Any]:
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC],
                             ask_tools=["DeleteRepo"])
    assert ps.connect(ss, SUB).status == 200
    return ss, ps, clock


def _asked(ss: Any, ps: Any, clock: Any, sdi: str) -> dict[str, Any]:
    r = ps.call(ss, "POST", "/mission", {
        "sdi": sdi, "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# work",
        "resources": [REC, MAIL], "tools": [{"name": "DeleteRepo"}]})
    d = dict(r.json())
    assert d["decision"] == "ask"
    return d


def _approved(ss: Any, ps: Any, clock: Any, sdi: str, resources: list[str]) -> str:
    """The PS's report of the mission it built from what the person approved."""
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [], "approved_resources": resources}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "s256": s256, "mission": b64u(raw)})
    assert r.status == 201, r.body
    return s256


def _send_in(ss: Any, ps: Any, s256: str) -> str:
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send",
                                    proposal=EVIL)
    return str(r.json()["decision"])


def test_an_asked_proposal_s_token_is_open_from_the_approval() -> None:
    # The person answers two hours after the proposal; the token is issued at approval.
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-slow")
    clock.t += 2 * 3600
    assert ps.resolved(ss, SUB, AGENT, "", "d-slow", "allow").status == 201
    s256 = _approved(ss, ps, clock, "d-slow", [REC, MAIL])
    assert _send_in(ss, ps, s256) == "ask"


def test_a_resource_the_person_puts_back_is_open_once_approved() -> None:
    # Supervision L422: the person confirms or edits the refinement, so the mission may
    # name a resource the SS left out; its token is issued at approval all the same.
    ss, ps, clock = _env()
    assert _send(ss, ps) == "allow"                      # a live external send
    d = _propose(ss, ps, clock, [REC, MAIL])
    assert d["decision"] == "ask" and d["proposed"]["approved_resources"] == [MAIL]
    sdi = ps.sent[-1][1]["sdi"]
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow").status == 201
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert _send_in(ss, ps, s256) == "ask"


def test_a_declined_or_narrowed_proposal_s_tokens_are_not_open() -> None:
    for answer in ("deny", "abandoned"):
        ss, ps, clock = _asked_env()
        _asked(ss, ps, clock, "d-no")
        assert ps.resolved(ss, SUB, AGENT, "", "d-no", answer).status == 201
        assert _send(ss, ps, issue=False) == "allow"     # no token was issued
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-less")
    assert ps.resolved(ss, SUB, AGENT, "", "d-less", "allow").status == 201
    _approved(ss, ps, clock, "d-less", [MAIL])           # the person left records out
    assert _send(ss, ps, issue=False) == "allow"


def test_one_approval_decides_a_bounded_number_of_tokens(monkeypatch: Any) -> None:
    # Each is a decision under the store lock: past the bound, the rest are put to the
    # person, left out of the refinement, without being decided one by one.
    from aauth_supervision_server import service
    many = [f"https://r{i}.records.example" for i in range(service.MAX_IDENTITY_TOKENS + 3)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"])
    assert ps.connect(ss, SUB).status == 200
    calls = [0]
    decide = ss.policy.decide

    def counted(*a: Any, **k: Any) -> Any:
        calls[0] += 1
        return decide(*a, **k)

    monkeypatch.setattr(ss.policy, "decide", counted)
    d = _propose(ss, ps, clock, many)
    assert calls[0] <= service.MAX_IDENTITY_TOKENS
    assert d["decision"] == "ask"
    assert d["proposed"]["approved_resources"] == many[:service.MAX_IDENTITY_TOKENS]


def test_approval_tokens_opened_at_approval_survive_a_restart(tmp_path: Any) -> None:
    ss, ps, clock = _env()
    ss.store = Store(str(tmp_path / "ss.json"))
    assert ps.connect(ss, SUB).status == 200
    assert _send(ss, ps) == "allow"
    d = _propose(ss, ps, clock, [REC, MAIL])
    sdi = ps.sent[-1][1]["sdi"]
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow").status == 201
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])   # the person put REC back
    assert d["decision"] == "ask"
    again = Store(str(tmp_path / "ss.json"))            # a restart
    assert again.load_error == "" and again.connections
    ss.store = again
    assert _send_in(ss, ps, s256) == "ask"


def test_a_token_approved_after_its_window_is_open_from_the_approval() -> None:
    # The record's first window (from the proposal) has passed, but the person has not
    # answered: the token, decided with the proposal and issued after the answer with no
    # decision of its own, may still come, so a send meanwhile counts it (let go after
    # the hour, an answer after that would find nothing to open). The approval opens its
    # window again.
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-late")
    clock.t += 2 * 3600
    assert _send(ss, ps, issue=False) == "ask"          # still awaited
    assert ps.resolved(ss, SUB, AGENT, "", "d-late", "allow").status == 201
    s256 = _approved(ss, ps, clock, "d-late", [REC, MAIL])
    assert _send_in(ss, ps, s256) == "ask"


def test_a_mission_s_tokens_are_opened_once_and_bounded() -> None:
    # The first `approved` report of a mission books a token for each identity resource it
    # names, past 256 one for each class; a report of the same mission again books none.
    from aauth_supervision_server import service
    other = "https://zz.records.example"                   # of another class
    many = [f"https://r{i:03}.records.example" for i in range(service.MAX_LIST + 5)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"],
                             rules=[{"resource": other, "class": "send_internal"}])
    assert ps.connect(ss, SUB).status == 200
    s256 = _approved(ss, ps, clock, "d-1", many + ["not an identifier", other])
    assert len(_approval_acts(ss, ps, s256)) == service.MAX_LIST + 1  # the other class
    _approved(ss, ps, clock, "d-2", many + ["not an identifier", other])   # reported again
    assert len(_approval_acts(ss, ps, s256)) == service.MAX_LIST + 1


def test_every_token_the_person_put_back_is_open() -> None:
    # More than the 16 decided at the proposal: the person approves them all.
    from aauth_supervision_server import service
    n = 2 * service.MAX_IDENTITY_TOKENS + 1
    many = [f"https://r{i:02}.records.example" for i in range(n)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"])
    assert ps.connect(ss, SUB).status == 200
    d = _propose(ss, ps, clock, many)
    assert d["decision"] == "ask"
    sdi = ps.sent[-1][1]["sdi"]
    assert ps.resolved(ss, SUB, AGENT, "", sdi, "allow").status == 201
    s256 = _approved(ss, ps, clock, sdi, many)
    assert {h.resource for h in _approval_acts(ss, ps, s256)} == set(many)


def _approved_without_sdi(ss: Any, ps: Any, clock: Any, resources: list[str]) -> str:
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [], "approved_resources": resources}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "s256": s256, "mission": b64u(raw)})
    assert r.status == 201, r.body
    return s256


def test_an_approval_reported_without_sdi_opens_its_tokens() -> None:
    # Supervision L443 marks no member of the report REQUIRED; the blob names the
    # resources the PS issued person tokens for (L417).
    ss, ps, clock = _env()
    s256 = _approved_without_sdi(ss, ps, clock, [REC, MAIL])
    assert _send_in(ss, ps, s256) == "ask"
    r = ps.call(ss, "POST", "/event", {"event": "person_token.issued", "id": ps.nid("e"),
                                       "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                       "mission_s256": s256, "aud": REC, "jti": "pt-1",
                                       "exp": int(clock()) + 600})
    assert r.status == 201
    assert not any(k.endswith("#" + REC) and ss.store.decisions[k].entry is not None
                   for k in ss.store.decisions)


def test_a_proposal_abandoned_then_approved_anyway_has_its_tokens_open() -> None:
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-back")
    assert ps.resolved(ss, SUB, AGENT, "", "d-back", "abandoned").status == 201
    s256 = _approved(ss, ps, clock, "d-back", [REC, MAIL])  # issuance is a fact
    assert _send_in(ss, ps, s256) == "ask"


def test_a_token_s_time_is_no_later_than_the_ss_s_clock() -> None:
    ss, ps, clock = _env()
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [], "approved_resources": [REC, MAIL]}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "iat": int(clock()) + 10 * 365 * 86400,
        "sub": SUB, "agent": AGENT, "s256": s256, "mission": b64u(raw)})
    assert r.status == 201
    # The tokens are acts of the approval, at the SS's clock, usable for an hour from the
    # approval's stamp, which the signature window bounds (a PS's clock may run that far
    # ahead, and the `exp` it writes on the token follows it).
    (h,) = _approval_acts(ss, ps, s256)
    assert h.at <= clock() and h.token_exp == int(clock()) + 60 + 3600


def test_a_token_reported_before_the_approval_report_stays_closed() -> None:
    ss, ps, clock = _env()
    d = _propose(ss, ps, clock, [REC, MAIL])
    assert d["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    r = ps.call(ss, "POST", "/event", {"event": "person_token.issued", "id": ps.nid("e"),
                                       "sdi": sdi, "iat": int(clock()), "sub": SUB,
                                       "agent": AGENT, "aud": REC, "jti": "pt-9",
                                       "exp": int(clock()) + 600})
    assert r.status == 201
    _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert ss.store.decisions[Store.k(ps.issuer, sdi, REC)].entry is None


def test_a_token_issued_at_approval_is_an_act_of_its_hour_whether_reported_or_not() -> None:
    # Protocol L863: a person token lives an hour at most, and not past the mission's
    # `expires_at`. Issued at approval, it is an act that may have served a request in that
    # hour, reported or not: a later send composes with it for good, as uncertain.
    ss, ps, clock = _env()
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [], "approved_resources": [REC, MAIL],
            "expires_at": "2026-09-28T13:23:20Z"}                      # in half an hour
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    assert ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "sdi": "d-a", "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "s256": s256, "mission": b64u(raw)}).status == 201
    (h,) = _approval_acts(ss, ps, s256)
    assert h.token_exp == int(clock()) + 1800           # the mission's end, within the hour
    clock.t += 2 * 3600                                  # no report, past both
    assert _send(ss, ps, issue=False) == "ask"


def test_an_expires_at_the_ss_cannot_read_leaves_the_hour() -> None:
    ss, ps, clock = _env()
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [], "approved_resources": [REC], "expires_at": "2026-10-30"}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    assert ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "sdi": "d-b", "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "s256": s256, "mission": b64u(raw)}).status == 201
    (h,) = _approval_acts(ss, ps, s256)
    assert h.token_exp == int(clock()) + 3600
    assert _send(ss, ps, issue=False) == "ask"


def _report_token(ss: Any, ps: Any, clock: Any, sdi: str, aud: str, jti: str,
                  s256: str = "") -> int:
    b = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
         "sub": SUB, "agent": AGENT, "aud": aud, "jti": jti, "exp": int(clock()) + 600}
    if s256:
        b["mission_s256"] = s256
    return int(ps.call(ss, "POST", "/event", b).status)


def _booked(ss: Any, ps: Any, where: str) -> list[str]:
    return [h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, where)
            if h.resource == REC]


def test_a_token_issued_at_approval_is_booked_in_its_mission() -> None:
    # Protocol L1415: each carries the mission's `s256`. A report that leaves it out
    # (L201: OPTIONAL), or comes before `approved`, books it there all the same.
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert _report_token(ss, ps, clock, sdi, REC, "pt-1") == 201
    assert _booked(ss, ps, s256) == [REC] and _booked(ss, ps, "") == []
    ss, ps, clock = _env()                                # reported before the approval
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    assert _report_token(ss, ps, clock, sdi, REC, "pt-2") == 201
    assert _booked(ss, ps, "") == []
    assert _send(ss, ps, issue=False) == "ask"            # open until it is placed
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert _booked(ss, ps, s256) == [REC] and _booked(ss, ps, "") == []


def test_past_the_bound_a_report_of_a_token_is_booked_in_its_mission() -> None:
    from aauth_supervision_server import service
    many = [f"https://r{i:03}.records.example" for i in range(service.MAX_LIST + 2)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"])
    assert ps.connect(ss, SUB).status == 200
    _propose(ss, ps, clock, [MAIL])
    sdi = ps.sent[-1][1]["sdi"]
    s256 = _approved(ss, ps, clock, sdi, many)
    assert len(_approval_acts(ss, ps, s256)) == service.MAX_LIST    # one class past it
    assert _report_token(ss, ps, clock, sdi, many[-1], "pt-last") == 201   # no mission named
    assert [h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
            if h.jti == "pt-last"] == [many[-1]]


def test_a_token_put_back_and_reported_before_the_approval_is_booked_in_the_mission() -> None:
    ss, ps, clock = _env()
    assert _send(ss, ps) == "allow"                       # a live external send
    d = _propose(ss, ps, clock, [REC, MAIL])
    assert d["decision"] == "ask" and d["proposed"]["approved_resources"] == [MAIL]
    sdi = ps.sent[-1][1]["sdi"]                           # REC held: no record of its own
    assert _report_token(ss, ps, clock, sdi, REC, "pt-back") == 201
    assert _booked(ss, ps, "") == []
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])     # the person put it back
    assert _booked(ss, ps, s256) == [REC]


def test_an_open_approval_token_is_no_allocation_at_a_metered_resource() -> None:
    # A person token books no budget (Budgets: it carries no allocation); open, it is no
    # allocation waiting to be reported either.
    inf = "https://inference.example"
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[inf],
                             resource_budgets={inf: {"unit": "USD", "decimals": 2,
                                                     "max_amount": 2500}})
    assert ps.connect(ss, SUB).status == 200
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# work", [inf])
    assert s256
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, inf, scope="inference.completions",
                                    budget={"amount": 1000, "unit": "USD", "decimals": 2})
    assert r.json()["decision"] == "allow", r.json()


def test_an_approval_report_naming_no_sdi_binds_no_proposal() -> None:
    # Supervision L443: the report names the proposal it followed from. With none named,
    # none is guessed: the mission's token is booked from the blob, and a report under the
    # proposal's sdi is held, then booked outside missions past its `exp`: counted twice,
    # never lost, never narrowing the scope.
    for before in (False, True):
        ss, ps, clock = _env()
        assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
        sdi = ps.sent[-1][1]["sdi"]
        if before:
            assert _report_token(ss, ps, clock, sdi, REC, "pt-b") == 201
        s256 = _approved_without_sdi(ss, ps, clock, [REC, MAIL])
        if not before:
            assert _report_token(ss, ps, clock, sdi, REC, "pt-a") == 201
        (h,) = _approval_acts(ss, ps, s256)
        assert h.jti == "", before                        # the blob's, not refined
        assert any(rec.decision == "reported" and rec.entry is not None
                   for rec in ss.store.decisions.values())
        assert _send(ss, ps, issue=False) == "ask"
        clock.t += 2 * 3600
        assert _send(ss, ps, issue=False) == "ask"
        assert [x.jti for x in ss.store.history_for(ps.issuer, SUB, AGENT, "")
                if x.resource == REC] in (["pt-a"], ["pt-b"])


def test_a_token_reported_for_a_resource_the_mission_leaves_out_is_booked_there() -> None:
    # Reported before `approved`, for a resource the person then left out: the report is a
    # fact, an act of the mission it was issued for.
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    assert _report_token(ss, ps, clock, sdi, REC, "pt-x") == 201
    s256 = _approved(ss, ps, clock, sdi, [MAIL])
    assert _booked(ss, ps, s256) == [REC] and _booked(ss, ps, "") == []


def test_an_sdi_shaped_like_the_ss_s_own_keys_reaches_none_of_them() -> None:
    # A PS mints its sdis (Supervision L196): one ending in `#<resource>` is an sdi like any
    # other, for another person or for this mission's own acts.
    ss, ps, clock = _env()
    d = _propose(ss, ps, clock, [REC, MAIL])
    assert d["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    shaped = f"{sdi}#{REC}"
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC, sdi=shaped)
    assert r.status == 200 and r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, shaped, REC).status == 201
    certain = [h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
               if h.resource == REC and h.detail != APPROVAL_DETAIL]
    assert len(certain) == 1                             # its own act, not folded into the token
    assert _send_in(ss, ps, s256) == "deny"             # the certain read completes the pair


def test_a_token_reported_and_then_declined_is_a_fact_either_way() -> None:
    for report_first in (True, False):
        ss, ps, clock = _asked_env()
        _asked(ss, ps, clock, "d-x")
        if report_first:
            assert _report_token(ss, ps, clock, "d-x", REC, "pt-1") == 201
        assert ps.resolved(ss, SUB, AGENT, "", "d-x", "deny").status == 201
        if not report_first:
            assert _report_token(ss, ps, clock, "d-x", REC, "pt-1") == 201
        assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")
                if h.resource == REC] == ["pt-1"], report_first
        assert not any(rec.decision == "reported" and rec.entry is not None
                       for rec in ss.store.decisions.values())


def test_a_report_for_another_agent_naming_the_mission_is_that_agent_s_act() -> None:
    # Another agent's person token in the mission is its own act there, not the approval's
    # token of the mission's agent.
    other = "aauth:assistant-2@agent.example"
    ss, ps, clock = _env()
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# read the records", [REC, MAIL])
    r = ps.call(ss, "POST", "/event", {
        "event": "person_token.issued", "id": ps.nid("e"), "sdi": "d-o", "iat": int(clock()),
        "sub": SUB, "agent": other, "aud": REC, "jti": "pt-o", "exp": int(clock()) + 600,
        "mission_s256": s256})
    assert r.status == 201
    (h,) = _approval_acts(ss, ps, s256)
    assert h.jti == ""                                   # the approval's token, unrefined
    assert [x.agent for x in ss.store.history_for(ps.issuer, SUB, other, s256)
            if x.jti == "pt-o"] == [other]


def test_a_token_reported_twice_past_the_bound_is_one_act() -> None:
    from aauth_supervision_server import service
    many = [f"https://r{i:03}.records.example" for i in range(service.MAX_LIST + 2)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"])
    assert ps.connect(ss, SUB).status == 200
    _propose(ss, ps, clock, [MAIL])
    sdi = ps.sent[-1][1]["sdi"]
    s256 = _approved(ss, ps, clock, sdi, many)
    for _ in range(2):
        assert _report_token(ss, ps, clock, sdi, many[-1], "pt-past") == 201
    assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
            if h.jti == "pt-past"] == ["pt-past"]


def test_a_second_token_of_an_approved_proposal_is_booked_in_its_mission() -> None:
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert _report_token(ss, ps, clock, sdi, REC, "pt-1") == 201
    assert _report_token(ss, ps, clock, sdi, REC, "pt-2") == 201   # another token for it
    assert sorted(h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
                  if h.resource == REC) == ["pt-1", "pt-2"]
    assert not any(rec.decision == "reported" and rec.entry is not None
                   for rec in ss.store.decisions.values())


def test_a_token_held_for_an_approval_that_never_comes_is_a_fact_once_it_expires() -> None:
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    assert _report_token(ss, ps, clock, sdi, REC, "pt-h") == 201      # no `approved` follows
    clock.t += 2 * 3600
    assert _send(ss, ps, issue=False) == "ask"                       # composes, as a fact
    assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")
            if h.resource == REC] == ["pt-h"]
    assert not any(rec.decision == "reported" and rec.entry is not None
                   for rec in ss.store.decisions.values())


def test_a_report_before_approval_is_held_whatever_the_agent_s_other_missions() -> None:
    # A proposal not approved yet, its agent's other mission holding no act of it: held.
    ss, ps, clock = _env()
    assert ps.propose_and_approve(ss, SUB, AGENT, "# mail only", [MAIL])[1]
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    later = ps.sent[-1][1]["sdi"]
    assert _report_token(ss, ps, clock, later, REC, "pt-3") == 201
    assert any(rec.decision == "reported" and rec.entry is not None
               for rec in ss.store.decisions.values())


def test_a_token_reported_before_its_approval_waits_for_its_own_mission() -> None:
    # The PS issues the tokens, records the mission, reports in the order of the acts
    # (Supervision L420, L211): the report comes before `approved`, and the agent has an
    # earlier mission whose approval issued a token for the same resource.
    for with_sdi in (True, False):
        ss, ps, clock = _env()
        _, m1 = ps.propose_and_approve(ss, SUB, AGENT, "# first", [REC, MAIL])
        assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
        sdi = ps.sent[-1][1]["sdi"]
        assert _report_token(ss, ps, clock, sdi, REC, "pt-2") == 201
        assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, m1)
                if h.resource == REC] == [""]               # the first mission's, untouched
        m2 = (_approved(ss, ps, clock, sdi, [REC, MAIL]) if with_sdi
              else _approved_without_sdi(ss, ps, clock, [REC, MAIL]))
        # Linked by the sdi, the held report refines the new mission's token; with none,
        # nothing links them, and the report stays held for its proposal.
        assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, m2)
                if h.resource == REC] == (["pt-2"] if with_sdi else [""]), with_sdi
        assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, m1)
                if h.resource == REC] == [""]


def test_a_held_token_past_its_exp_counts_in_the_decision_that_settles_it() -> None:
    # The decision that finds it past its `exp` books it outside missions; it must count
    # in that very decision, not only in the next one.
    ss, ps, clock = _env()
    _, m1 = ps.propose_and_approve(ss, SUB, AGENT, "# mail", [MAIL])
    assert m1
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    assert _report_token(ss, ps, clock, sdi, REC, "pt-s") == 201      # no `approved` follows
    clock.t += 2 * 3600
    assert [_send_in(ss, ps, m1) for _ in range(2)] == ["ask", "ask"]


def test_a_token_of_an_approval_is_unplaced_in_order_or_reported_late() -> None:
    # In order or reported after acts of the person that took place later (a replay),
    # where the approval's token stood is not worked out.
    ss, ps, clock = _env()
    s256 = _approved(ss, ps, clock, "d-in-order", [REC, MAIL])
    (h,) = _approval_acts(ss, ps, s256)
    assert h.unplaced
    clock.t += 100
    assert ps.call(ss, "POST", "/event", {                # a later act, recorded
        "event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "action": "WebSearch"}).status == 201
    blob = {"agent": AGENT, "approved_at": "2026-10-07T00:00:00Z", "description": "# late",
            "approved_tools": [], "approved_resources": [REC]}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    late = b64u(hashlib.sha256(raw).digest())
    assert ps.call(ss, "POST", f"/mission/{late}", {
        "action": "approved", "id": ps.nid("e"), "sdi": "d-late", "iat": int(clock()) - 50,
        "sub": SUB, "agent": AGENT, "s256": late, "mission": b64u(raw)}).status == 201
    (h,) = _approval_acts(ss, ps, late)
    assert h.unplaced


def test_an_approval_naming_no_sdi_leaves_open_proposals_alone() -> None:
    # Two proposals wait on the person; an approval that names neither binds neither.
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-p1")
    _asked(ss, ps, clock, "d-p2")
    before = {k for k, rec in ss.store.decisions.items()
              if rec.act == "person_token" and rec.entry is not None}
    _approved_without_sdi(ss, ps, clock, [MAIL])
    after = {k for k, rec in ss.store.decisions.items()
             if rec.act == "person_token" and rec.entry is not None}
    assert before and after == before
    assert all(not rec.mission_s256 for rec in ss.store.decisions.values()
               if rec.act == "mission_proposal")


def test_a_held_token_reported_again_keeps_one_record_and_its_widest_window() -> None:
    # Two tokens held for one resource, each reported again (a replay, Supervision L619):
    # each is one act, from its first report to its latest `exp`, booked once.
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    sdi = ps.sent[-1][1]["sdi"]
    t0 = int(clock())

    def report(jti: str, life: int) -> None:
        assert ps.call(ss, "POST", "/event", {
            "event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi,
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "aud": REC, "jti": jti,
            "exp": int(clock()) + life}).status == 201
        clock.t += 1

    report("pt-1", 3600)
    report("pt-2", 600)
    report("pt-1", 30)
    report("pt-2", 600)
    held = sorted((rec.entry.jti, rec.entry.token_exp) for rec in ss.store.decisions.values()
                  if rec.decision == "reported" and rec.entry is not None)
    assert held == [("pt-1", t0 + 3600), ("pt-2", t0 + 1 + 600 + 2)]
    s256 = _approved(ss, ps, clock, sdi, [REC, MAIL])
    assert sorted(h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
                  if h.resource == REC) == ["pt-1", "pt-2"]


def _approval_records(ss: Any, ps: Any, sdi: str) -> list[Any]:
    return [rec for k, rec in ss.store.decisions.items()
            if rec.act == "person_token" and rec.sdi == sdi and rec.entry is not None
            and k == _approval_key(ps.issuer, sdi, rec.entry.resource)]


def test_an_approval_token_open_before_approved_is_unplaced() -> None:
    # Open, before `approved` books it, the token floats as well.
    ss, ps, clock = _env()
    assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
    (rec,) = _approval_records(ss, ps, ps.sent[-1][1]["sdi"])
    assert rec.decision == "allow" and rec.entry.unplaced


def test_an_asked_proposal_s_token_stays_open_until_the_person_answers() -> None:
    # Its token cannot be issued before the person answers: an hour of asking does not
    # end its wait, whatever decision looks at the open set meanwhile.
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-slow")
    (rec,) = _approval_records(ss, ps, "d-slow")
    clock.t += 3700
    _send(ss, ps, issue=False)                         # a decision looks at the open set
    key = _approval_key(ps.issuer, "d-slow", REC)
    assert key in ss.store.open_records(ps.issuer, SUB)
    assert ps.resolved(ss, SUB, AGENT, "", "d-slow", "allow").status == 201
    assert rec.resolved_at >= clock() - 1 and key in ss.store.open_records(ps.issuer, SUB)


def test_an_answered_proposal_s_token_stays_open_while_it_could_still_be_live() -> None:
    # Issued at approval (within the hour after the answer) and living up to an hour
    # (Protocol L863): until `approved` books it, it counts for two hours after the answer.
    ss, ps, clock = _asked_env()
    _asked(ss, ps, clock, "d-answered")
    assert ps.resolved(ss, SUB, AGENT, "", "d-answered", "allow").status == 201
    key = _approval_key(ps.issuer, "d-answered", REC)
    clock.t += 5400                                    # an hour and a half later
    assert _send(ss, ps, issue=False) == "ask"
    assert key in ss.store.open_records(ps.issuer, SUB)
    clock.t += 2000                                    # past both hours and the margin
    assert _send(ss, ps, issue=False) == "allow"
    assert key not in ss.store.open_records(ps.issuer, SUB)


def test_an_approval_finds_its_tokens_whatever_decision_looked_before() -> None:
    # `approved` long after the tokens could be live: it finds the same records whether or
    # not a decision cleared the open set in between (as after a restart, which indexes
    # every record again).
    entries = []
    for looked in (False, True):
        ss, ps, clock = _env()
        assert _propose(ss, ps, clock, [REC, MAIL])["decision"] == "allow"
        sdi = ps.sent[-1][1]["sdi"]
        clock.t += 3 * 3600
        if looked:
            _send(ss, ps, issue=False)
        _approved(ss, ps, clock, sdi, [REC, MAIL])
        (rec,) = (r for k, r in ss.store.decisions.items()
                  if k == _approval_key(ps.issuer, sdi, REC))
        entries.append(rec.entry is None)
    assert entries[0] == entries[1]


def test_a_held_token_reported_again_long_after_is_placed_by_the_window() -> None:
    # An approval's person token, held before the approval, reported at once and again
    # 400 s later under a new event id: from then on it is placed anywhere the signature
    # window allows around its stamp, so `at` reaches that far past it.
    ss, ps, clock = make_env(serves_on_identity=[REC])
    ps.clock = lambda: clock.t + 30
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/mission", {
        "sdi": sdi, "iat": int(ps.clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# plan",
        "tools": [{"name": "WebSearch", "description": "x"}], "resources": [REC, MAIL]})
    assert r.json()["decision"] == "allow"
    stamp = int(ps.clock())
    ev = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": stamp,
          "sub": SUB, "agent": AGENT, "jti": "pt-1", "aud": REC, "exp": stamp + 3600}
    assert ps.call(ss, "POST", "/event", ev).status == 201
    clock.t = t + 400
    assert ps.call(ss, "POST", "/event", dict(ev, id=ps.nid("e"))).status == 201
    (e,) = (rec.entry for rec in ss.store.decisions.values()
            if rec.act == "person_token" and rec.entry is not None and rec.entry.jti == "pt-1")
    assert e.wide and e.at >= e.iat + ss.cfg.signature_window + ss.cfg.transit_allowance + 2


def test_past_the_bound_a_token_with_other_classes_is_still_booked() -> None:
    # Past 256 identity resources one token is booked for each kind of act: a resource
    # whose most severe class is booked already, but which may also be of another class,
    # is a kind of its own.
    from aauth_supervision_server import service
    other = "https://zy.records.example"
    many = [f"https://r{i:03}.records.example" for i in range(service.MAX_LIST + 5)]
    ss, ps, clock = make_env(transport="forwarded",
                             serves_on_identity=["https://*.records.example"],
                             rules=[{"resource": other, "scope": "x", "class": "send_internal"},
                                    {"resource": "https://*.records.example",
                                     "class": "write"}])
    assert ps.connect(ss, SUB).status == 200
    s256 = _approved(ss, ps, clock, "d-1", many + [other])
    acts = _approval_acts(ss, ps, s256)
    assert len(acts) == service.MAX_LIST + 1
    assert [a.cls for a in next(h for h in acts if h.resource == other).blind] == [
        "send_internal"]


def test_the_approval_s_ask_speaks_of_that_token_and_says_it_once() -> None:
    # What the policy says of the act it decided is said of the token the approval would
    # issue: "this one" too, and the opening already says the resource may serve on it.
    ss, ps, clock = _env()
    assert _send(ss, ps) == "allow"
    s = _propose(ss, ps, clock, [REC, MAIL])["summary"]
    assert "this one" not in s and "this act" not in s.lower()
    assert "not of that token" in s and s.count("may serve") == 1


def test_an_approval_that_holds_back_several_tokens_says_which_each_reason_is_about() -> None:
    hr = "https://hr.example"
    ss, ps, clock = make_env(transport="forwarded", serves_on_identity=[REC, hr])
    assert ps.connect(ss, SUB).status == 200
    assert _send(ss, ps) == "allow"
    s = _propose(ss, ps, clock, [REC, hr, MAIL])["summary"]
    assert "that token" not in s and "this act" not in s.lower()
    assert f"the token for {REC} may complete" in s or f"each of the tokens for {REC}" in s
    assert f"the token for {hr} may complete" in s or f"each of the tokens for {REC}, {hr}" in s
