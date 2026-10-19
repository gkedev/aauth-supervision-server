"""What a connection, and its end, cover.

Supervision L188: the SS "MUST accept requests only from a PS it has connected for the
`sub` the request names"; L249: "A request after disconnect is answered `unknown_sub`";
L199 and L203: `(iss, sub)` names one person, and the SS keys its state on `sub`. So a
disconnect ends what is open for the pair (a clarification, a connect awaiting the
person's confirmation), and a mission is the mission of the person who has it.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.service import ServerConfig

SUB2 = "c9f0f895fb98ab9159f51fd0297e236d"
MAIL = "https://mail.example"


def _disconnect(ss: Any, ps: Any, clock: Any, sub: str = SUB) -> None:
    r = ps.call(ss, "POST", "/connect", {"action": "disconnect", "id": ps.nid("c"),
                                         "iat": int(clock()), "sub": sub})
    assert r.json() == {"status": "disconnected"}


@pytest.mark.req("SUP-011", "SUP-022")
def test_a_clarification_ends_with_the_connection() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), tools=[{"name": "SendEmail", "description": "x"}])
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission", "iat": int(clock()),
                                          "sub": SUB, "agent": AGENT, "mission_s256": s256,
                                          "action": "SendEmail",
                                          "parameters": {"to": "x@outside.example"}})
    assert r.status == 202
    loc = r.headers["Location"]
    _disconnect(ss, ps, clock)
    # L249: "A request after disconnect is answered `unknown_sub`", at the pending URL too
    # (the PS connects again and resends, L633), not `410`.
    for method, body in (("GET", None), ("POST", {"action": "clarification_response",
                                                  "clarification_response": "A report"}),
                         ("DELETE", None)):
        r = ps.call(ss, method, loc, body)
        assert (r.status, r.json()["error"]) == (404, "unknown_sub")
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "abandoned"


@pytest.mark.req("SUP-022")
def test_a_connect_awaiting_confirmation_ends_with_a_disconnect() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    assert r.status == 202
    code = next(p.code for p in ss.store.pending.values() if p.kind == "connect")
    _disconnect(ss, ps, clock)
    from aauth_supervision_server.httpsig import HttpRequest
    confirm = ss.handle(HttpRequest("POST", "ss.example", "/interaction", {},
                                    f"code={code}&admin_token=operator-secret".encode()))
    assert confirm.status != 200
    assert f"{ps.issuer}|{SUB}" not in ss.store.connections


@pytest.mark.req("SUP-022")
def test_a_connect_poll_after_disconnect_says_so() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    loc = r.headers["Location"]
    p = next(x for x in ss.store.pending.values() if x.kind == "connect")
    from aauth_supervision_server.httpsig import HttpRequest
    ok = ss.handle(HttpRequest("POST", "ss.example", "/interaction", {},
                               f"code={p.code}&admin_token=operator-secret".encode()))
    assert ok.status == 200
    _disconnect(ss, ps, clock)
    poll = ps.call(ss, "GET", loc)
    assert poll.status != 200 or poll.json() != {"status": "connected"}


def test_a_mission_is_the_mission_of_the_person_who_has_it() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(MAIL,))
    assert ps.connect(ss, SUB2).status == 200
    _, r, _ = ps.auth_token_request(ss, SUB2, AGENT, s256, MAIL)
    assert r.status == 404 and r.json()["error"] == "unknown_mission"
    t = ps.call(ss, "POST", f"/mission/{s256}", {"action": "terminated", "id": ps.nid("e"),
                                                  "iat": int(clock()), "sub": SUB2,
                                                  "agent": AGENT, "reason": "completed"})
    assert t.status == 404
    assert ss.store.missions[f"{ps.issuer}|{s256}"].state == "active"


@pytest.mark.req("SUP-001")
@pytest.mark.parametrize("issuer", ["https://ss.example/", "https://SS.example",
                                    "https://ss.example:8443", "https://ss.example/v1"])
def test_the_ss_issuer_is_a_server_identifier(issuer: str) -> None:
    # L157: the issuer conforms to the server identifier rules; it is also the `id` every
    # signed answer names, which a PS compares with the SS it registered (L342).
    with pytest.raises(ValueError, match="issuer must be an https URL"):
        ServerConfig(issuer=issuer)


def test_forwarded_r3_bytes_without_a_digest_to_check_are_not_the_resources_word() -> None:
    # R3 L503: a resource token for R3 carries `r3_s256`. Bytes beside a token without one
    # are bound to nothing the resource signed, so they are not resource evidence.
    from aauth_supervision_server.jwk import b64u
    from aauth_supervision_server.testing import r3_bytes
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=("https://hr.example", MAIL))
    hr = "https://records.example"
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["approved_resources"].append(hr)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, hr)
    assert r.json()["decision"] == "allow"
    ps.issued(ss, SUB, AGENT, s256, sdi, hr)
    raw, _ = r3_bytes({"operations": [{"operationId": "send_email"}],
                       "parameters": {"to": "a@corp.example"}})
    body = {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token(MAIL, "mail.send", "", s256),
            "presented_token": "a.b.c", "r3_proposal": b64u(raw)}
    d = ps.call(ss, "POST", "/decision", body).json()
    assert d["decision"] != "allow", d


def test_a_disconnect_ends_only_what_is_open_for_that_pair() -> None:
    from aauth_supervision_server.store import Pending
    ss, ps, clock = make_env(clarify_missing_justification=True)
    connected((ss, ps, clock), tools=[{"name": "SendEmail", "description": "x"}])
    assert ps.connect(ss, SUB2).status == 200
    others = {
        "other-ps": Pending("other-ps", "https://other.example", "d-o", "clarify", {"sub": SUB}),
        "done": Pending("done", ps.issuer, "d-done", "clarify", {"sub": SUB}, cancelled=True),
        "sub2": Pending("sub2", ps.issuer, "d-s2", "clarify", {"sub": SUB2}),
        "conn2": Pending("conn2", ps.issuer, "", "connect", sub=SUB2),
        "norec": Pending("norec", ps.issuer, "d-gone", "clarify", {"sub": SUB}),
    }
    ss.store.pending.update(others)
    _disconnect(ss, ps, clock)
    assert [k for k, p in ss.store.pending.items() if p.cancelled] == ["done", "norec"]


def _connect(ps: Any, ss: Any, clock: Any, cid: str) -> Any:
    return ps.call(ss, "POST", "/connect", {"action": "connect", "id": cid,
                                            "iat": int(clock()), "sub": SUB})


def test_a_connect_withdrawn_by_a_disconnect_stays_withdrawn() -> None:
    # The person's connect awaiting confirmation is cancelled by the disconnect: a resend
    # of that connect reports the disconnection, and a new connect gets a new code.
    ss, ps, clock = make_env(auto_connect=False)
    first = _connect(ps, ss, clock, "c-first")
    assert first.status == 202
    _disconnect(ss, ps, clock)
    assert _connect(ps, ss, clock, "c-first").json() == {"status": "disconnected"}
    again = _connect(ps, ss, clock, "c-again")
    assert again.status == 202
    assert again.headers["AAuth-Requirement"] != first.headers["AAuth-Requirement"]


def test_a_question_already_answered_keeps_its_answer_through_a_disconnect() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=(MAIL,))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    ans = ps.call(ss, "POST", r.headers["Location"], {"action": "clarification_response",
                                                      "clarification_response": "a note"})
    assert ans.json()["decision"] == "ask"
    _disconnect(ss, ps, clock)
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "ask"
