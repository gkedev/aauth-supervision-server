"""Two PSes the SS trusts are two parties: neither acts for, nor sees, the other's people.

Supervision L188: the SS accepts requests "only from a PS it has connected for the `sub`
the request names". L199: "`(iss, sub)` names one person at one PS", so the same `sub`
value from another PS is another person, with other missions and other decisions. L197:
events are deduplicated on `(iss, id)`. L286, L635: a pending URL answers only the PS that
made the request; any other gets `unknown_pending`. Every test here runs one SS that
trusts two PSes with distinct issuers, both keyed in the same fetcher.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, Clock, policy_cfg

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import SimulatedPS

HR, MAIL = "https://hr.example", "https://mail.example"


def _two(a_auto: bool = True, **policy_over: Any) -> tuple[Any, SimulatedPS, SimulatedPS, Clock]:
    """One SS trusting PS A (https://ps.example) and PS B (https://ps2.example)."""
    clock = Clock()
    fetcher = StaticFetcher()
    a = SimulatedPS(issuer="https://ps.example", clock=clock)
    b = SimulatedPS(issuer="https://ps2.example", clock=clock)
    for p in (a, b):
        p.install(fetcher)
    key = SigningKey.generate("ss-key-1")
    cfg = ServerConfig(issuer="https://ss.example",
                       trusted_ps={a.issuer: TrustedPS(auto_connect=a_auto),
                                   b.issuer: TrustedPS(auto_connect=True)},
                       admin_token="operator-secret")
    ss = SupervisionServer(cfg, Policy(policy_cfg(**policy_over)), JwksUriResolver(fetcher),
                           key, clock=clock)
    for p in (a, b):
        p.ss_jwk = key.public_jwk()
    return ss, a, b, clock


def _mission(ss: Any, ps: SimulatedPS) -> str:
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Prepare the report", [HR, MAIL],
                                     [{"name": "WebSearch", "description": "Search"}])
    assert r.status == 200 and s256
    return s256


def _permission(ps: SimulatedPS, ss: Any, s256: str = "", **over: Any) -> Any:
    body = {"sdi": ps.nid("d"), "act": "permission", "iat": int(ps.clock()), "sub": SUB,
            "agent": AGENT, "action": "WebSearch", "parameters": {"q": "x"}} | over
    if s256:
        body["mission_s256"] = s256
    return ps.call(ss, "POST", "/decision", body)


def _status_and_error(r: Any) -> tuple[int, Any]:
    body = r.json() if r.body else None
    return r.status, body.get("error") if isinstance(body, dict) else None


# ------------------------------------------------------------------ the connection


@pytest.mark.req("SUP-011", "SUP-015")
def test_a_trusted_ps_not_connected_for_the_sub_cannot_act_for_that_person() -> None:
    # L188: "only from a PS it has connected for the `sub`", answered `unknown_sub` (L633).
    # PS B is trusted and could connect, but has not: PS A's connection is not B's.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200
    s256 = _mission(ss, a)
    now = int(clock())
    base = {"iat": now, "sub": SUB, "agent": AGENT}
    tries = {
        "decision": ("/decision", base | {"sdi": "d-b", "act": "permission",
                                          "action": "WebSearch", "parameters": {}}),
        "proposal": ("/mission", base | {"sdi": "d-p", "agent_token": b.agent_token(AGENT),
                                         "description": "# Plan"}),
        "update": (f"/mission/{s256}", base | {"action": "update", "sdi": "d-u",
                                               "description": "x"}),
        "terminated": (f"/mission/{s256}", base | {"action": "terminated", "id": "e-t",
                                                   "reason": "completed"}),
        "event": ("/event", base | {"event": "agent.bound", "id": "e-b"}),
    }
    for name, (path, body) in tries.items():
        assert _status_and_error(b.call(ss, "POST", path, body)) == (404, "unknown_sub"), name
    assert ss.store.missions[Store.k(a.issuer, s256)].state == "active"
    assert Store.k(b.issuer, SUB, AGENT) not in ss.store.agents
    # Once B connects the person it speaks for, its requests are taken.
    assert b.connect(ss, SUB).status == 200
    assert _status_and_error(b.call(ss, "POST", *tries["decision"])) == (200, None)


@pytest.mark.req("SUP-015")
def test_a_disconnect_by_one_ps_leaves_the_other_ps_connected() -> None:
    # L247-L249: the SS records `(iss, sub)`; a disconnect is for that pair, and "a request
    # after disconnect is answered `unknown_sub`" for that pair only.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    r = b.call(ss, "POST", "/connect", {"action": "disconnect", "id": "c-x",
                                        "iat": int(clock()), "sub": SUB})
    assert r.status == 200
    assert _status_and_error(_permission(b, ss)) == (404, "unknown_sub")
    assert _status_and_error(_permission(a, ss)) == (200, None)
    assert Store.k(a.issuer, SUB) in ss.store.connections


# ------------------------------------------------------------------ the person's records


@pytest.mark.req("SUP-011", "SUP-015")
def test_the_same_sub_at_another_ps_is_another_person_without_the_first_ones_missions() -> None:
    # L199: `(iss, sub)` names one person at one PS. B, connected for the same `sub` value,
    # speaks for someone else: A's mission is not one B can act in, change or end.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    s256 = _mission(ss, a)
    base = {"iat": int(clock()), "sub": SUB, "agent": AGENT}
    assert _status_and_error(_permission(b, ss, s256)) == (404, "unknown_mission")
    for action, member in (("update", "description"), ("completion", "summary")):
        r = b.call(ss, "POST", f"/mission/{s256}", base | {"action": action, "sdi": b.nid("d"),
                                                          member: "x"})
        assert _status_and_error(r) == (404, "unknown_mission"), action
    r = b.call(ss, "POST", f"/mission/{s256}", base | {"action": "terminated", "id": "e-t",
                                                      "reason": "completed"})
    assert _status_and_error(r) == (404, "unknown_mission")
    r = b.call(ss, "POST", "/event", base | {"event": "audit.recorded", "id": "e-a",
                                             "mission_s256": s256, "action": "Export",
                                             "parameters": {}})
    assert _status_and_error(r) == (404, "unknown_mission")
    m = ss.store.missions[Store.k(a.issuer, s256)]
    assert (m.state, m.updates, m.history) == ("active", [], [])
    assert _status_and_error(_permission(a, ss, s256)) == (200, None)


@pytest.mark.req("SUP-015")
def test_one_mission_blob_at_two_pses_is_two_missions() -> None:
    # The same approved blob, so the same `s256`, reported by both PSes: two people's
    # missions. B terminating its own ends nothing of A's.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    s256 = _mission(ss, a)
    assert _mission(ss, b) == s256
    r = b.call(ss, "POST", f"/mission/{s256}", {"action": "terminated", "id": "e-t",
                                                "iat": int(clock()), "sub": SUB,
                                                "agent": AGENT, "reason": "completed"})
    assert r.status == 201
    assert ss.store.missions[Store.k(b.issuer, s256)].state == "terminated"
    assert ss.store.missions[Store.k(a.issuer, s256)].state == "active"
    d = _permission(a, ss, s256)
    assert d.status == 200 and d.json()["decision"] == "allow"


@pytest.mark.req("SUP-011", "SUP-015")
def test_another_ps_cannot_answer_the_first_ones_ask() -> None:
    # The person's answer to an `ask` is reported by the PS that asked (L207, L572): B
    # reporting an answer under A's `sdi`, for the same `sub` value and agent, answers
    # nothing of A's and gives no reach to A's later acts.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    s256 = _mission(ss, a)
    sdi, r, _ = a.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    assert r.json()["decision"] == "ask"
    rep = b.call(ss, "POST", "/event", {"event": "decision.resolved", "id": "e-r",
                                        "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                        "sdi": sdi, "answer": "allow", "apply": "always"})
    assert rep.status == 201
    assert ss.store.decisions[Store.k(a.issuer, sdi)].decision == "ask"
    _, again, _ = a.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    assert again.json()["decision"] == "ask"


# ------------------------------------------------------------------ deduplication


@pytest.mark.req("SUP-013")
def test_the_same_event_id_from_two_pses_is_two_events() -> None:
    # L197: "`(iss, id)` is the deduplication key, where `iss` is the PS's verified
    # identity". Each PS mints ids unique within itself, so ids collide across PSes.
    ss, a, b, clock = _two()
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    bound = {"event": "agent.bound", "id": "e-1", "iat": int(clock()), "sub": SUB,
             "agent": AGENT, "agent_iss": "https://agent.example", "agent_sub": AGENT}
    for p in (a, b):
        assert p.call(ss, "POST", "/event", bound).status == 201
    assert {Store.k(a.issuer, SUB, AGENT), Store.k(b.issuer, SUB, AGENT)} <= set(ss.store.agents)
    # A report is deduplicated the same way: B's approval under the id A used for its own
    # is B's mission, recorded, and B's acts in it are decided.
    s256 = _mission(ss, a)
    approved = next(body for path, body, _ in a.sent
                    if path == f"/mission/{s256}" and body.get("action") == "approved")
    r = b.call(ss, "POST", f"/mission/{s256}", approved)
    assert r.status == 201
    assert Store.k(b.issuer, s256) in ss.store.missions
    assert _status_and_error(_permission(b, ss, s256)) == (200, None)
    # Within one PS an id is still one event.
    n = len(ss.store.agents)
    assert a.call(ss, "POST", "/event", bound | {"agent": "aauth:other@agent.example"}
                  ).status == 201
    assert len(ss.store.agents) == n


# ------------------------------------------------------------------ pending URLs


def _replies() -> list[tuple[str, dict[str, Any] | None]]:
    return [("GET", None),
            ("POST", {"action": "clarification_response", "clarification_response": "x"}),
            ("POST", {"action": "updated_request", "presented_token": "a.b.c",
                      "resource_token": "a.b.c"}),
            ("DELETE", None)]


@pytest.mark.req("SUP-027", "REF-054")
@pytest.mark.parametrize("method,body", _replies(), ids=["get", "reply", "update", "delete"])
def test_another_ps_at_a_clarifications_pending_url_is_unknown_pending(
        method: str, body: dict[str, Any] | None) -> None:
    # L286: the PS polls "signing under the same identity that made the request", and the
    # SS "MUST verify that identity and MUST answer `unknown_pending` to a poll from any
    # other"; L635: the same for a clarification reply "or the poller is not the
    # requester"; Protocol L2839: identity verified "on every poll". B is trusted and
    # connected for the same `sub` value, and still is not the requester.
    ss, a, b, clock = _two(clarify_missing_justification=True)
    assert a.connect(ss, SUB).status == 200 and b.connect(ss, SUB).status == 200
    s256 = _mission(ss, a)
    sdi, r, _ = a.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202
    loc, question = r.headers["Location"], r.json()["clarification"]
    assert _status_and_error(b.call(ss, method, loc, body)) == (404, "unknown_pending")
    # A's question is untouched: still open, still A's, still answerable by A.
    assert ss.store.decisions[Store.k(a.issuer, sdi)].decision == "clarify"
    poll = a.call(ss, "GET", loc)
    assert poll.status == 202 and poll.json()["clarification"] == question
    ans = a.call(ss, "POST", loc, {"action": "clarification_response",
                                   "clarification_response": "Weekly status to my team."})
    assert ans.status == 200 and ans.json()["sdi"] == sdi


@pytest.mark.req("SUP-027", "REF-054", "SUP-P04")
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_another_ps_at_a_connects_pending_url_is_unknown_pending(method: str) -> None:
    # A connect awaiting the operator is polled at its pending URL like any deferred
    # response (L244): only by the PS that connected.
    ss, a, b, clock = _two(a_auto=False)
    r = a.connect(ss, SUB)
    assert r.status == 202
    loc = r.headers["Location"]
    assert b.connect(ss, SUB).status == 200
    body = {"action": "clarification_response", "clarification_response": "x"} \
        if method == "POST" else None
    assert _status_and_error(b.call(ss, method, loc, body)) == (404, "unknown_pending")
    assert a.call(ss, "GET", loc).status == 202
    assert Store.k(a.issuer, SUB) not in ss.store.connections
