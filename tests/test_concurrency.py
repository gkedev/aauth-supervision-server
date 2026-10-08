"""Concurrent delivery: the PS (or several PS workers) may send the same request at once.

The listener is a ThreadingHTTPServer, so `handle` runs on many threads. Deduplication
and idempotence must hold under that concurrency, not only for sequential retries:
the same event delivered N times at once is recorded once, and the same decision
request delivered N times at once gets one answer.
"""
from __future__ import annotations

import threading
from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Store

N = 16
CAL = "https://calendar.example"


def at_once(n: int, fn: Any) -> list[Any]:
    """Run fn() on n threads released together; return every result."""
    gate = threading.Barrier(n)
    out: list[Any] = [None] * n

    def worker(i: int) -> None:
        gate.wait()
        out[i] = fn()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return out


def test_the_same_event_delivered_at_once_is_recorded_once() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c), resources=("https://hr.example",))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "ask"
    req = ps.build("POST", "/event", {"event": "decision.resolved", "id": "e-once",
                                      "sdi": sdi, "iat": 1, "sub": SUB, "agent": AGENT,
                                      "mission_s256": s256, "answer": "allow",
                                      "apply": "mission"})
    statuses = at_once(N, lambda: ss.handle(req).status)
    assert statuses == [201] * N
    assert len(ss.store.reach) == 1  # one standing reach, not N
    assert ss.store.decisions[Store.k(ps.issuer, sdi)].decision == "resolved_allow"


def test_the_same_issuance_delivered_at_once_joins_history_once() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert r.json()["decision"] == "allow"
    req = ps.build("POST", "/event", {"event": "auth_token.issued", "id": "e-iss", "sdi": sdi,
                                      "iat": 1, "sub": SUB, "agent": AGENT, "jti": "at-1",
                                      "aud": "https://hr.example", "exp": 2_000_000_000,
                                      "mission_s256": s256})
    assert at_once(N, lambda: ss.handle(req).status) == [201] * N
    assert [h.sdi for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == [sdi]


def test_the_same_decision_request_at_once_gets_one_answer() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi = "d-concurrent"
    req = ps.build("POST", "/decision", {
        "sdi": sdi, "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "mission_s256": s256,
        "resource_token": ps.resource_token("https://hr.example", mission_s256=s256),
        "presented_token": "a.b.c"})
    answers = at_once(N, lambda: ss.handle(req))
    assert {a.status for a in answers} == {200}
    assert len({(a.body, a.headers["Signature"]) for a in answers}) == 1
    assert len([k for k in ss.store.decisions if k.endswith(sdi)]) == 1


def test_concurrent_clarifications_share_one_pending_url() -> None:
    ss, ps, c = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, c))
    req = ps.build("POST", "/decision", {
        "sdi": "d-q", "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "mission_s256": s256,
        "resource_token": ps.resource_token("https://mail.example", "mail.send", "", s256),
        "presented_token": "a.b.c"})
    answers = at_once(N, lambda: ss.handle(req))
    assert {a.status for a in answers} == {202}
    assert len({a.headers["Location"] for a in answers}) == 1
    assert len([p for p in ss.store.pending.values() if p.sdi == "d-q"]) == 1


def test_rate_limit_counts_every_concurrent_request() -> None:
    ss, ps, c = make_env()
    ss.cfg.rate_limit_per_minute = 5
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-r", "iat": 1, "sub": SUB})
    statuses = at_once(N, lambda: ss.handle(req).status)
    assert statuses.count(200) == 5 and statuses.count(429) == N - 5
