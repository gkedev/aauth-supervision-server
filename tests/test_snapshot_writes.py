"""The snapshot is written for a request that changed state, and only then.

Writing it serializes the whole state under the store lock, so a request that changes
nothing (a poll, a duplicate event or connect, a retried decision) does not write it.
A refusal can follow a change (a clarification past its deadline is settled, then
answered `expired`): that change is written like any other, so a restart answers as the
running SS would.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Store

MAIL = "https://mail.example"


def _counting(ss: Any) -> list[int]:
    n = [0]
    save = ss.store.save

    def counted() -> None:
        n[0] += 1
        save()

    ss.store.save = counted
    return n


def test_a_request_that_changes_nothing_writes_nothing(tmp_path: Path) -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True, auto_connect=False)
    ss.store = Store(str(tmp_path / "ss.json"))
    writes = _counting(ss)
    r = ps.connect(ss, SUB)
    assert r.status == 202 and writes[0] == 1             # a connect awaiting the person
    assert ps.call(ss, "GET", r.headers["Location"]).status == 202
    assert writes[0] == 1                                 # a poll
    ss.cfg.trusted_ps[ps.issuer].auto_connect = True
    s256 = connected((ss, ps, clock))
    before = writes[0]
    _, d, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert d.status == 202 and writes[0] == before + 1    # a question to the agent
    loc = d.headers["Location"]
    assert ps.call(ss, "GET", loc).status == 202          # its poll
    ev = {"event": "agent.bound", "id": "e-1", "iat": int(clock()), "sub": SUB, "agent": AGENT}
    assert ps.call(ss, "POST", "/event", ev).status == 201
    assert writes[0] == before + 2
    assert ps.call(ss, "POST", "/event", ev).status == 201    # the same event again
    _, a, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert a.status == 200 and writes[0] == before + 3        # a decision
    again = ps.call(ss, "POST", "/decision", ps.sent[-1][1])   # a retry of that decision
    assert again.status == 200 and writes[0] == before + 3


def test_an_expired_question_is_answered_the_same_after_a_restart(tmp_path: Path) -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.store = Store(str(tmp_path / "ss.json"))
    s256 = connected((ss, ps, clock))
    ss.cfg.clarification_timeout = 5
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    clock.t += 10
    poll = ps.call(ss, "GET", loc)
    assert poll.status == 408 and poll.json()["error"] == "expired"
    ss.store = Store(str(tmp_path / "ss.json"))           # a restart reads the snapshot
    assert ps.call(ss, "GET", loc).status == 410


def test_repeats_and_gone_urls_write_nothing(tmp_path: Path) -> None:
    ss, ps, clock = make_env()
    ss.store = Store(str(tmp_path / "ss.json"))
    writes = _counting(ss)
    body = {"action": "connect", "id": "c-1", "iat": int(clock()), "sub": SUB}
    assert ps.call(ss, "POST", "/connect", body).status == 200 and writes[0] == 1
    assert ps.call(ss, "POST", "/connect", body).status == 200 and writes[0] == 1
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# plan", ["https://hr.example"])
    n = writes[0]
    _, raw = ps._last_blob
    report = {"action": "approved", "id": "e-approved", "sdi": "d-x", "iat": int(clock()),
              "sub": SUB, "agent": AGENT, "s256": s256}
    from aauth_supervision_server.jwk import b64u
    report["mission"] = b64u(raw)
    assert ps.call(ss, "POST", f"/mission/{s256}", report).status == 201
    assert writes[0] == n + 1
    assert ps.call(ss, "POST", f"/mission/{s256}", report).status == 201   # again
    assert writes[0] == n + 1
    ss2, ps2, c2 = make_env(clarify_missing_justification=True)
    ss2.store = Store(str(tmp_path / "ss2.json"))
    s2 = connected((ss2, ps2, c2))
    w2 = _counting(ss2)
    _, q, _ = ps2.auth_token_request(ss2, SUB, AGENT, s2, MAIL, scope="mail.send")
    assert ps2.call(ss2, "DELETE", q.headers["Location"]).status == 204
    k = w2[0]
    assert ps2.call(ss2, "GET", q.headers["Location"]).status == 410 and w2[0] == k


def test_a_retry_after_a_failed_write_writes_the_state(tmp_path: Path, monkeypatch: Any) -> None:
    # The state changed in memory, its write failed (another process held the file), and
    # the PS retries: the retry is answered from memory, and must write what is unwritten.
    import os

    from aauth_supervision_server import store as store_module
    ss, ps, clock = make_env()
    ss.store = Store(str(tmp_path / "ss.json"))
    s256 = connected((ss, ps, clock))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert r.json()["decision"] == "allow"
    real = os.replace

    def held(src: Any, dst: Any) -> None:
        raise PermissionError(13, "held by another process", str(dst))

    monkeypatch.setattr(store_module.os, "replace", held)
    monkeypatch.setattr(store_module.time, "sleep", lambda s: None)
    assert ps.issued(ss, SUB, AGENT, s256, sdi, "https://hr.example").status == 500
    monkeypatch.setattr(store_module.os, "replace", real)
    retry = ps.sent[-1][1]
    assert ps.call(ss, "POST", "/event", retry).status == 201
    again = Store(str(tmp_path / "ss.json"))                # a restart
    assert [h.sdi for h in again.missions[Store.k(ps.issuer, s256)].history] == [sdi]
