"""A clarification past its deadline keeps no request body once the person's next question
is considered.

A question past its deadline is over (Core, Clarification Required), but its request was
dropped only when something settled it: a poll of its URL, or a later decision whose
composition scope reached its record. The person's open questions are counted for the cap
on every new question, and that count settles each one it finds over, so expired bodies
do not pile up beyond the cap whatever agent or scope asks next.
"""
from __future__ import annotations

from typing import Any

from conftest import SUB, make_env

from aauth_supervision_server.testing import make_jwt

MAIL = "https://mail.example"


def _clarify(ss: Any, ps: Any, clock: Any, agent: str) -> int:
    body = {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": agent, "agent_token": ps.agent_token(agent),
            "resource_token": ps.resource_token(MAIL, "mail.send"),
            "presented_token": make_jwt(ps.key, "aa-person+jwt", {
                "iss": ps.issuer, "aud": MAIL, "sub": "p", "iat": int(clock())}),
            "x_pad": "A" * 1000}
    return int(ps.call(ss, "POST", "/decision", body).status)


def test_expired_questions_are_settled_when_the_next_one_is_counted() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    assert ps.connect(ss, SUB).status == 200
    assert [_clarify(ss, ps, clock, "aauth:a@p1.example") for _ in range(3)] == [202] * 3
    clock.t += ss.cfg.clarification_timeout + 1
    # Another agent, of another provider, outside missions: its scope never reaches them.
    assert _clarify(ss, ps, clock, "aauth:b@p2.example") == 202
    held = [p for p in ss.store.pending.values() if p.kind == "clarify" and p.request]
    assert len(held) == 1 and held[0].request["agent"] == "aauth:b@p2.example"
    # Polling an expired one still says it expired, then that it is gone.
    old = next(p for p in ss.store.pending.values() if not p.request)
    assert ps.call(ss, "GET", f"/pending/{old.id}").status == 408
    assert ps.call(ss, "GET", f"/pending/{old.id}").status == 410
