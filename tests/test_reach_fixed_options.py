"""An `ask` with no `apply_options` still has the three reaches whose meaning is fixed.

Supervision, Reach of an Answer (L599 to L605): when an ask carries no `apply_options`, the
PS MAY offer `once`, `mission` and `always`, "whose meaning is fixed", and the SS
remembers and applies the person's answer (L582). This SS's own policy always names its
options; a pluggable one may not, which `NoOptions` stands for here. A reach the person
gave also settles the act before any question to the agent: the person has already said
yes to acts like it, so the agent is not asked to justify one.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env


class NoOptions:
    """A pluggable policy whose asks name no reach."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def decide(self, *args: Any, **kw: Any) -> Any:
        d = self.inner.decide(*args, **kw)
        d.apply_options = []
        return d


def _env(rounds: int = 0, options: bool = False) -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    if not options:
        ss.policy = NoOptions(ss.policy)
    ss.cfg.clarification_rounds = rounds
    s256 = connected((ss, ps, clock), tools=[{"name": "SendEmail", "description": "mail"}])
    return ss, ps, clock, s256


def _send(ss: Any, ps: Any, clock: Any, s256: str) -> tuple[str, Any]:
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission", "iat": int(clock()),
                                          "sub": SUB, "agent": AGENT, "mission_s256": s256,
                                          "action": "SendEmail",
                                          "parameters": {"to": "x@outside.example"}})
    return sdi, r.json()


@pytest.mark.req("SUP-060", "SUP-P11")
@pytest.mark.parametrize("apply", ["mission", "always"])
def test_a_fixed_reach_to_an_ask_without_options_is_remembered(apply: str) -> None:
    ss, ps, clock, s256 = _env()
    sdi, first = _send(ss, ps, clock, s256)
    assert first["decision"] == "ask" and "apply_options" not in first
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply=apply).status == 201
    assert [r.value for r in ss.store.reach] == [apply]
    assert _send(ss, ps, clock, s256)[1]["decision"] == "allow"


def test_a_value_outside_the_fixed_three_still_counts_once() -> None:
    ss, ps, clock, s256 = _env()
    sdi, _ = _send(ss, ps, clock, s256)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="refundable-under-4k")
    assert ss.store.reach == []
    assert _send(ss, ps, clock, s256)[1]["decision"] == "ask"


def test_a_reach_settles_the_act_before_any_clarification() -> None:
    ss, ps, clock, s256 = _env(rounds=3, options=True)
    sdi, first = _send(ss, ps, clock, s256)
    assert first["decision"] == "clarify"
    pend = next(p for p in ss.store.pending.values() if p.sdi == sdi)
    r = ps.call(ss, "POST", f"/pending/{pend.id}", {"action": "clarification_response",
                                                     "clarification_response": "A report"})
    asked = r.json()
    assert asked["decision"] == "ask" and asked["apply_options"]
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission")
    assert _send(ss, ps, clock, s256)[1]["decision"] == "allow"


def test_a_mission_proposal_ask_sets_no_reach() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/mission", {
        "sdi": sdi, "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# Clean up",
        "tools": [{"name": "DeleteRepo", "description": "x"}], "resources": []})
    assert r.json()["decision"] == "ask" and r.json()["apply_options"] == [
        {"value": "once", "label": "This proposal only"}]
    ps.resolved(ss, SUB, AGENT, "", sdi, "allow", apply="always")
    assert ss.store.reach == []
