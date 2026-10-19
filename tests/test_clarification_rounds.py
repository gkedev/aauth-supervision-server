"""A question to the agent is bounded, and what ends it is a decision the PS can act on.

A pluggable policy may ask the agent again after it answers (`decide` is then called
with `clarify=False`, but nothing makes a policy honour it):

- a further round is the same open question, so it does not count against the person's
  cap on open questions;
- once the rounds are spent the act goes to the person, who is told the agent did not
  resolve the question within the round limit;
- a policy that still answers `clarify` then, or answers a value the protocol does not
  define, puts the act to the person: a decision is `allow`, `deny` or `ask`
  (Supervision L262).
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, Clock

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Act, Classification, Decision
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.testing import SimulatedPS

ROUND_LIMIT = "The agent did not resolve the supervisor's question within the round limit."


class Asking:
    """A pluggable policy that asks the agent until it has answered `rounds` times, then
    gives `final`; its mission proposals get `proposal`."""

    r3_member = None
    ask_on_mission_update = False

    def __init__(self, rounds: int, final: str = "allow", proposal: str = "allow") -> None:
        self.rounds, self.final, self.proposal = rounds, final, proposal

    def serves_on_identity(self, resource: str) -> bool:
        return False

    def classify(self, act: Act) -> Classification:
        return Classification("x", "configured", False)

    def decide(self, act: Act, mission: Any, history: Any, reach: Any,
               now: float | None = None, *, clarify: bool = True) -> Decision:
        if act.justification.count("answer") < self.rounds:
            return Decision("clarify", clarification="Why?")
        return Decision(self.final)

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        return Decision(self.proposal)


def _env(policy: Asking, rounds: int = 3) -> tuple[SupervisionServer, SimulatedPS, Clock]:
    clock, fetcher = Clock(), StaticFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    key = SigningKey.generate("ss-key-1")
    ps.ss_jwk = key.public_jwk()
    ss = SupervisionServer(ServerConfig(issuer="https://ss.example", clarification_rounds=rounds,
                                        trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                           policy, JwksUriResolver(fetcher), key, clock=clock)
    assert ps.connect(ss, SUB).status == 200
    return ss, ps, clock


def _act(ss: SupervisionServer, ps: SimulatedPS, clock: Clock, sdi: str = "d-1") -> Any:
    return ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission",
                                             "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                             "action": "Export"})


def _answer(ss: SupervisionServer, ps: SimulatedPS, loc: str) -> Any:
    return ps.call(ss, "POST", loc, {"action": "clarification_response",
                                     "clarification_response": "answer"})


def test_a_further_round_is_the_same_question_not_another_one(monkeypatch: Any) -> None:
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_OPEN_CLARIFICATIONS", 1)
    ss, ps, clock = _env(Asking(2))
    first = _act(ss, ps, clock)
    assert first.status == 202
    loc = first.headers["Location"]
    second = _answer(ss, ps, loc)
    assert (second.status, second.headers.get("Location")) == (202, loc)
    final = _answer(ss, ps, loc)
    assert (final.status, final.json()["decision"]) == (200, "allow")


def test_rounds_spent_put_the_act_to_the_person_with_the_reason() -> None:
    ss, ps, clock = _env(Asking(2, final="allow"), rounds=1)
    first = _act(ss, ps, clock)
    assert first.status == 202
    done = _answer(ss, ps, first.headers["Location"])
    assert done.status == 200
    body = done.json()
    assert body["decision"] == "ask" and body["summary"].startswith(ROUND_LIMIT)
    assert ps.call(ss, "GET", first.headers["Location"]).status == 410


@pytest.mark.parametrize("value", ["clarify", "maybe", ""])
def test_a_decision_the_protocol_does_not_define_goes_to_the_person(value: str) -> None:
    ss, ps, clock = _env(Asking(0, final=value), rounds=0)
    r = _act(ss, ps, clock)
    assert r.status == 200
    body = r.json()
    assert body["decision"] == "ask" and body["summary"]


@pytest.mark.parametrize("value", ["clarify", "maybe"])
def test_a_proposal_decision_the_protocol_does_not_define_goes_to_the_person(value: str) -> None:
    ss, ps, clock = _env(Asking(0, proposal=value))
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Prepare the review",
                                     ["https://mail.example"])
    assert r.status == 200 and s256 == ""
    body = r.json()
    assert body["decision"] == "ask" and body["summary"]
