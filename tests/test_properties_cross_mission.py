"""Model-based property: across missions, instances and person tokens, asked, never denied.

Hypothesis drives the real server through random interleavings of: new missions of either
of two instances of one agent provider, requests for either half of a prohibited pair by
either instance, inside any mission (its own, or the other's as a call chain) or outside
missions, person tokens the PS reports for a resource that serves on identity, the
person's answers, the PS's issuance reports (in any order it may send them) and the clock.
Each answer is checked against a model written from the rule, not from the code.

The act's own scope: inside a mission, the mission's acts and the acts outside missions of
its chain (the mission's agent, the agent acting, every agent with history in it); outside
missions, the acts of every mission the agent owns or has history in, and the acts outside
missions of that chain (the agent and those missions' agents). Then:

* `deny` exactly when the other half is history on certain evidence in the act's own scope;
* otherwise `ask` when the other half is history anywhere else (another mission, the other
  instance, a person token: all uncertain), or open anywhere (an ask the person is
  deciding, an allow not yet reported issued, the person token a mission's approval has
  the PS issue for the resource that serves on identity, until the PS reports it; both
  instances are of one provider, so every act of the person is in scope);
* otherwise `allow`.

A mission proposal is approved when that approval token would be allowed (a read with
nothing the model would ask about), and asked otherwise.

A pair has no time bound, so history counts however old.
"""
from __future__ import annotations

from dataclasses import dataclass

from conftest import AGENT, SUB, make_env
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, rule

from aauth_supervision_server.store import EXP_SKEW, Store

REC, CHAT, IDR = "https://records.example", "https://chat.example", "https://hr.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": IDR, "class": "read_sensitive"},
         {"resource": CHAT, "class": "send_internal"}]
HALF = {REC: "read", IDR: "read", CHAT: "send"}
AGENTS = [AGENT, "aauth:assistant-2@agent.example"]  # two instances of one provider


@dataclass
class Act:
    sdi: str
    half: str                # read | send
    where: str               # the mission's s256, or "" outside missions
    agent: str
    decision: str            # allow | ask | deny | person (a person token, no decision)
                             # | approval (a mission approval's token: history from then,
                             # as a reported one is, Protocol L863 bounding its window)
    at: float
    resolved: str = ""
    resolved_at: float = 0.0
    issued: bool = False

    @property
    def history(self) -> bool:
        return self.issued or self.decision in ("person", "approval")


class CrossMission(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.ss, self.ps, self.clock = make_env(
            rules=RULES, prohibited_pairs=[["read_sensitive", "send_internal"]],
            prohibited_sequences=[], high_impact=[], budgets={}, resource_budgets={},
            serves_on_identity=[IDR])
        self.missions: list[str] = []
        self.owner: dict[str, str] = {}
        self.acts: list[Act] = []
        assert self.ps.connect(self.ss, SUB).status == 200
        self._propose(AGENT)

    def _open(self, a: Act, now: float) -> bool:
        if a.issued or a.decision in ("deny", "person"):
            return False
        if a.decision == "ask" and not a.resolved:
            return True
        if a.decision == "ask" and a.resolved != "allow":
            return False
        since = a.resolved_at if a.resolved else a.at
        return now < since + Store.OPEN_ISSUANCE + EXP_SKEW

    def _chain(self, m: str) -> set[str]:
        return {self.owner[m]} | {a.agent for a in self.acts if a.where == m and a.history}

    def _missions_of(self, agent: str) -> set[str]:
        return {m for m in self.missions if self.owner[m] == agent or any(
            a.agent == agent and a.where == m and a.history for a in self.acts)}

    def _own(self, a: Act, agent: str, where: str) -> bool:
        """Whether `a` is in the scope an act of `agent` at `where` composes with directly."""
        if where:
            return a.where == where or (not a.where and a.agent in self._chain(where) | {agent})
        mine = self._missions_of(agent)
        chain = {agent}.union(*(self._chain(m) for m in mine))
        return (not a.where and a.agent in chain) or (bool(a.where) and a.where in mine)

    def _expected(self, half: str, agent: str, where: str, now: float) -> str:
        other = [a for a in self.acts if a.half != half]
        history = [a for a in other if a.history]
        if any(a.issued and a.decision not in ("person", "approval") and self._own(a, agent, where)
               for a in history):
            return "deny"
        if history:
            return "ask"
        if any(self._open(a, now) for a in other):
            return "ask"
        return "allow"

    def _propose(self, agent: str) -> None:
        now = self.clock()
        approve = self._expected("read", agent, "", now) == "allow"
        r, s256 = self.ps.propose_and_approve(
            self.ss, SUB, agent, f"# Task {len(self.missions)}", [REC, CHAT, IDR],
            [{"name": "WebSearch", "description": "Search"}])
        assert r.status == 200, r.body
        assert r.json()["decision"] == ("allow" if approve else "ask"), (r.json(), self.acts)
        if not approve:
            return
        assert s256 and s256 not in self.missions
        self.missions.append(s256)
        self.owner[s256] = agent
        self.acts.append(Act(r.json()["sdi"], "read", s256, agent, "approval", now))

    @rule(j=st.integers(0, 1))
    def new_mission(self, j: int) -> None:
        if len(self.missions) < 3:
            self._propose(AGENTS[j])

    @rule(i=st.integers(0, 10))
    def report_approval_token(self, i: int) -> None:
        # The PS reports the person token it issued at approval, under the proposal's sdi.
        waiting = [a for a in self.acts if a.decision == "approval"]
        if not waiting:
            return
        a, now = waiting[i % len(waiting)], self.clock()
        body = {"event": "person_token.issued", "id": self.ps.nid("e"), "sdi": a.sdi,
                "iat": int(now), "sub": SUB, "agent": a.agent, "jti": self.ps.nid("pt"),
                "aud": IDR, "exp": int(now) + 3600, "mission_s256": a.where}
        assert self.ps.call(self.ss, "POST", "/event", body).status == 201
        a.decision = "person"

    def _where(self, i: int) -> str:
        options = [""] + self.missions
        return options[i % len(options)]

    @rule(resource=st.sampled_from([REC, CHAT]), i=st.integers(0, 10), j=st.integers(0, 1))
    def request(self, resource: str, i: int, j: int) -> None:
        agent, where, now = AGENTS[j], self._where(i), self.clock()
        expected = self._expected(HALF[resource], agent, where, now)
        sdi, resp, _ = self.ps.auth_token_request(self.ss, SUB, agent, where, resource)
        assert resp.status == 200, resp.body
        got = resp.json()["decision"]
        assert got == expected, (resource, agent, where, got, expected, self.acts)
        self.acts.append(Act(sdi, HALF[resource], where, agent, got, now))

    @rule(i=st.integers(0, 10), j=st.integers(0, 1))
    def person_token(self, i: int, j: int) -> None:
        # The PS issued a person token for a resource that serves on identity (with no
        # decision request: at mission approval, or under a decision the SS allowed).
        agent, where, now = AGENTS[j], self._where(i), self.clock()
        body = {"event": "person_token.issued", "id": self.ps.nid("e"),
                "sdi": self.ps.nid("d"), "iat": int(now), "sub": SUB, "agent": agent,
                "jti": self.ps.nid("pt"), "aud": IDR, "exp": int(now) + 3600}
        if where:
            body["mission_s256"] = where
        assert self.ps.call(self.ss, "POST", "/event", body).status == 201
        self.acts.append(Act(body["sdi"], "read", where, agent, "person", now))

    @rule(i=st.integers(0, 40), answer=st.sampled_from(["allow", "deny", "abandoned"]))
    def resolve(self, i: int, answer: str) -> None:
        asks = [a for a in self.acts if a.decision == "ask" and not a.resolved]
        if not asks:
            return
        a = asks[i % len(asks)]
        assert self.ps.resolved(self.ss, SUB, a.agent, a.where, a.sdi, answer).status == 201
        a.resolved, a.resolved_at = answer, self.clock()

    @rule(i=st.integers(0, 40))
    def issue(self, i: int) -> None:
        ready = [a for a in self.acts if not a.issued and (
            a.decision == "allow" or a.resolved == "allow")]
        if not ready:
            return
        a = ready[i % len(ready)]
        resource = REC if a.half == "read" else CHAT
        assert self.ps.issued(self.ss, SUB, a.agent, a.where, a.sdi, resource).status == 201
        a.issued = True

    @rule(seconds=st.sampled_from([1, 60, 3600, 3661, 86400]))
    def tick(self, seconds: int) -> None:
        self.clock.t += seconds


CrossMission.TestCase.settings = settings(
    max_examples=300, stateful_step_count=30, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestCrossMission = CrossMission.TestCase
