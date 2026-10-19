"""Model-based property: no prohibited pair takes effect without the person seeing it.

The rule behind open acts: the SS never permits a composition nobody saw. Hypothesis
drives the real server with random interleavings of requests for the two halves of a
prohibited pair, the person's answers, the PS's issuance reports (in any order the PS
may legitimately send them, Supervision L211) and the clock. For every pair that ends up
both issued, the act the SS answered second must have been put to the person (an ask they
allowed), unless the first was not open when the second was decided. A direct allow
caps its token's `exp` an hour after the decision (Supervision L508), so one issued later
is spent; what remains is an ask the person allowed whose token the PS reported more than
an hour after the answer (Protocol L1775), the residual the README states. And the SS
denies only on certain evidence: a deny needs the other half issued before it.
"""
from __future__ import annotations

from dataclasses import dataclass

from conftest import AGENT, SUB, connected, make_env
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from aauth_supervision_server.store import EXP_SKEW, Store

REC, CHAT = "https://records.example", "https://chat.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": CHAT, "class": "send_internal"}]


@dataclass
class Act:
    sdi: str
    resource: str
    decision: str            # what the SS answered: allow | ask | deny
    at: float                # when it answered
    resolved: str = ""       # the person's answer to an ask
    resolved_at: float = 0.0
    issued_at: float | None = None
    open_at_decision: tuple[str, ...] = ()  # sdis of the other half open when decided
    step: int = 0            # when the SS answered, in the order of operations
    issued_step: int = 0     # when the PS reported it issued, likewise

    def awaited_since(self) -> float:
        return self.resolved_at if self.resolved else self.at


class OpenActs(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.ss, self.ps, self.clock = make_env(
            rules=RULES, prohibited_pairs=[["read_sensitive", "send_internal"]],
            prohibited_sequences=[], high_impact=[], budgets={}, resource_budgets={})
        self.s256 = connected((self.ss, self.ps, self.clock), resources=(REC, CHAT))
        self.acts: list[Act] = []
        self.steps = 0

    def _open(self, a: Act, now: float) -> bool:
        """Whether `a` may still take effect without the SS having been told (the model of
        an open act, written from the rule, not from the code)."""
        if a.issued_at is not None or a.decision == "deny":
            return False
        if a.decision == "ask" and not a.resolved:
            return True
        if a.decision == "ask" and a.resolved != "allow":
            return False
        return now < a.awaited_since() + Store.OPEN_ISSUANCE + EXP_SKEW

    @staticmethod
    def _effective(a: Act) -> bool:
        """Whether `a`'s token could be used at all. The PS applies the `exp` a direct
        allow carries (Supervision L508), capped an hour after the decision, so a token it
        issues later is spent on issue, beyond the usable margin past `exp`."""
        assert a.issued_at is not None
        exp = int(a.issued_at) + 3600
        if a.decision == "allow":
            exp = min(exp, int(a.at) + Store.OPEN_ISSUANCE)
        return a.issued_at < exp + EXP_SKEW

    @rule(resource=st.sampled_from([REC, CHAT]))
    def request(self, resource: str) -> None:
        now = self.clock()
        others = tuple(a.sdi for a in self.acts if a.resource != resource and self._open(a, now))
        issued_other = any(a.resource != resource and a.issued_at is not None for a in self.acts)
        sdi, resp, _ = self.ps.auth_token_request(self.ss, SUB, AGENT, self.s256, resource)
        assert resp.status == 200, resp.body
        d = resp.json()["decision"]
        if d == "deny":
            # Certain evidence only: the other half was reported issued.
            assert issued_other
        if issued_other:
            assert d == "deny"
        elif others:
            assert d == "ask"
        else:
            assert d == "allow"
        self.acts.append(Act(sdi, resource, d, now, open_at_decision=others,
                             step=self._next()))

    def _next(self) -> int:
        self.steps += 1
        return self.steps

    @rule(i=st.integers(0, 40), answer=st.sampled_from(["allow", "deny", "abandoned"]))
    def resolve(self, i: int, answer: str) -> None:
        asks = [a for a in self.acts if a.decision == "ask" and not a.resolved]
        if not asks:
            return
        a = asks[i % len(asks)]
        assert self.ps.resolved(self.ss, SUB, AGENT, self.s256, a.sdi, answer).status == 201
        a.resolved, a.resolved_at = answer, self.clock()

    @rule(i=st.integers(0, 40))
    def issue(self, i: int) -> None:
        # The PS issues what it may: an allow, or an ask the person allowed.
        ready = [a for a in self.acts if a.issued_at is None and (
            a.decision == "allow" or a.resolved == "allow")]
        if not ready:
            return
        a = ready[i % len(ready)]
        assert self.ps.issued(self.ss, SUB, AGENT, self.s256, a.sdi, a.resource).status == 201
        a.issued_at, a.issued_step = self.clock(), self._next()

    @rule(seconds=st.sampled_from([1, 60, 600, 3599, 3600, 3601]))
    def tick(self, seconds: int) -> None:
        self.clock.t += seconds

    @invariant()
    def no_pair_takes_effect_unseen(self) -> None:
        done = [(i, a) for i, a in enumerate(self.acts)
                if a.issued_at is not None and self._effective(a)]
        for i, x in done:
            for j, y in done:
                if x.resource == y.resource or i >= j:
                    continue
                # y was answered second. If the SS let it through without asking, x
                # cannot have been open then, or the person never saw the pair. x was not
                # history yet (else y is denied), so it was issued after y was decided.
                # A direct allow issued that late is spent (its `exp` cap), so x can only
                # be an ask the person allowed, issued over an hour after the answer: the
                # residual the README states.
                if y.decision == "allow":
                    assert x.sdi not in y.open_at_decision
                    assert x.issued_step > y.step, (x, y)
                    assert x.decision == "ask", (x, y)
                    assert y.at >= x.awaited_since() + Store.OPEN_ISSUANCE + EXP_SKEW, (x, y)


OpenActs.TestCase.settings = settings(
    max_examples=150, stateful_step_count=25, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestOpenActs = OpenActs.TestCase
