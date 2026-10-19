"""Model-based stateful test of the decision lifecycle (Hypothesis RuleBasedStateMachine).

A small model says what every request must answer: open, answered, withdrawn or expired
clarifications, terminal asks and allows, retries, polls, withdrawals, the clock, and the
person's `decision.resolved`. Hypothesis drives the real server with random sequences of
those operations and checks each answer, and the stored decision, against the model.

The model catches two lifecycle defects of exactly this shape: a DELETE after the answer
rewriting the answer (SUP-P17), and an unanswered clarification never timing out
(SUP-P15). Reintroducing either one makes this test fail.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from conftest import AGENT, SUB, connected, make_env
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, rule

from aauth_supervision_server.httpsig import HttpResponse, verify_response
from aauth_supervision_server.jwk import key_from_jwk
from aauth_supervision_server.store import Store

HR, MAIL, CAL = "https://hr.example", "https://mail.example", "https://calendar.example"
TIMEOUT = 120


@dataclass
class Req:
    sdi: str
    kind: str                # "clarify" | "ask" | "allow"
    body: dict[str, Any]
    record: str              # the decision the SS must have stored under this sdi
    state: str = "terminal"  # clarify: "open" | "answered" | "withdrawn" | "expired"
    location: str = ""
    deadline: float = 0.0
    answer: bytes = b""      # the terminal body every later retry must repeat
    signature: str = ""      # the signature a retry at /decision must repeat (L316)
    gone: bool = False       # the pending URL returned a terminal response: 410 (L2840)


class Lifecycle(RuleBasedStateMachine):
    questions = Bundle("questions")
    terminal = Bundle("terminal")

    def __init__(self) -> None:
        super().__init__()
        # No compositions: this model is about the lifecycle of each request, so the kinds
        # must not affect each other. With the example policy's pair and sequence, an open
        # act (a question being answered, an allow not yet reported issued) rightly turns
        # a later act it composes with into an ask; that is tested in test_open_acts.py
        # and test_properties_open_acts.py.
        self.ss, self.ps, self.clock = make_env(clarify_missing_justification=True,
                                                prohibited_pairs=[], prohibited_sequences=[])
        self.s256 = connected((self.ss, self.ps, self.clock), resources=(HR, MAIL))
        self.all: list[Req] = []

    def _expire_if_due(self, r: Req) -> None:
        if r.state == "open" and self.clock() >= r.deadline:
            r.state, r.record = "expired", "expired"

    def _call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        resp = self.ps.call(self.ss, method, path, body)
        assert resp.status != 500, resp.body
        return resp

    def _request(self, resource: str, scope: str, kind: str) -> Req:
        sdi, resp, _ = self.ps.auth_token_request(self.ss, SUB, AGENT, self.s256, resource,
                                                  scope=scope)
        r = Req(sdi, kind, self.ps.sent[-1][1], record=kind)
        self.all.append(r)
        return r

    # ------------------------------------------------------------ requests

    @rule(target=questions)
    def ask_a_question(self) -> Req:
        r = self._request(MAIL, "mail.send", "clarify")
        resp = self.ps.sent[-1]
        assert resp[2] == 202
        p = next(p for p in self.ss.store.pending.values() if p.sdi == r.sdi)
        r.state, r.location, r.deadline = "open", f"/pending/{p.id}", self.clock() + TIMEOUT
        return r

    @rule(target=terminal, kind=st.sampled_from(["ask", "allow"]))
    def decide(self, kind: str) -> Req:
        r = self._request(CAL if kind == "ask" else HR, "", kind)
        rec = self.ss.store.decisions[Store.k(self.ps.issuer, r.sdi)]
        assert rec.signed is not None and rec.decision == kind
        r.answer, r.signature = rec.signed.body.encode(), rec.signed.headers["Signature"]
        return r

    @rule(seconds=st.sampled_from([0, 1, 5, 30, 60, 119, 120, 121]))
    def tick(self, seconds: int) -> None:
        self.clock.t += seconds

    # ------------------------------------------------------------ the pending URL

    # Protocol L2840: "Once a terminal response is returned, the pending URL MUST return
    # `410 Gone`". The answer to a clarification reply and a 408 `expired` (terminal, L2414)
    # are terminal responses; a DELETE leaves the URL gone too (L1121).

    @rule(r=questions)
    def answer(self, r: Req) -> None:
        self._expire_if_due(r)
        resp = self._call("POST", r.location, {"action": "clarification_response",
                                               "clarification_response": "for the report"})
        if r.gone or r.state == "withdrawn":
            assert resp.status == 410
        elif r.state == "open":
            assert resp.status == 200 and resp.json()["decision"] == "ask"
            r.state, r.record, r.answer, r.gone = "answered", "ask", resp.body, True
        else:
            assert resp.status == 408 and resp.json()["error"] == "expired"
            r.gone = True

    @rule(r=questions)
    def poll(self, r: Req) -> None:
        self._expire_if_due(r)
        resp = self._call("GET", r.location)
        if r.gone or r.state == "withdrawn":
            assert resp.status == 410
        elif r.state == "open":
            assert resp.status == 202
        else:
            assert resp.status == 408
            r.gone = True

    @rule(r=questions)
    def withdraw(self, r: Req) -> None:
        self._expire_if_due(r)
        resp = self._call("DELETE", r.location)
        if r.gone or r.state == "withdrawn":
            assert resp.status == 410
        elif r.state == "expired":
            assert resp.status == 408
            r.gone = True
        else:
            assert resp.status == 204
            r.record, r.state = "abandoned", "withdrawn"

    # ------------------------------------------------------------ retries and events

    @rule(r=st.one_of(questions, terminal))
    def retry(self, r: Req) -> None:
        # Verified without an age check: Idempotence (L316) requires "the same signed
        # response", so a retry long after carries the original `created` (findings F6).
        req = self.ps.build("POST", "/decision", r.body)
        resp = self.ss.handle(req)
        assert resp.status != 500, resp.body
        if r.answer:  # a terminal answer exists: a retry gets it, byte for byte
            assert resp.status == 200 and resp.body == r.answer
            hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                              resp.body)
            verify_response(hr, req, key_from_jwk(self.ps.ss_jwk),
                            ["@status", "content-type", "content-digest"],
                            expected_issuer="https://ss.example", window=None)
            if r.signature:
                assert resp.headers["Signature"] == r.signature
            return
        self._expire_if_due(r)
        assert resp.status == 202
        if r.state == "open":  # an open question: the same pending URL
            assert resp.headers["Location"] == r.location
        else:
            # A question that is over (withdrawn, timed out) answered nothing: the request
            # is decided again under its sdi, and asks again at a new pending URL.
            assert resp.headers["Location"] != r.location
            r.state, r.location, r.record = "open", resp.headers["Location"], "clarify"
            r.deadline, r.gone = self.clock() + TIMEOUT, False

    # `apply` stays within reaches that do not change later decisions ("bogus" was not
    # offered, so it counts as once), so each kind of request keeps its expected answer.
    @rule(r=st.one_of(questions, terminal), answer=st.sampled_from(["allow", "deny"]),
          apply=st.sampled_from([None, "once", "bogus"]))
    def resolve(self, r: Req, answer: str, apply: str | None) -> None:
        resp = self.ps.resolved(self.ss, SUB, AGENT, self.s256, r.sdi, answer, apply=apply)
        assert resp.status == 201
        if r.record == "ask":  # only an ask is put to the person
            r.record = "resolved_" + answer

    # ------------------------------------------------------------ invariant

    @invariant()
    def records_match_the_model(self) -> None:
        for r in self.all:
            stored = self.ss.store.decisions[Store.k(self.ps.issuer, r.sdi)].decision
            if r.state == "open" and self.clock() >= r.deadline:
                # Expiry is observed lazily, at the next touch of the pending URL.
                assert stored in ("clarify", "expired"), (r, stored)
            else:
                assert stored == r.record, (r, stored)


Lifecycle.TestCase.settings = settings(
    max_examples=200, stateful_step_count=30, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestLifecycle = Lifecycle.TestCase
