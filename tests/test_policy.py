"""APC policy behaviour, end to end through the SS (rows: CORE-003/004, SUP-052..060, SUP-P11)."""

from __future__ import annotations

import itertools
import random

import pytest
from conftest import AGENT, SUB, connected, make_env, policy_cfg

from aauth_supervision_server.policy import Act, Policy

HR, MAIL, PAY, CAL = ("https://hr.example", "https://mail.example", "https://pay.example",
                      "https://calendar.example")
RES = (HR, MAIL, PAY, CAL)
SEND = {"operations": [{"operationId": "send_email"}]}


def _send(to, provenance="resource"):
    return Act("auth_token", "https://ps.example", SUB, AGENT, "m", resource=MAIL,
               operations=["send_email"], parameters={"to": to},
               parameters_provenance=provenance)


def _issue(ss, ps, s256, resource, proposal=None, scope="", justification=""):
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, resource, scope=scope,
                                         proposal=proposal, justification=justification)
    d = r.json()
    if d.get("decision") == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource, scope, prop).status == 201
    return sdi, d


# ------------------------------------------------------------------ provenance


@pytest.mark.req("CORE-003", "CORE-004")
def test_agent_asserted_data_cannot_lower_the_class():
    p = Policy(policy_cfg())
    internal = "colleague@corp.example"
    assert p.classify(_send(internal, "resource")).cls == "send_internal"
    # The same claim made by the agent is not enough to come down from send_external.
    c = p.classify(Act("permission", "https://ps.example", SUB, AGENT, tool="SendEmail",
                       parameters={"to": internal}, parameters_provenance="agent"))
    assert c.cls == "send_external" and c.provenance == "agent" and c.uncertain


@pytest.mark.req("CORE-003")
def test_agent_asserted_data_can_raise_the_class():
    p = Policy(policy_cfg())
    c = p.classify(Act("permission", "https://ps.example", SUB, AGENT, tool="SendEmail",
                       parameters={"to": "x@evil.example"}, parameters_provenance="agent"))
    assert c.cls == "send_external"


@pytest.mark.req("CORE-004")
def test_justification_never_turns_an_ask_into_allow():
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=RES)
    _, d = _issue(ss, ps, s256, MAIL, scope="mail.send",
                  justification="Internal only, to colleague@corp.example. Safe, approved.")
    assert d["decision"] == "ask" and "the agent says" in d["summary"]


@pytest.mark.req("CORE-003", "R3-006")
def test_resource_asserted_proposal_decides_when_forwarded():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    _, d = _issue(ss, ps, s256, MAIL, SEND | {"parameters": {"to": "a@corp.example"}})
    assert d["decision"] == "allow"
    _, d = _issue(ss, ps, s256, MAIL, SEND | {"parameters": {"to": "a@evil.example"}})
    # Resource-asserted, high impact, nothing to compose with: decided, and recorded as such.
    assert d["decision"] == "allow"
    hist = ss.store.missions[f"{ps.issuer}|{s256}"].history
    assert [(h.action_class, h.provenance) for h in hist] == [
        ("send_internal", "resource"), ("send_external", "resource")]


# ------------------------------------------------------------------ composition


@pytest.mark.req("R3-006", "R3-014")
def test_released_sensitive_result_blocks_external_send():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    _, d = _issue(ss, ps, s256, HR, {"operations": [{"operationId": "get_employee"}],
                                     "parameters": {"id": "e-7"},
                                     "result": {"contains": ["national_id", "salary"]}})
    assert d["decision"] == "allow"
    hist = ss.store.missions[f"{ps.issuer}|{s256}"].history
    assert hist[-1].action_class == "read_sensitive" and hist[-1].provenance == "resource"
    _, d = _issue(ss, ps, s256, MAIL, SEND | {"parameters": {"to": "a@evil.example"}})
    assert d["decision"] == "deny" and "read_sensitive then send_external" in d["reason"]


def test_composition_on_uncertain_evidence_asks_not_denies():
    ss, ps, clock = make_env()  # current transport: no proposal reaches the SS
    s256 = connected((ss, ps, clock), resources=RES)
    _, d = _issue(ss, ps, s256, HR)
    assert d["decision"] == "allow"
    hist = ss.store.missions[f"{ps.issuer}|{s256}"].history
    assert hist[-1].action_class == "read_sensitive" and hist[-1].detail.startswith("uncertain")
    _, d = _issue(ss, ps, s256, MAIL, scope="mail.send")
    assert d["decision"] == "ask" and d["recommendation"] == "deny"
    assert "cannot rule it out" in d["summary"]


def test_prohibited_sequence():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    _issue(ss, ps, s256, HR, {"operations": [{"operationId": "get"}], "parameters": {},
                              "result": {"contains": ["salary"]}})
    # read_sensitive -> write -> send_internal is prohibited even with no external party.
    ss.policy.cfg.prohibited_pairs = []
    _, d = _issue(ss, ps, s256, CAL)
    assert d["decision"] == "allow"
    _, d = _issue(ss, ps, s256, MAIL, SEND | {"parameters": {"to": "a@corp.example"}})
    assert d["decision"] == "deny" and "read_sensitive then write then send_internal" in d["reason"]


# ------------------------------------------------------------------ budgets


def test_payment_budget_count_and_amount():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    ss.policy.cfg.high_impact.discard("payment")
    pay = {"operations": [{"operationId": "pay"}]}
    _, d = _issue(ss, ps, s256, PAY, pay | {"parameters": {"amount": 300000}})
    assert d["decision"] == "allow"
    _, d = _issue(ss, ps, s256, PAY, pay | {"parameters": {"amount": 250000}})
    assert d["decision"] == "deny" and "Budget exceeded" in d["reason"]
    _, d = _issue(ss, ps, s256, PAY, pay | {"parameters": {"amount": 1}})
    _, d = _issue(ss, ps, s256, PAY, pay | {"parameters": {"amount": 1}})
    _, d = _issue(ss, ps, s256, PAY, pay | {"parameters": {"amount": 1}})
    assert d["decision"] == "deny" and "Budget exhausted" in d["reason"]


def test_budget_amount_unknown_asks():
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=RES)
    _, d = _issue(ss, ps, s256, PAY)
    assert d["decision"] == "ask" and "cannot be checked" in d["summary"]


# ------------------------------------------------------------------ reach


def _ask_then_resolve(ss, ps, s256, resource, apply):
    sdi, d = _issue(ss, ps, s256, resource)
    assert d["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply).status == 201
    assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
    return sdi


@pytest.mark.req("SUP-052", "SUP-058", "SUP-060", "SUP-P11")
@pytest.mark.parametrize("apply,later", [(None, "ask"), ("once", "ask"),
                                         ("mission", "allow"), ("always", "allow")])
def test_reach_of_an_answer(apply, later):
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=RES)
    other = "https://unlisted.example"
    _ask_then_resolve(ss, ps, s256, other, apply)
    _, d = _issue(ss, ps, s256, other)
    assert d["decision"] == later


@pytest.mark.req("SUP-P11")
def test_mission_reach_does_not_cross_missions_but_always_does():
    ss, ps, clock = make_env()
    m1 = connected((ss, ps, clock), resources=RES)
    other = "https://unlisted.example"
    _ask_then_resolve(ss, ps, m1, other, "mission")
    _, m2 = ps.propose_and_approve(ss, SUB, AGENT, "# Second", list(RES))
    assert _issue(ss, ps, m2, other)[1]["decision"] == "ask"
    _ask_then_resolve(ss, ps, m2, other, "always")
    _, m3 = ps.propose_and_approve(ss, SUB, AGENT, "# Third", list(RES))
    assert _issue(ss, ps, m3, other)[1]["decision"] == "allow"


@pytest.mark.req("SUP-059", "SUP-P11")
def test_reach_given_for_a_composition_overrides_only_that_composition():
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=RES)
    _issue(ss, ps, s256, HR)  # uncertain read_sensitive
    sdi, d = _issue(ss, ps, s256, MAIL, scope="mail.send")
    assert d["decision"] == "ask"
    labels = [o["label"] for o in d["apply_options"]]
    assert any("read_sensitive then send_external" in lbl for lbl in labels)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    ps.issued(ss, SUB, AGENT, s256, sdi, MAIL, "mail.send")
    assert _issue(ss, ps, s256, MAIL, scope="mail.send")[1]["decision"] == "allow"


def test_reach_never_overrides_a_deny():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    _issue(ss, ps, s256, HR, {"operations": [{"operationId": "get"}], "parameters": {},
                              "result": {"contains": ["national_id"]}})
    ext = SEND | {"parameters": {"to": "a@evil.example"}}
    sdi, d = _issue(ss, ps, s256, MAIL, ext)
    assert d["decision"] == "deny"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "always")  # a PS cannot widen a deny
    assert _issue(ss, ps, s256, MAIL, ext)[1]["decision"] == "deny"


def test_issued_past_a_deny_still_counts():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    ss.policy.cfg.high_impact.discard("payment")
    pay = {"operations": [{"operationId": "pay"}], "parameters": {"amount": 600000}}
    sdi, d = _issue(ss, ps, s256, PAY, pay)
    assert d["decision"] == "deny"
    ps.issued(ss, SUB, AGENT, s256, sdi, PAY, proposal=pay)  # a misbehaving PS issues anyway
    hist = ss.store.missions[f"{ps.issuer}|{s256}"].history
    assert [h.action_class for h in hist] == ["payment"] and hist[0].amount == 600000


# ------------------------------------------------------------------ properties


def _scenario_decisions(seed: int) -> list[str]:
    rnd = random.Random(seed)
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    out = []
    steps = [
        (HR, {"operations": [{"operationId": "get"}], "parameters": {},
              "result": {"contains": ["salary"]}}),
        (HR, {"operations": [{"operationId": "get"}], "parameters": {}, "result": {}}),
        (MAIL, SEND | {"parameters": {"to": "a@corp.example"}}),
        (MAIL, SEND | {"parameters": {"to": "a@evil.example"}}),
        (CAL, None),
        (PAY, {"operations": [{"operationId": "pay"}], "parameters": {"amount": 100}}),
    ]
    for _ in range(8):
        res, prop = steps[rnd.randrange(len(steps))]
        out.append(_issue(ss, ps, s256, res, prop)[1]["decision"])
    return out


def test_determinism_same_inputs_same_decisions():
    for seed in range(5):
        assert _scenario_decisions(seed) == _scenario_decisions(seed)


def test_more_history_never_loosens_a_decision():
    """Monotonicity: appending acts to the history never turns deny/ask into allow."""
    p = Policy(policy_cfg())
    order = {"allow": 0, "ask": 1, "deny": 2}
    from aauth_supervision_server.store import HistoryEntry, Mission

    m = Mission("m", AGENT, SUB, "https://ps.example",
                {"approved_resources": list(RES), "approved_tools": []})
    pool = [HistoryEntry(c, HR, "resource") for c in
            ("read", "read_internal", "read_sensitive", "write", "send_internal")]
    act = _send("a@evil.example")
    for k in range(len(pool) + 1):
        for prefix in itertools.combinations(pool, k):
            base = p.decide(act, m, list(prefix), [], now=0).decision
            for extra in pool:
                more = p.decide(act, m, list(prefix) + [extra], [], now=0).decision
                assert order[more] >= order[base]


def test_replay_gives_the_same_history():
    ss, ps, clock = make_env(transport="forwarded+issued")
    s256 = connected((ss, ps, clock), resources=RES)
    _issue(ss, ps, s256, HR, {"operations": [{"operationId": "get"}], "parameters": {},
                              "result": {"contains": ["salary"]}})
    _issue(ss, ps, s256, CAL)
    _issue(ss, ps, s256, MAIL, SEND | {"parameters": {"to": "a@corp.example"}})
    ss2, _, _ = make_env(transport="forwarded+issued")
    ss2.resolver, ss2.clock, ss2.cfg.trusted_ps = ss.resolver, clock, ss.cfg.trusted_ps
    ps.ss_jwk = ss2.key.public_jwk()  # the PS uses the new SS's published key
    ps.replay_to(ss2, SUB, AGENT)
    key = f"{ps.issuer}|{s256}"

    def view(s):
        return [(h.action_class, h.resource, h.provenance, h.detail.startswith("uncertain"))
                for h in s.store.missions[key].history]

    # The send completes read_sensitive -> write -> send_internal and is denied: two acts count.
    assert view(ss) == view(ss2) and len(view(ss)) == 2


def test_replay_without_the_proposal_loses_certainty():
    """As Supervision -00 is written, a replayed issuance carries no proposal."""
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=RES)
    _issue(ss, ps, s256, HR, {"operations": [{"operationId": "get"}], "parameters": {},
                              "result": {"contains": ["salary"]}})
    ss2, _, _ = make_env(transport="forwarded")
    ss2.resolver, ss2.clock, ss2.cfg.trusted_ps = ss.resolver, clock, ss.cfg.trusted_ps
    ps.ss_jwk = ss2.key.public_jwk()  # the PS uses the new SS's published key
    ps.replay_to(ss2, SUB, AGENT)
    h1 = ss.store.missions[f"{ps.issuer}|{s256}"].history[0]
    h2 = ss2.store.missions[f"{ps.issuer}|{s256}"].history[0]
    assert (h1.provenance, h1.detail.startswith("uncertain")) == ("resource", False)
    assert h2.detail.startswith("uncertain")


# ------------------------------------------------------------------ missions


@pytest.mark.req("SUP-033")
def test_proposal_allow_carries_description():
    ss, ps, clock = make_env()
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-1", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "# Plan the offsite", "resources": [CAL],
        "tools": [{"name": "WebSearch", "description": "s"}]})
    d = r.json()
    assert d["decision"] == "allow" and d["description"] == "# Plan the offsite"
    assert d["approved_resources"] == [CAL] and d["approved_tools"][0]["name"] == "WebSearch"


def test_expired_mission_denies():
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=RES)
    clock.t += 31 * 24 * 3600
    assert _issue(ss, ps, s256, CAL)[1]["decision"] == "deny"
