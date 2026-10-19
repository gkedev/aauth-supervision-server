"""What a person's answer with reach covers (Supervision L582: the SS remembers and
applies it to later acts).

- An `allow` given when the composition could only be completed on uncertain evidence
  does not cover a later completion on certain evidence: the person was told "may", and
  "would" was never put to them (in `composition_on_certain: ask` mode; in `deny` mode a
  certain completion is denied before any answer is looked at).
- A `deny` with reach is applied wherever the composition is completed by recorded acts,
  in another mission or at another instance of the provider too: the label offered it.
  A composition only an open act completes is still asked: that act may never happen.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import HistoryEntry, Reach

SEND, READ = "https://send.example", "https://read.example"


def _policy() -> Policy:
    return Policy(PolicyConfig(
        severity=["unclassified", "read_sensitive", "send_external"],
        rules=[Rule(cls="read_sensitive", resource=READ), Rule(cls="send_external", resource=SEND)],
        prohibited_pairs=[["read_sensitive", "send_external"]], composition_on_certain="ask"))


def test_an_allow_given_to_may_does_not_answer_would() -> None:
    p = _policy()
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=SEND,
              parameters_provenance="resource")
    unsure = [HistoryEntry("read_sensitive", READ, "configured", detail="uncertain: x")]
    d = p.decide(act, None, unsure, [], 0.0)
    assert d.decision == "ask" and d.certain is False
    reach = [Reach("mission", "iss", SUB, AGENT, d.kind, "m", d.composition, "allow",
                   certain=d.certain)]
    assert p.decide(act, None, unsure, reach, 0.0).decision == "allow"
    sure = [HistoryEntry("read_sensitive", READ, "resource", detail="rule")]
    d2 = p.decide(act, None, sure, reach, 0.0)
    assert d2.decision == "ask" and d2.certain is True
    reach2 = [Reach("mission", "iss", SUB, AGENT, d2.kind, "m", d2.composition, "allow",
                    certain=True)]
    assert p.decide(act, None, sure, reach2, 0.0).decision == "allow"
    assert p.decide(act, None, unsure, reach2, 0.0).decision == "allow"


def test_a_deny_given_to_may_still_answers_would() -> None:
    p = _policy()
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=SEND,
              parameters_provenance="resource")
    d = p.decide(act, None, [HistoryEntry("read_sensitive", READ, "configured",
                                          detail="uncertain: x")], [], 0.0)
    reach = [Reach("mission", "iss", SUB, AGENT, d.kind, "m", d.composition, "deny")]
    sure = [HistoryEntry("read_sensitive", READ, "resource", detail="rule")]
    assert p.decide(act, None, sure, reach, 0.0).decision == "deny"


def test_the_certainty_of_the_ask_reaches_the_stored_answer() -> None:
    ss, ps, clock = make_env(rules=[{"resource": READ, "class": "read_sensitive"},
                                    {"resource": SEND, "class": "send_external"}],
                             prohibited_pairs=[["read_sensitive", "send_external"]],
                             prohibited_sequences=[], high_impact=[],
                             composition_on_certain="ask")
    s256 = connected((ss, ps, clock), resources=(READ, SEND))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, READ)
    assert ps.issued(ss, SUB, AGENT, s256, sdi, READ).status == 201
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, SEND)
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission").status == 201
    assert ss.store.reach[-1].certain is True


def _two_missions() -> tuple[Any, Any, str, str]:
    rules = [{"resource": READ, "class": "read_sensitive"},
             {"resource": SEND, "class": "send_external"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[["read_sensitive", "send_external"]],
                             prohibited_sequences=[], high_impact=[])
    a = connected((ss, ps, clock), resources=(READ, SEND))
    r, b = ps.propose_and_approve(ss, SUB, AGENT, "# Other", [READ, SEND], [])
    assert r.status == 200 and b
    return ss, ps, a, str(b)


def test_a_no_across_missions_is_applied() -> None:
    ss, ps, a, b = _two_missions()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, a, READ)
    assert ps.issued(ss, SUB, AGENT, a, sdi, READ).status == 201
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, b, SEND)
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, b, sdi, "deny", apply="mission").status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, b, SEND)
    assert r.json()["decision"] == "deny" and "declined" in r.json()["reason"]


def test_a_no_across_missions_is_applied_with_another_act_open() -> None:
    # An unrelated act still open must not take the answer away from recorded acts.
    ss, ps, a, b = _two_missions()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, a, READ)
    assert ps.issued(ss, SUB, AGENT, a, sdi, READ).status == 201
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, b, SEND)
    assert ps.resolved(ss, SUB, AGENT, b, sdi, "deny", apply="mission").status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, b, SEND)  # open: decided, not issued
    assert r.json()["decision"] == "deny"
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, a, READ)  # another open act
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, b, SEND)
    assert r.json()["decision"] == "deny" and "declined" in r.json()["reason"]


def test_a_no_is_not_applied_where_only_another_mission_s_open_act_completes() -> None:
    p = _policy()
    act = Act("auth_token", "iss", SUB, AGENT, "m", resource=SEND,
              parameters_provenance="resource")
    d = p.decide(act, None, [HistoryEntry("read_sensitive", READ, "configured",
                                          detail="uncertain: x")], [], 0.0)
    reach = [Reach("mission", "iss", SUB, AGENT, d.kind, "m", d.composition, "deny")]
    open_elsewhere = HistoryEntry("read_sensitive", READ, "resource", borrowed=True,
                                  open="other", scope="m-2",
                                  detail="uncertain: allow not yet settled")
    d2 = p.decide(act, None, [open_elsewhere], reach, 0.0)
    assert d2.decision == "ask"
