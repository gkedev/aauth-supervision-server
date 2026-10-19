"""When an act in history can take effect, as the SS is able to know it.

* A permission grant has no lifetime: the agent "MAY proceed with the action" (core,
  Permission Response), at any later moment. Read as one moment, a permission for the last
  step of a sequence, taken first, lets the earlier steps through in the harmless order.
* An audit record reports an action already taken, at some moment before the report
  (the audit endpoint is fire and forget): it can precede acts the SS learned of earlier.
* A token's act counts from its issuance, not from the decision: when the person answers
  an ask hours later, the token did not exist while earlier tokens were live.
* An `exp` the PS reports that is not after the event's own `iat` cannot be the token's
  (a lifetime sent as `exp`, or a typo); the token is treated as never expiring.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

REC, DOCS, CHAT = "https://records.example", "https://docs.example", "https://chat.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": DOCS, "class": "write"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": "*", "tool": "PostToChat", "class": "send_internal"},
         {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"},
         {"resource": "*", "tool": "WriteDoc", "class": "write"}]
TOOLS = [{"name": n, "description": n} for n in ("PostToChat", "ExportRecords", "WriteDoc")]


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [])
    ss, ps, clock = make_env(rules=RULES, high_impact=[], **over)
    s256 = connected((ss, ps, clock), resources=(REC, DOCS, CHAT), tools=TOOLS)
    return ss, ps, clock, s256


def _token(ss: Any, ps: Any, s256: str, res: str, *, issue: bool = True) -> tuple[str, str]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, res)
    d = str(r.json()["decision"])
    if d == "allow" and issue:
        assert ps.issued(ss, SUB, AGENT, s256, sdi, res).status == 201
    return sdi, d


def _permission(ss: Any, ps: Any, clock: Any, s256: str, action: str) -> str:
    r = ps.call(ss, "POST", "/decision", {"sdi": ps.nid("d"), "act": "permission",
                                          "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                          "mission_s256": s256, "action": action})
    return str(r.json()["decision"])


@pytest.mark.parametrize("in_mission", [True, False])
def test_a_permission_for_the_last_step_taken_first_still_counts(in_mission: bool) -> None:
    ss, ps, clock, s256 = _env()
    m = s256 if in_mission else ""
    assert _permission(ss, ps, clock, m, "PostToChat") == "allow"
    assert _token(ss, ps, m, DOCS)[1] == "allow"
    assert _token(ss, ps, m, REC)[1] == "deny"      # then write, then the granted post


def test_an_audit_reported_late_still_precedes_what_followed_the_action() -> None:
    ss, ps, clock, s256 = _env()
    # The export happened first; its audit record arrives after a 30 s write token was
    # obtained and had expired.
    clock.t += 5
    sdi, d = _token(ss, ps, s256, DOCS, issue=False)
    assert d == "allow"
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "w", "aud": DOCS,
            "exp": int(clock()) + 30, "issuer": ps.issuer}
    assert ps.call(ss, "POST", "/event", body).status == 201
    clock.t += 55
    body = {"event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "action": "ExportRecords"}
    assert ps.call(ss, "POST", "/event", body).status == 201
    clock.t += 10
    assert _token(ss, ps, s256, CHAT)[1] == "deny"


def test_a_token_counts_from_its_issuance_not_from_the_decision() -> None:
    ss, ps, clock, s256 = _env()
    t0 = clock.t
    ss.policy.cfg.allow_unlisted_resources = False
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["approved_resources"] = [DOCS, CHAT]
    sdi_read, d = _token(ss, ps, s256, REC)          # outside the mission: asked
    assert d == "ask"
    clock.t = t0 + 10
    sdi_w, d = _token(ss, ps, s256, DOCS, issue=False)
    assert d == "allow"
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi_w, "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "w", "aud": DOCS,
            "exp": int(t0) + 3610, "issuer": ps.issuer}
    assert ps.call(ss, "POST", "/event", body).status == 201
    clock.t = t0 + 7200                               # the person answers two hours later
    ps.resolved(ss, SUB, AGENT, s256, sdi_read, "allow")
    assert ps.issued(ss, SUB, AGENT, s256, sdi_read, REC).status == 201
    clock.t = t0 + 7300
    # The write token expired an hour before the read token existed: no read, write, send.
    assert _token(ss, ps, s256, CHAT)[1] == "allow"


@pytest.mark.parametrize("exp", [3600, -1, 0])
def test_an_exp_not_after_the_issuance_is_not_the_tokens(exp: int) -> None:
    ss, ps, clock, s256 = _env()
    sdi, d = _token(ss, ps, s256, CHAT, issue=False)
    assert d == "allow"
    iat = int(clock())
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": iat,
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "c", "aud": CHAT,
            "exp": iat + exp if exp <= 0 else exp, "issuer": ps.issuer}
    assert ps.call(ss, "POST", "/event", body).status == 201
    clock.t += 5
    assert _token(ss, ps, s256, DOCS)[1] == "allow"
    assert _token(ss, ps, s256, REC)[1] == "deny"     # the send token is still live


def test_a_resolution_must_name_the_person_and_agent_of_its_decision() -> None:
    ss, ps, clock, s256 = _env()
    ss.policy.cfg.allow_unlisted_resources = False
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["approved_resources"] = [DOCS]
    sdi, d = _token(ss, ps, s256, CHAT)
    assert d == "ask"
    other = "aauth:other@agent.example"
    r, m2 = ps.propose_and_approve(ss, SUB, AGENT, "# Another task", [DOCS], [])
    assert m2 and m2 != s256
    for envelope in ({"agent": other}, {"mission_s256": m2}):
        body = {"event": "decision.resolved", "id": ps.nid("e"), "sdi": sdi,
                "iat": int(clock()), "sub": SUB, "agent": AGENT, "mission_s256": s256,
                "answer": "allow", "apply": "mission", **envelope}
        assert ps.call(ss, "POST", "/event", body).status in (400, 404)
    assert ss.store.reach == []
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "ask"
