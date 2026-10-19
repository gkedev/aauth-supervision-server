"""A permission the person grants while the SS could not answer is still history.

Supervision, Unavailable Supervisor (L611) and Decision Resolved (L551): when the PS cannot
use the SS's answer it puts the act to the person and later reports what they decided in
`decision.resolved`, with `supervisor: unavailable`. A permission has no issuance event, so
that report is the only record that the grant happened. The SS's own record for the sdi may
say anything (it denied, or was still clarifying, when the answer was lost); the grant
happened all the same, and the acts after it must compose with it. It carries no reach.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Reach

MAIL = "https://mail.example"
RULES = [{"resource": "*", "tool": "Export", "class": "read_sensitive"},
         {"resource": MAIL, "operation": "send_email",
          "param_domain_not_in": {"to": ["corp.example"]}, "class": "send_external"},
         {"resource": MAIL, "class": "send_internal", "if_unknown": "send_external"}]
SEND_OUT = {"operations": [{"operationId": "send_email"}],
            "parameters": {"to": "x@evil.example"}}


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(transport="forwarded", rules=RULES, prohibited_sequences=[],
                             **over)
    s256 = connected((ss, ps, clock), resources=(MAIL,),
                     tools=[{"name": "Export", "description": "Export records"}])
    return ss, ps, clock, s256


def _export(ss: Any, ps: Any, clock: Any, s256: str) -> tuple[str, str]:
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission",
                                          "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                          "mission_s256": s256, "action": "Export"})
    return sdi, r.json()["decision"]


def _resolved_unavailable(ss: Any, ps: Any, clock: Any, s256: str, sdi: str,
                          answer: str = "allow", apply: str | None = None) -> None:
    body = {"event": "decision.resolved", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "answer": answer,
            "supervisor": "unavailable"}
    if apply:
        body["apply"] = apply
    assert ps.call(ss, "POST", "/event", body).status == 201


def _send_out(ss: Any, ps: Any, s256: str) -> str:
    return str(ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=SEND_OUT)[1]
               .json()["decision"])


@pytest.mark.parametrize("over", [
    {"budgets": {"read_sensitive": {"max_count": 0}}},                 # the SS had denied it
    {"high_impact": ["read_sensitive", "send_external"],
     "clarify_missing_justification": True},                          # still clarifying
])
def test_a_permission_granted_on_the_unavailable_path_composes(over: dict[str, Any]) -> None:
    ss, ps, clock, s256 = _env(**over)
    sdi, first = _export(ss, ps, clock, s256)
    assert first in ("deny", "clarify")
    _resolved_unavailable(ss, ps, clock, s256, sdi)
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [(h.action_class, h.sdi) for h in hist] == [("read_sensitive", sdi)]
    assert _send_out(ss, ps, s256) == "deny"


def test_the_control_without_the_grant_is_allowed() -> None:
    ss, ps, clock, s256 = _env(budgets={"read_sensitive": {"max_count": 0}})
    sdi, first = _export(ss, ps, clock, s256)
    assert first == "deny"
    _resolved_unavailable(ss, ps, clock, s256, sdi, answer="deny")
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []
    assert _send_out(ss, ps, s256) == "allow"


def test_such_a_grant_sets_no_reach_and_is_recorded_once() -> None:
    ss, ps, clock, s256 = _env(budgets={"read_sensitive": {"max_count": 0}})
    sdi, _ = _export(ss, ps, clock, s256)
    _resolved_unavailable(ss, ps, clock, s256, sdi, apply="always")
    _resolved_unavailable(ss, ps, clock, s256, sdi)  # a second report, a new id
    assert ss.store.reach == []
    assert len(ss.store.history_for(ps.issuer, SUB, AGENT, s256)) == 1
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "deny"  # the SS's answer stands


def test_a_clarified_permission_later_answered_is_not_recorded_twice() -> None:
    ss, ps, clock, s256 = _env(high_impact=["read_sensitive", "send_external"],
                               clarify_missing_justification=True)
    sdi, first = _export(ss, ps, clock, s256)
    assert first == "clarify"
    pend = next(p for p in ss.store.pending.values() if p.sdi == sdi)
    _resolved_unavailable(ss, ps, clock, s256, sdi)
    # Meanwhile the person gave this kind of act a reach, and the agent's answer to the
    # clarification arrives after all, so the SS now allows it: still one act in history.
    kind = ss.store.decisions[f"{ps.issuer}|{sdi}"].kind
    # (An answer to the high-impact question: it records that gate.)
    ss.store.reach.append(Reach("mission", ps.issuer, SUB, AGENT, kind, s256, gate="high_impact"))
    r = ps.call(ss, "POST", f"/pending/{pend.id}", {"action": "clarification_response",
                                                     "clarification_response": "Quarterly"})
    assert r.json()["decision"] == "allow"
    assert len([h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)
                if h.sdi == sdi]) == 1
