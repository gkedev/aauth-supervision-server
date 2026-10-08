"""The service-layer state machine, driven out of its happy path.

`service.py` is the protocol state machine: mission lifecycle (proposal, approval,
update, completion, termination), pending/polling, clarification rounds, replay and
idempotence, and event dedup. These tests drive each transition out of order and
assert the SS answers cleanly and never crashes, plus a randomized interleave that
throws a chaotic op sequence at a live SS and checks no request yields a 500, the
store invariants hold, and the resulting snapshot still reloads.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Store

HR, MAIL = "https://hr.example", "https://mail.example"
CAL = "https://calendar.example"


def _decision_body(ps, sdi):
    return next(b for p, b, _ in ps.sent if p == "/decision" and b.get("sdi") == sdi)


# ------------------------------------------------------------ mission lifecycle

def test_update_after_terminate_is_denied_not_crash(env):
    ss, ps, _ = env
    s256 = connected(env)
    ps.call(ss, "POST", f"/mission/{s256}", {"action": "terminated", "id": "e-t", "iat": 1,
                                             "sub": SUB, "agent": AGENT, "reason": "done"})
    u = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": "d-u", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "description": "x"})
    assert u.status == 200 and u.json()["decision"] == "deny"
    c = ps.call(ss, "POST", f"/mission/{s256}", {"action": "completion", "sdi": "d-c", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "summary": "s"})
    assert c.json()["decision"] == "deny"


def test_terminate_is_idempotent_by_id(env):
    ss, ps, _ = env
    s256 = connected(env)
    body = {"action": "terminated", "id": "e-t", "iat": 1, "sub": SUB, "agent": AGENT}
    assert ps.call(ss, "POST", f"/mission/{s256}", body).status == 201
    assert ps.call(ss, "POST", f"/mission/{s256}", body).status == 201  # same id, no-op


def test_completion_on_unknown_mission_is_404(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    c = ps.call(ss, "POST", "/mission/UNKNOWN", {"action": "completion", "sdi": "d-c9", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "summary": "x"})
    assert c.status == 404 and c.json()["error"] == "unknown_mission"


def test_mission_sdi_reused_with_different_body_is_refused(env):
    ss, ps, _ = env
    s256 = connected(env)
    b1 = {"action": "update", "sdi": "d-reuse", "iat": 1, "sub": SUB, "agent": AGENT,
          "description": "first"}
    assert ps.call(ss, "POST", f"/mission/{s256}", b1).json()["decision"] == "allow"
    b2 = dict(b1, description="SECOND different")
    r2 = ps.call(ss, "POST", f"/mission/{s256}", b2, verify=False)
    assert r2.status == 400 and r2.json()["error"] == "invalid_request"


# ------------------------------------------------------------ pending / polling

def test_post_to_connect_pending_is_rejected():
    ss, ps, _ = make_env(auto_connect=False)
    loc = ps.connect(ss, SUB).headers["Location"]
    pr = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                   "clarification_response": "x"})
    assert pr.status == 400 and pr.json()["error"] == "invalid_request"


def test_connect_pending_polled_with_get_only():
    ss, ps, _ = make_env(auto_connect=False)
    loc = ps.connect(ss, SUB).headers["Location"]
    assert ps.call(ss, "GET", loc).status == 202  # still pending


def test_double_delete_then_answer_on_clarify_pending():
    env = make_env(clarify_missing_justification=True)
    ss, ps, _ = env
    s256 = connected(env)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    assert ps.call(ss, "DELETE", loc).status == 204
    assert ps.call(ss, "DELETE", loc).status == 410  # already cancelled
    pr = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                   "clarification_response": "x"})
    assert pr.status == 410  # answering a cancelled pending is gone


def test_bogus_action_on_clarify_pending_is_400():
    env = make_env(clarify_missing_justification=True)
    ss, ps, _ = env
    s256 = connected(env)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    pr = ps.call(ss, "POST", loc, {"action": "nope"})
    assert pr.status == 400 and pr.json()["error"] == "invalid_request"


def test_unknown_pending_id_is_404(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    pr = ps.call(ss, "GET", "/pending/does-not-exist")
    assert pr.status == 404 and pr.json()["error"] == "unknown_pending"


# ------------------------------------------------------------ clarification rounds

def test_clarification_rounds_are_bounded():
    env = make_env(clarify_missing_justification=True)
    ss, ps, _ = env
    ss.cfg.clarification_rounds = 2
    s256 = connected(env)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    rounds, last = 0, r
    while last.status == 202 and rounds < 10:
        body = last.json()
        if body.get("decision") != "clarify":
            break
        last = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                         "clarification_response": ""})  # never resolves
        rounds += 1
    assert rounds <= 3, f"clarification looped {rounds} times with cap=2"
    assert last.status == 200 and last.json()["decision"] in ("ask", "allow", "deny")


# ------------------------------------------------------------ replay / idempotence

def test_decision_retry_is_byte_identical(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r1, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    r2 = ps.call(ss, "POST", "/decision", _decision_body(ps, sdi))
    assert r1.body == r2.body
    assert r1.headers.get("Signature") == r2.headers.get("Signature")


def test_decision_retry_with_tampered_body_is_refused(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r1, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL, sdi="tamper")
    tampered = dict(_decision_body(ps, sdi))
    tampered["justification"] = (tampered.get("justification") or "") + " APPENDED"
    r2 = ps.call(ss, "POST", "/decision", tampered, verify=False)
    assert r2.status == 400 and r2.json()["error"] == "invalid_request"


def test_full_replay_to_a_fresh_ss_rebuilds_state(env):
    ss, ps, clock = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    ps.issued(ss, SUB, AGENT, s256, sdi, CAL)
    ss2, _, _ = make_env()
    ss2.resolver, ss2.clock, ss2.cfg.trusted_ps = ss.resolver, clock, ss.cfg.trusted_ps
    ps.ss_jwk = ss2.key.public_jwk()  # the PS verifies against the new SS's published key
    ps.replay_to(ss2, SUB, AGENT)  # must not raise
    assert any(m.s256 == s256 for m in ss2.store.missions.values())


# ------------------------------------------------------------ events

def test_resolved_on_a_non_ask_record_adds_no_reach(env):
    """An auth_token the SS allowed outright is not an `ask`; a resolution reported for
    it (even apply=always) must not create a standing reach."""
    ss, ps, _ = env
    s256 = connected(env)
    # HR is an approved resource -> allowed outright, decision != ask
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, HR, scope="read")
    assert r.json()["decision"] == "allow"
    before = len(ss.store.reach)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="always")
    assert len(ss.store.reach) == before


def test_resolved_unoffered_apply_is_treated_as_once(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL, sdi="forever")
    assert r.json()["decision"] == "ask"  # CAL not approved -> ask with options
    before = len(ss.store.reach)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="forever")  # never offered
    assert len(ss.store.reach) == before


def test_duplicate_resolved_event_adds_reach_once(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL, sdi="dup")
    assert r.json()["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission")
    after1 = len(ss.store.reach)
    body = next(b for p, b, _ in ps.sent if p == "/event"
                and b.get("event") == "decision.resolved" and b.get("sdi") == sdi)
    ps.call(ss, "POST", "/event", body)  # same event id -> deduped
    assert len(ss.store.reach) == after1


def test_resolved_deny_cannot_be_widened_by_a_later_allow(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL, sdi="flip")
    assert r.json()["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny")
    before = len(ss.store.reach)
    # the record is now resolved_deny, not ask -> a second resolution carries no authority
    ps.call(ss, "POST", "/event", {"event": "decision.resolved", "id": "e-flip2", "sdi": sdi,
            "iat": 1, "sub": SUB, "agent": AGENT, "answer": "allow", "apply": "always"})
    assert len(ss.store.reach) == before


def test_resolved_bad_answer_is_400(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    rr = ps.call(ss, "POST", "/event", {"event": "decision.resolved", "id": "e-r", "sdi": sdi,
                 "iat": 1, "sub": SUB, "agent": AGENT, "answer": "maybe"})
    assert rr.status == 400 and rr.json()["error"] == "invalid_request"


def test_event_for_unknown_sdi_and_mission(env):
    ss, ps, _ = env
    connected(env)
    # resolved / issued for an sdi the SS never saw -> accepted (201), classified from the event
    assert ps.call(ss, "POST", "/event", {"event": "decision.resolved", "id": "e1",
                   "sdi": "never", "iat": 1, "sub": SUB, "agent": AGENT, "answer": "allow"}
                   ).status == 201
    assert ps.call(ss, "POST", "/event", {"event": "auth_token.issued", "id": "e2", "sdi": "fresh",
                   "iat": 1, "sub": SUB, "agent": AGENT, "jti": "at", "aud": CAL, "exp": 2,
                   "issuer": ps.issuer}).status == 201
    # an issuance naming an unknown mission is unknown_mission
    r = ps.call(ss, "POST", "/event", {"event": "auth_token.issued", "id": "e3", "sdi": "s",
                "iat": 1, "sub": SUB, "agent": AGENT, "jti": "at2", "mission_s256": "NOPE",
                "aud": HR, "exp": 2, "issuer": ps.issuer})
    assert r.status == 404 and r.json()["error"] == "unknown_mission"


# ------------------------------------------------------------ randomized interleave

@pytest.mark.parametrize("seed", range(25))
def test_random_interleave_never_500s_and_snapshot_reloads(seed, tmp_path):
    """A chaotic op sequence against a live SS: no request may yield a 500, store
    invariants hold, and the resulting snapshot reloads without error."""
    rng = random.Random(seed)
    env = make_env(clarify_missing_justification=True)
    ss, ps, _ = env
    seen_500: list[str] = []
    orig = ss.handle

    def watch(req):
        resp = orig(req)
        if resp.status == 500:
            seen_500.append(f"{req.method} {req.path} -> {resp.body!r}")
        return resp
    ss.handle = watch  # type: ignore[method-assign]

    ps.connect(ss, SUB)
    missions: list[str] = []
    for i in range(2):
        _, s256 = ps.propose_and_approve(ss, SUB, AGENT, f"# M{i}", [HR, MAIL], [])
        if s256:
            missions.append(s256)
    sdis: list[str] = []
    pendings: list[str] = []

    def mission():
        return rng.choice(missions + ["", "NO-SUCH"]) if missions else ""

    ops = ["decision", "update", "complete", "terminate", "issued", "resolved", "audit",
           "poll_get", "poll_post", "poll_delete", "connect", "agent_bound", "replay"]
    for _ in range(90):
        op = rng.choice(ops)
        if op == "decision":
            sdi = f"sd-{seed}-{len(sdis)}"
            sdis.append(sdi)
            _, r, _ = ps.auth_token_request(
                ss, SUB, AGENT, mission(),
                rng.choice([HR, MAIL, CAL, "https://new.example"]), sdi=sdi,
                scope=rng.choice(["", "mail.send", "write"]),
                justification=rng.choice(["", "because"]))
            if r.status == 202 and r.headers.get("Location"):
                pendings.append(r.headers["Location"])
        elif op in ("update", "complete", "terminate") and missions:
            n = rng.randint(0, 9999)
            act = {"update": {"action": "update", "sdi": f"u{seed}-{n}", "description": "x"},
                   "complete": {"action": "completion", "sdi": f"c{seed}-{n}", "summary": "s"},
                   "terminate": {"action": "terminated", "id": f"t{seed}-{n}", "reason": "r"}}[op]
            ps.call(ss, "POST", f"/mission/{mission()}",
                    dict(act, iat=1, sub=SUB, agent=AGENT), verify=False)
        elif op == "issued" and sdis:
            ps.issued(ss, SUB, AGENT, mission(), rng.choice(sdis), rng.choice([HR, MAIL]))
        elif op == "resolved" and sdis:
            ps.resolved(ss, SUB, AGENT, mission(), rng.choice(sdis),
                        rng.choice(["allow", "deny", "abandoned"]),
                        apply=rng.choice([None, "once", "mission", "always", "forever"]))
        elif op == "audit":
            ps.call(ss, "POST", "/event", {"event": "audit.recorded", "id": f"a{seed}-"
                    f"{rng.randint(0,9999)}", "iat": 1, "sub": SUB, "agent": AGENT,
                    "action": "LocalWrite", "mission_s256": mission()}, verify=False)
        elif op == "poll_get" and pendings:
            ps.call(ss, "GET", rng.choice(pendings), verify=False)
        elif op == "poll_post" and pendings:
            ps.call(ss, "POST", rng.choice(pendings), {"action": rng.choice(
                ["clarification_response", "updated_request", "bogus"]),
                "clarification_response": "x"}, verify=False)
        elif op == "poll_delete" and pendings:
            ps.call(ss, "DELETE", rng.choice(pendings), verify=False)
        elif op == "connect":
            ps.connect(ss, SUB)
        elif op == "agent_bound":
            ps.call(ss, "POST", "/event", {"event": "agent.bound", "id": f"ab{seed}-"
                    f"{rng.randint(0,9999)}", "iat": 1, "sub": SUB, "agent": AGENT,
                    "agent_iss": "https://agent.example", "agent_sub": AGENT}, verify=False)
        elif op == "replay" and sdis:
            body = next((b for p, b, _ in ps.sent if p == "/decision"
                         and b.get("sdi") == rng.choice(sdis)), None)
            if body:
                ps.call(ss, "POST", "/decision", body, verify=False)

    assert not seen_500, f"server_error(s): {seen_500[:3]}"
    for rec in ss.store.decisions.values():
        assert rec.decision in ("allow", "deny", "ask", "clarify", "abandoned",
                                 "resolved_allow", "resolved_deny", "resolved_abandoned")
    for rh in ss.store.reach:
        assert rh.kind, "reach entries must carry a non-empty kind"

    snap = Path(tmp_path) / f"s{seed}.json"
    ss.store.path = snap
    ss.store.save()
    reloaded = Store(str(snap))
    assert reloaded.load_error == "", f"fuzzed snapshot failed to reload: {reloaded.load_error}"
