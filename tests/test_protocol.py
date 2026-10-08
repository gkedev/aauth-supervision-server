"""Protocol conformance of the SS against Supervision -00 (rows in docs/conformance-matrix.md)."""

from __future__ import annotations

import json

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.jwk import b64u

HR, MAIL = "https://hr.example", "https://mail.example"


def _first_decision(ps, sdi):
    return next(b for p, b, _ in ps.sent if p == "/decision" and b.get("sdi") == sdi)


@pytest.mark.req("SUP-001", "SUP-002", "SUP-003", "SUP-004", "SUP-005", "SUP-006", "SUP-007", "SUP-008")
def test_metadata_and_jwks(env):  # SUP metadata rows
    ss, _, _ = env
    md = ss.handle(HttpRequest("GET", "ss.example", "/.well-known/aauth-supervisor.json")).json()
    for k in ("issuer", "connect_endpoint", "mission_endpoint", "decision_endpoint",
              "event_endpoint", "jwks_uri"):
        assert md[k].startswith("https://ss.example")
    assert md["name"] == ss.cfg.name  # SUP-002: the display name the PS MAY show
    keys = ss.handle(HttpRequest("GET", "ss.example", "/.well-known/jwks.json")).json()["keys"]
    assert keys[0]["alg"] == "Ed25519" and "d" not in keys[0]


@pytest.mark.req("SUP-007")
def test_no_jwks_when_unsigned():
    ss, _, _ = make_env(sign=False)
    md = ss.handle(HttpRequest("GET", "ss.example", "/.well-known/aauth-supervisor.json")).json()
    assert "jwks_uri" not in md


@pytest.mark.req("SUP-011", "SUP-P14")
def test_unsigned_request_is_401(env):
    ss, _, _ = env
    r = ss.handle(HttpRequest("POST", "ss.example", "/decision",
                              {"content-type": "application/json"}, b"{}"))
    assert r.status == 401 and "Signature-Error" in r.headers


@pytest.mark.req("SUP-011")
def test_wrong_authority(env):
    ss, ps, _ = env
    ps.ss_authority = "other.example"
    assert ps.connect(ss, SUB).json()["error"] == "invalid_request"


@pytest.mark.req("SUP-011")
def test_unsupported_iss():
    ss, ps, _ = make_env()
    ss.cfg.trusted_ps.clear()
    r = ps.connect(ss, SUB)
    assert r.status == 403 and r.json()["error"] == "unsupported_iss"


@pytest.mark.req("SUP-011", "SUP-015")
def test_unknown_sub_before_connect(env):
    ss, ps, _ = env
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", HR)
    assert r.status == 404 and r.json()["error"] == "unknown_sub"


@pytest.mark.req("SUP-021", "SUP-064")
def test_connect_interaction_flow():
    ss, ps, _ = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    assert r.status == 202
    req = r.headers["AAuth-Requirement"]
    assert req.startswith("requirement=interaction") and 'url="https://ss.example/interaction"' in req
    code = req.split('code="')[1].rstrip('"')
    assert len(code) == 10 and all(c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for c in code)
    loc = r.headers["Location"]
    assert ps.call(ss, "GET", loc).status == 202
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", query=f"code={code}"))
    assert page.status == 200 and code.encode() in page.body and b"ps.example" in page.body
    bad = ss.handle(HttpRequest("POST", "ss.example", "/interaction",
                                {"content-type": "application/x-www-form-urlencoded"},
                                f"code={code}&admin_token=nope".encode()))
    assert bad.status == 403
    ok = ss.handle(HttpRequest("POST", "ss.example", "/interaction",
                               {"content-type": "application/x-www-form-urlencoded"},
                               f"code={code}&admin_token=operator-secret".encode()))
    assert ok.status == 200
    assert ps.call(ss, "GET", loc).status == 200
    assert ps.connect(ss, SUB).status == 200  # already connected


@pytest.mark.req("SUP-019", "SUP-022")
def test_disconnect_then_unknown_sub(env):
    ss, ps, _ = env
    connected(env)
    r = ps.call(ss, "POST", "/connect", {"action": "disconnect", "id": "c-x", "iat": 1, "sub": SUB})
    assert r.status == 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", HR)
    assert r.json()["error"] == "unknown_sub"


@pytest.mark.req("SUP-031")
def test_mission_action_required(env):
    ss, ps, _ = env
    s256 = connected(env)
    for body in ({"id": "e1", "iat": 1, "sub": SUB, "agent": AGENT},
                 {"action": "bogus", "id": "e2", "iat": 1, "sub": SUB, "agent": AGENT}):
        r = ps.call(ss, "POST", f"/mission/{s256}", body)
        assert r.status == 400 and r.json()["error"] == "invalid_request"


@pytest.mark.req("SUP-038")
def test_mission_approved_digest_checked(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    raw = b'{"agent":"x","approved_at":"2026-01-01T00:00:00Z","description":"d"}'
    r = ps.call(ss, "POST", "/mission/WRONG", {
        "action": "approved", "id": "e9", "sdi": "d1", "iat": 1, "sub": SUB, "agent": AGENT,
        "s256": "WRONG", "mission": b64u(raw)})
    assert r.status == 400


@pytest.mark.req("SUP-025", "SUP-034", "SUP-035", "SUP-036", "SUP-037", "SUP-P06")
def test_proposal_refines_and_strips_ask_tools(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-p1", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "# Clean up", "tools": [{"name": "DeleteRepo", "description": "x"},
                                                {"name": "ReadFile", "description": "y"}],
        "resources": [HR]})
    d = r.json()
    assert d["decision"] == "ask" and d["proposed"]["approved_tools"] == [
        {"name": "ReadFile", "description": "y"}]
    assert "expires_at" in d["proposed"]


@pytest.mark.req("SUP-024")
def test_proposal_deny_resource(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-p2", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "x", "resources": ["https://exfil.example"]})
    assert r.json()["decision"] == "deny" and "reason" in r.json()


@pytest.mark.req("SUP-P13")
def test_unknown_mission(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "NOPE", HR)
    assert r.status == 404 and r.json()["error"] == "unknown_mission"


@pytest.mark.req("SUP-039", "SUP-040", "SUP-P07", "SUP-P08")
def test_update_completion_terminated(env):
    ss, ps, _ = env
    s256 = connected(env)
    u = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": "d-u", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "description": "x"})
    assert u.json()["decision"] == "allow"
    c = ps.call(ss, "POST", f"/mission/{s256}", {"action": "completion", "sdi": "d-c", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "summary": "done"})
    assert c.json()["decision"] == "allow"
    t = ps.call(ss, "POST", f"/mission/{s256}", {"action": "terminated", "id": "e-t", "iat": 1,
                                                 "sub": SUB, "agent": AGENT, "reason": "completed"})
    assert t.status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, HR)
    assert r.json()["decision"] == "deny"


@pytest.mark.req("SUP-012", "SUP-P14")
def test_invalid_act_and_missing_members(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/decision", {"sdi": "d", "act": "fly", "iat": 1, "sub": SUB,
                                          "agent": AGENT})
    assert r.status == 400
    r = ps.call(ss, "POST", "/decision", {"act": "auth_token", "iat": 1, "sub": SUB,
                                          "agent": AGENT})
    assert r.status == 400 and "sdi" in r.json()["detail"]
    r = ps.call(ss, "POST", "/event", {"event": "nope", "id": "e", "iat": 1, "sub": SUB,
                                       "agent": AGENT})
    assert r.status == 400


@pytest.mark.req("SUP-026", "SUP-028", "SUP-029")
def test_signed_decision_and_idempotence(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r1, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://calendar.example")
    assert r1.status == 200 and "Signature" in r1.headers  # verified inside ps.call
    assert 'dwk="aauth-supervisor.json"' in r1.headers["Signature-Key"]
    assert '"content-digest";req' in r1.headers["Signature-Input"]
    retry_body = ps.sent[-1][1]  # a PS retry re-sends the same request under the same sdi
    r2 = ps.call(ss, "POST", "/decision", retry_body)
    assert r2.body == r1.body and r2.headers["Signature"] == r1.headers["Signature"]


@pytest.mark.req("SUP-013", "SUP-050", "SUP-P02", "SUP-P10")
def test_event_dedup(env):
    ss, ps, _ = env
    connected(env)
    body = {"event": "agent.bound", "id": "e-dup", "iat": 1, "sub": SUB, "agent": AGENT,
            "agent_iss": "https://agent.example", "agent_sub": AGENT}
    assert ps.call(ss, "POST", "/event", body).status == 201
    assert ps.call(ss, "POST", "/event", body).status == 201
    assert len(ss.store.agents) == 1 and ss.handle  # nothing recorded twice


@pytest.mark.req("SUP-P09")
def test_permission_act(env):
    ss, ps, _ = env
    s256 = connected(env)
    r = ps.call(ss, "POST", "/decision", {
        "sdi": "d-perm", "act": "permission", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "WebSearch", "description": "look up flights",
        "parameters": {"q": "flights"}})
    assert r.json()["decision"] == "allow"
    r = ps.call(ss, "POST", "/decision", {
        "sdi": "d-perm2", "act": "permission", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "ReadFile", "parameters": {}})
    assert r.json()["decision"] == "ask"  # tool not in approved_tools


@pytest.mark.req("SUP-041")
def test_person_token_act(env):
    ss, ps, _ = env
    s256 = connected(env)
    base = {"act": "person_token", "iat": 1, "sub": SUB, "agent": AGENT, "mission_s256": s256,
            "agent_token": ps.agent_token(AGENT)}
    assert ps.call(ss, "POST", "/decision", base | {"sdi": "d-pt", "resource": HR}
                   ).json()["decision"] == "allow"
    assert ps.call(ss, "POST", "/decision", base | {"sdi": "d-pt2", "resource":
                                                    "https://other.example"}).json()["decision"] \
        == "ask"


@pytest.mark.req("SUP-027", "SUP-048", "SUP-P03", "SUP-P04", "SUP-P05")
def test_clarify_flow():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202 and r.headers["AAuth-Requirement"] == "requirement=clarification"
    body = r.json()
    assert body["decision"] == "clarify" and body["status"] == "pending" and body["sdi"] == sdi
    loc = r.headers["Location"]
    assert ps.call(ss, "GET", loc).status == 202
    other = make_env()[1]  # a different PS cannot touch it
    other.issuer = "https://ps2.example"
    other.clock = clock
    other.install(ss.resolver.fetcher)  # type: ignore[attr-defined]
    ss.cfg.trusted_ps[other.issuer] = ss.cfg.trusted_ps[ps.issuer]
    assert other.call(ss, "GET", loc).json()["error"] == "unknown_pending"
    ans = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                    "clarification_response": "Weekly status to my team."})
    assert ans.status == 200 and ans.json()["decision"] == "ask"
    assert "the agent says" in ans.json()["summary"]
    assert ps.call(ss, "GET", loc).json()["decision"] == "ask"
    # the decision endpoint replays the same terminal answer for the sdi
    again = ps.call(ss, "POST", "/decision", ps.sent[0][1] if False else _first_decision(ps, sdi),
                    verify=False)
    assert again.body == ans.body


@pytest.mark.req("SUP-P05")
def test_clarify_cancel():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    assert ps.call(ss, "DELETE", loc).status == 204
    assert ps.call(ss, "GET", loc).status == 410
    bad = ps.call(ss, "POST", "/pending/nope", {"action": "clarification_response"})
    assert bad.json()["error"] == "unknown_pending"


@pytest.mark.req("SUP-062")
def test_rate_limited():
    ss, ps, _ = make_env()
    ss.cfg.rate_limit_per_minute = 2
    ps.connect(ss, SUB)
    ps.connect(ss, SUB)
    r = ps.connect(ss, SUB)
    assert r.status == 429 and int(r.headers["Retry-After"]) >= 1


@pytest.mark.req("SUP-P14")
def test_errors_are_problem_json(env):
    ss, ps, _ = env
    r = ps.auth_token_request(ss, SUB, AGENT, "", HR)[1]
    assert r.headers["Content-Type"] == "application/problem+json" and "error" in r.json()


@pytest.mark.req("SUP-028")
def test_state_survives_restart(tmp_path):
    from aauth_supervision_server.store import Store

    ss, ps, clock = make_env()
    ss.store = Store(str(tmp_path / "state.json"))
    s256 = connected((ss, ps, clock))
    ss2_store = Store(str(tmp_path / "state.json"))
    assert any(m.s256 == s256 for m in ss2_store.missions.values())
    assert json.loads((tmp_path / "state.json").read_text())["connections"]
