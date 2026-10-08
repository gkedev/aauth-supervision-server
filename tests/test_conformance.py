"""Conformance tests for matrix rows not covered by test_protocol.py."""

from __future__ import annotations

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message
from aauth_supervision_server.jwk import b64u
from aauth_supervision_server.service import TrustedPS
from aauth_supervision_server.testing import make_jwt, r3_bytes

HR, MAIL, CAL = "https://hr.example", "https://mail.example", "https://calendar.example"


def _decision(ps, ss, **body):
    base = {"sdi": ps.nid("d"), "iat": 1, "sub": SUB, "agent": AGENT}
    return ps.call(ss, "POST", "/decision", base | body)


@pytest.mark.req("SUP-011")
def test_body_signature_must_cover_content_digest(env):
    ss, ps, clock = env
    ps.connect(ss, SUB)
    raw = b'{"action":"connect","id":"c-1","iat":1,"sub":"x"}'
    req = HttpRequest("POST", "ss.example", "/connect",
                      {"content-type": "application/json", "content-digest": content_digest(raw)},
                      raw)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    h = sign_message(["@method", "@authority", "@path", "signature-key"], ps.key, sk, req,
                     created=int(clock()))
    req.headers.update({k.lower(): v for k, v in h.items()})
    r = ss.handle(req)
    assert r.status == 401 and "Signature-Error" in r.headers


@pytest.mark.req("SUP-012", "SUP-013", "SUP-014", "SUP-015", "SUP-016", "SUP-032")
@pytest.mark.parametrize("missing", ["iat", "sub", "agent", "agent_token", "description"])
def test_proposal_required_members(env, missing):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    body = {"sdi": "d-m", "iat": 1, "sub": SUB, "agent": AGENT,
            "agent_token": ps.agent_token(AGENT), "description": "x"}
    del body[missing]
    r = ps.call(ss, "POST", "/mission", body)
    assert r.status == 400 and missing in r.json()["detail"]


@pytest.mark.req("SUP-013", "SUP-014")
@pytest.mark.parametrize("missing", ["id", "iat"])
def test_event_required_members(env, missing):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    body = {"event": "agent.bound", "id": "e-1", "iat": 1, "sub": SUB, "agent": AGENT}
    del body[missing]
    assert ps.call(ss, "POST", "/event", body).status == 400


@pytest.mark.req("SUP-014")
def test_iat_must_be_integer(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c", "iat": "now", "sub": SUB})
    assert r.status == 400


@pytest.mark.req("SUP-017", "SUP-P09")
def test_act_without_mission(env):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = _decision(ps, ss, act="permission", action="WebSearch", parameters={"q": "x"})
    assert r.status == 200 and r.json()["decision"] == "allow"


@pytest.mark.req("SUP-019")
def test_connect_action_must_be_known(env):
    ss, ps, _ = env
    r = ps.call(ss, "POST", "/connect", {"action": "pair", "id": "c", "iat": 1, "sub": SUB})
    assert r.status == 400


@pytest.mark.req("SUP-020")
def test_tenant_accepts_without_interaction():
    ss, ps, _ = make_env(auto_connect=False)
    ss.cfg.trusted_ps[ps.issuer] = TrustedPS(auto_connect=False, tenants=["corp.example"])
    r = ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c", "iat": 1, "sub": SUB,
                                         "tenant": "corp.example"})
    assert r.status == 200
    r = ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c2", "iat": 1, "sub": "s2",
                                         "tenant": "other.example"})
    assert r.status == 202


@pytest.mark.req("SUP-064")
def test_connect_page_shows_issuer_name_and_code():
    ss, ps, _ = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", query=f"code={code}")).body
    assert b"https://ps.example" in page and b"Example Person Server" in page
    assert code.encode() in page


@pytest.mark.req("SUP-023", "SUP-045", "SUP-049")
def test_allow_narrows_exp_to_mission_expiry(env):
    ss, ps, _ = env
    s256 = connected(env, resources=(HR, MAIL, CAL))
    exp = ss.store.missions[f"{ps.issuer}|{s256}"].blob["expires_at"]
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    d = r.json()
    assert d["decision"] == "allow" and isinstance(d["exp"], int)
    from aauth_supervision_server.policy import _iso_to_epoch

    assert d["exp"] == int(_iso_to_epoch(exp))
    pt = _decision(ps, ss, act="person_token", mission_s256=s256, resource=HR,
                   agent_token=ps.agent_token(AGENT))
    assert pt.json()["exp"] == d["exp"]


@pytest.mark.req("SUP-025")
def test_ask_carries_summary_and_apply_options(env):
    ss, ps, _ = env
    s256 = connected(env)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    d = r.json()
    assert d["decision"] == "ask" and d["summary"]
    assert {o["value"] for o in d["apply_options"]} == {"once", "mission", "always"}


@pytest.mark.req("SUP-026", "SUP-030")
def test_response_echoes_sdi_and_signs_as_issuer(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["sdi"] == sdi
    assert 'id="https://ss.example"' in r.headers["Signature-Key"]


@pytest.mark.req("SUP-028", "SUP-029")
def test_retry_later_gets_identical_signed_response(env):
    ss, ps, clock = env
    s256 = connected(env)
    sdi, r1, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    body = next(b for p, b, _ in ps.sent if p == "/decision" and b.get("sdi") == sdi)
    clock.t += 30  # the retry is delivered later and signed later by the PS
    r2 = ps.call(ss, "POST", "/decision", body)
    assert r2.body == r1.body
    assert r2.headers["Signature"] == r1.headers["Signature"]
    assert r2.headers["Signature-Input"] == r1.headers["Signature-Input"]
    for c in ('"@status"', '"content-type"', '"content-digest"', '"content-digest";req',
              '"@authority";req', '"@path";req'):
        assert c in r1.headers["Signature-Input"]


@pytest.mark.req("SUP-028", "SUP-P04")
def test_retry_while_pending_gets_same_location():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock))
    sdi, r1, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    body = next(b for p, b, _ in ps.sent if p == "/decision" and b.get("sdi") == sdi)
    r2 = ps.call(ss, "POST", "/decision", body)
    assert r1.status == r2.status == 202
    assert r1.headers["Location"] == r2.headers["Location"]


@pytest.mark.req("SUP-027", "SUP-029")
def test_poll_answer_is_signed_for_the_poll():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    ps.call(ss, "POST", loc, {"action": "clarification_response",
                              "clarification_response": "status report"})
    g = ps.call(ss, "GET", loc)  # verified by the PS against this GET
    assert g.status == 200 and '"@path";req' in g.headers["Signature-Input"]
    assert '"content-digest";req' not in g.headers["Signature-Input"]


@pytest.mark.req("SUP-P05")
def test_clarify_updated_request():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=(HR, MAIL, CAL))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    # Core, Updated Request: the same resource (same iss, ps, sub, mission_s256), a
    # smaller request. Here: read instead of send.
    rt = ps.resource_token(MAIL, "mail.read", mission_s256=s256)
    ans = ps.call(ss, "POST", loc, {"action": "updated_request", "resource_token": rt,
                                    "presented_token": "a.b.c"})
    assert ans.status == 200 and ans.json()["decision"] == "allow"
    bad = ps.call(ss, "POST", loc, {"action": "nonsense"})
    assert bad.status == 200  # already resolved: the terminal answer is replayed


@pytest.mark.req("SUP-P16")
def test_updated_request_for_another_resource_is_refused():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=(HR, MAIL, CAL))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    swapped = ps.call(ss, "POST", loc, {"action": "updated_request", "presented_token": "a.b.c",
                                        "resource_token": ps.resource_token(CAL, mission_s256=s256)})
    assert swapped.status == 400
    assert swapped.json()["detail"] == "updated resource token differs from the original in iss"
    other_mission = ps.call(ss, "POST", loc, {"action": "updated_request",
                                              "presented_token": "a.b.c",
                                              "resource_token": ps.resource_token(MAIL, "mail.read")})
    assert other_mission.status == 400
    assert other_mission.json()["detail"].endswith("in mission_s256")
    # A refused update leaves the question open for a conforming answer.
    assert ps.call(ss, "GET", loc).status == 202


@pytest.mark.req("SUP-P05")
def test_clarify_rounds_are_bounded():
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_rounds = 1
    s256 = connected((ss, ps, clock))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202
    ans = ps.call(ss, "POST", r.headers["Location"],
                  {"action": "clarification_response", "clarification_response": ""})
    assert ans.json()["decision"] in ("ask", "allow")


@pytest.mark.req("SUP-041", "SUP-042")
@pytest.mark.parametrize("missing", ["resource", "agent_token"])
def test_person_token_required_members(env, missing):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    body = {"act": "person_token", "resource": HR, "agent_token": ps.agent_token(AGENT)}
    del body[missing]
    assert _decision(ps, ss, **body).status == 400


@pytest.mark.req("SUP-046")
@pytest.mark.parametrize("missing", ["resource_token", "presented_token"])
def test_auth_token_required_members(env, missing):
    ss, ps, _ = env
    ps.connect(ss, SUB)
    body = {"act": "auth_token", "resource_token": ps.resource_token(CAL),
            "presented_token": "a.b.c"}
    del body[missing]
    assert _decision(ps, ss, **body).status == 400


@pytest.mark.req("SUP-043", "SUP-044", "SUP-047")
def test_optional_chain_tokens_accepted(env):
    ss, ps, _ = env
    s256 = connected(env, resources=(HR, MAIL, CAL))
    up = make_jwt(ps.ap_key, "aa-agent+jwt", {"iss": "https://up.example", "sub": "x"})
    r = _decision(ps, ss, act="person_token", mission_s256=s256, resource=HR,
                  agent_token=ps.agent_token(AGENT), upstream_token=up, subagent_token=up)
    assert r.json()["decision"] == "allow"
    r = _decision(ps, ss, act="auth_token", mission_s256=s256,
                  resource_token=ps.resource_token(CAL), presented_token="a.b.c",
                  upstream_token=up)
    assert r.json()["decision"] == "allow"


@pytest.mark.req("SUP-051", "SUP-053", "SUP-054", "SUP-055", "SUP-056", "SUP-057")
def test_decision_resolved_members(env):
    ss, ps, _ = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    base = {"event": "decision.resolved", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "sdi": sdi}
    assert ps.call(ss, "POST", "/event", base | {"id": "e-r0"}).status == 400  # answer required
    ok = ps.call(ss, "POST", "/event", base | {
        "id": "e-r1", "answer": "deny", "recommendation": "", "transcript": [
            {"from": "person", "text": "why?"}, {"from": "agent", "text": "status"}],
        "supervisor": "unavailable"})  # no reason: a reason is never required
    assert ok.status == 201 and ok.body == b""
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "resolved_deny"


@pytest.mark.req("R3-019")
def test_forwarded_proposal_must_match_r3_s256():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock))
    raw, digest = r3_bytes({"operations": [{"operationId": "send_email"}],
                            "parameters": {"to": "a@corp.example"}})
    body = {"sdi": "d-x", "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token(MAIL, "", digest, s256),
            "presented_token": "a.b.c",
            "r3_proposal": b64u(raw.replace(b"corp.example", b"evil.example"))}
    r = ps.call(ss, "POST", "/decision", body)
    assert r.status == 400 and "r3_s256" in r.json()["detail"]


@pytest.mark.req("R3-002", "R3-003")
def test_digest_parameter_is_not_a_value():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock))
    prop = {"operations": [{"operationId": "send_email"}],
            "parameters": {"to": {"s256": "abc", "excerpt": "a@evil.example"}}}
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=prop)
    # The recipient is a digest: not visible, so the conservative class applies (ask).
    assert r.json()["decision"] == "ask"


@pytest.mark.req("SUP-P01")
def test_ss_only_fetches_keying_material(env):
    ss, ps, _ = env
    s256 = connected(env)
    ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    calls = ss.resolver.fetcher.calls  # type: ignore[attr-defined]
    assert calls and all("/.well-known/" in u for u in calls)


@pytest.mark.req("SUP-P12", "SUP-P13")
def test_replay_rebuilds_state_on_new_ss(env):
    ss, ps, clock = env
    s256 = connected(env)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    ps.issued(ss, SUB, AGENT, s256, sdi, CAL)
    ss2, _, _ = make_env()
    ss2.resolver = ss.resolver
    ss2.clock = clock
    ss2.cfg.trusted_ps = ss.cfg.trusted_ps
    ps.ss_jwk = ss2.key.public_jwk()
    _, before, _ = ps.auth_token_request(ss2, SUB, AGENT, s256, CAL)
    assert before.status == 404  # unknown_sub until the PS connects and replays
    ps.replay_to(ss2, SUB, AGENT)
    assert f"{ps.issuer}|{s256}" in ss2.store.missions
    hist = ss2.store.missions[f"{ps.issuer}|{s256}"].history
    assert [h.action_class for h in hist] == ["write"]
