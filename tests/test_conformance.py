"""Conformance tests for matrix rows not covered by test_protocol.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message
from aauth_supervision_server.jwk import b64u, b64u_decode
from aauth_supervision_server.service import TrustedPS
from aauth_supervision_server.testing import make_jwt, r3_bytes

HR, MAIL, CAL = "https://hr.example", "https://mail.example", "https://calendar.example"


def _decision(ps, ss, **body):
    base = {"sdi": ps.nid("d"), "iat": 1, "sub": SUB, "agent": AGENT}
    return ps.call(ss, "POST", "/decision", base | body)


@pytest.mark.req("SUP-011", "VER-010")
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


@pytest.mark.req("SUP-011", "VER-010")
def test_body_signature_must_cover_content_type(env):
    ss, ps, clock = env
    ps.connect(ss, SUB)
    raw = b'{"action":"connect","id":"c-1","iat":1,"sub":"x"}'
    req = HttpRequest("POST", "ss.example", "/connect",
                      {"content-type": "application/json", "content-digest": content_digest(raw)},
                      raw)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    h = sign_message(["@method", "@authority", "@path", "signature-key", "content-digest"],
                     ps.key, sk, req, created=int(clock()))
    req.headers.update({k.lower(): v for k, v in h.items()})
    r = ss.handle(req)
    assert r.status == 401 and "Signature-Error" in r.headers


@pytest.mark.req("SUP-026")
def test_mission_answers_echo_the_sdi(env):
    ss, ps, clock = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/mission", {"sdi": "d-prop", "iat": int(clock()), "sub": SUB,
                                         "agent": AGENT, "agent_token": ps.agent_token(AGENT),
                                         "description": "x", "resources": []})
    assert r.json()["sdi"] == "d-prop"
    s256 = connected(env)
    for action, member in (("update", "description"), ("completion", "summary")):
        r = ps.call(ss, "POST", f"/mission/{s256}", {"action": action, "sdi": f"d-{action}",
                                                     "iat": int(clock()), "sub": SUB,
                                                     "agent": AGENT, member: "x"})
        assert r.json()["sdi"] == f"d-{action}"


@pytest.mark.req("SUP-P02")
def test_a_repeated_event_records_nothing_new(env):
    ss, ps, clock = env
    s256 = connected(env)
    ev = {"event": "audit.recorded", "id": "e-dup", "iat": int(clock()), "sub": SUB,
          "agent": AGENT, "mission_s256": s256, "action": "Export", "parameters": {}}
    for _ in range(3):
        assert ps.call(ss, "POST", "/event", ev).status == 201
    assert len(ss.store.missions[f"{ps.issuer}|{s256}"].history) == 1


@pytest.mark.req("SUP-012", "SUP-013", "SUP-014", "SUP-015", "SUP-016", "SUP-032", "REF-050")
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


IAT_NUMBER = "member 'iat' must be a finite JSON number of at most 2**53 - 1 either way"
IAT_TYPE = "member 'iat' has the wrong JSON type"


def _signed_raw(ss, ps, clock, path, raw):
    """`raw` sent as written, signed: a number in a form `json.dumps` never writes (an
    exponent, NaN, Infinity) reaches the SS as such."""
    req = HttpRequest("POST", "ss.example", path,
                      {"content-type": "application/json", "content-digest": content_digest(raw)},
                      raw)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    h = sign_message(["@method", "@authority", "@path", "signature-key", "content-digest",
                      "content-type"], ps.key, sk, req, created=int(clock()))
    req.headers.update({k.lower(): v for k, v in h.items()})
    return ss.handle(req)


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("iat, detail", [
    ("now", IAT_TYPE), ("1790600000", IAT_TYPE), (True, IAT_TYPE), (False, IAT_TYPE),
    ([1], IAT_TYPE), ({"s": 1}, IAT_TYPE), (None, "missing member(s): iat"),
    (2.0 ** 60, IAT_NUMBER), (2 ** 60, IAT_NUMBER), (2 ** 53, IAT_NUMBER),
    (-(2 ** 53), IAT_NUMBER), (10 ** 400, IAT_NUMBER), (float("nan"), IAT_NUMBER),
    (float("inf"), IAT_NUMBER), (float("-inf"), IAT_NUMBER)])
def test_an_iat_that_is_not_a_finite_number_of_seconds_is_refused_here(env, iat, detail):
    # L198 gives `iat` as "seconds since the epoch" and says no more: any JSON number is
    # seconds, a fraction too (`tests/test_iat_seconds.py`). One no JSON parser holds
    # exactly (past 2**53 - 1 either way, I-JSON), NaN and the infinities (no JSON numbers,
    # which Python's reader takes all the same), and anything not a number are refused,
    # and the refusal says which.
    ss, ps, _ = env
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c", "iat": iat, "sub": SUB})
    assert (r.status, r.json()["error"], r.json()["detail"]) == (400, "invalid_request", detail)


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("written", [b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400",
                                     b"9007199254740992", b"-9007199254740992",
                                     b"9.007199254740992e15"])
def test_an_iat_written_as_no_finite_time_is_refused_here(env, written):
    ss, ps, clock = env
    raw = b'{"action":"connect","id":"c","iat":' + written + b',"sub":"' + SUB.encode() + b'"}'
    r = _signed_raw(ss, ps, clock, "/connect", raw)
    assert r.status == 400 and json.loads(r.body)["detail"] == IAT_NUMBER
    assert f"{ps.issuer}|{SUB}" not in ss.store.connections


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("written, read", [
    (b"1.7906e9", 1790600000), (b"17906E5", 1790600000), (b"1790600000e0", 1790600000),
    (b"1.7906000009e9", 1790600000), (b"1790600000.0", 1790600000),
    (b"9.007199254740991E15", 2 ** 53 - 1)])
def test_an_iat_written_with_an_exponent_is_read_as_its_number(env, written, read):
    # A number of seconds written with an exponent or a decimal point is a JSON number all
    # the same (RFC 8259 Section 6): sent as written, signed, taken, and read as the whole
    # second it falls in.
    ss, ps, clock = env
    raw = b'{"action":"connect","id":"c","iat":' + written + b',"sub":"' + SUB.encode() + b'"}'
    r = _signed_raw(ss, ps, clock, "/connect", raw)
    assert r.status == 200 and json.loads(r.body) == {"status": "connected"}
    raw = (b'{"event":"audit.recorded","id":"e-1","iat":' + written + b',"sub":"'
           + SUB.encode() + b'","agent":"' + AGENT.encode() + b'","action":"WebSearch"}')
    assert _signed_raw(ss, ps, clock, "/event", raw).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    assert h.iat == read and type(h.iat) is int


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


@pytest.mark.req("SUP-023", "SUP-049")
def test_allow_narrows_exp_to_mission_expiry(env):
    ss, ps, clock = env
    s256 = connected(env, resources=(HR, MAIL, CAL))
    from aauth_supervision_server.policy import _iso_to_epoch
    from aauth_supervision_server.store import Store

    blob = ss.store.missions[f"{ps.issuer}|{s256}"].blob
    # A mission ending within the hour: its expiry is earlier than the auth-token cap
    # (decision + one hour, Supervision L508), so both acts carry the mission's.
    far = int(_iso_to_epoch(blob["expires_at"]))
    assert far > int(clock()) + Store.OPEN_ISSUANCE
    blob["expires_at"] = datetime.fromtimestamp(int(clock()) + 600, UTC).isoformat().replace(
        "+00:00", "Z")
    exp = blob["expires_at"]
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    d = r.json()
    assert d["decision"] == "allow" and isinstance(d["exp"], int)

    assert d["exp"] == int(_iso_to_epoch(exp))
    pt = _decision(ps, ss, act="person_token", mission_s256=s256, resource=HR,
                   agent_token=ps.agent_token(AGENT))
    assert pt.json()["exp"] == d["exp"]


@pytest.mark.req("SUP-P09")
def test_a_permission_allow_carries_no_exp(env):
    """Supervision defines `exp` on the allow of a person token (L485) and an auth token
    (L508); a permission allow becomes `permission: granted` (L531), which has no
    lifetime, and this SS counts a grant as never expiring. So it sends no `exp` there,
    even in a mission with an `expires_at`."""
    ss, ps, clock = env
    s256 = connected(env, tools=[{"name": "Export", "description": "Export a file"}])
    assert "expires_at" in ss.store.missions[f"{ps.issuer}|{s256}"].blob
    r = _decision(ps, ss, act="permission", mission_s256=s256, action="Export")
    assert r.json()["decision"] == "allow" and "exp" not in r.json()


def _with_typ(token: str, typ: str) -> str:
    """The same token with another `typ` header (the SS reads forwarded tokens, it does
    not verify their signatures: the PS did)."""
    head = json.loads(b64u_decode(token.split(".")[0])) | {"typ": typ}
    return b64u(json.dumps(head).encode()) + "." + token.split(".", 1)[1]


@pytest.mark.parametrize("typ,status", [
    ("aa-resource+jwt", 200), ("application/aa-resource+jwt", 200), ("AA-Resource+JWT", 200),
    ("aa-auth+jwt", 400), ("aa-person+jwt", 400), ("JWT", 400), (None, 400)])
def test_a_forwarded_resource_token_is_read_only_with_its_typ(env, typ, status):
    """Protocol L2896: implementations "MUST check `typ` before acting on any AAuth JWT".
    The SS acts on the resource token's claims, so it checks the header is a resource
    token's, compared as RFC 7515 Section 4.1.9 compares a media type (case-insensitive,
    `application/` implied)."""
    ss, ps, _ = env
    s256 = connected(env)
    rt = ps.resource_token(CAL, mission_s256=s256)
    if typ is None:
        head = json.loads(b64u_decode(rt.split(".")[0]))
        del head["typ"]
        rt = b64u(json.dumps(head).encode()) + "." + rt.split(".", 1)[1]
    else:
        rt = _with_typ(rt, typ)
    r = _decision(ps, ss, act="auth_token", mission_s256=s256, agent_token=ps.agent_token(AGENT),
                  resource_token=rt, presented_token="a.b.c")
    assert r.status == status, r.json()
    if status == 400:
        assert r.json()["error"] == "invalid_request"


@pytest.mark.parametrize("header", [b"[1]", b'"aa-resource+jwt"', b"{", b"\xff"])
def test_a_forwarded_resource_token_whose_header_is_not_an_object_is_refused(env, header):
    ss, ps, _ = env
    s256 = connected(env)
    rt = ps.resource_token(CAL, mission_s256=s256)
    rt = b64u(header) + "." + rt.split(".", 1)[1]
    r = _decision(ps, ss, act="auth_token", mission_s256=s256, agent_token=ps.agent_token(AGENT),
                  resource_token=rt, presented_token="a.b.c")
    assert r.status == 400 and r.json()["error"] == "invalid_request"


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
    # A connect confirmed by the operator is answered on the poll: signed for that GET.
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    loc = r.headers["Location"]
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
    ok = ss.handle(HttpRequest("POST", "ss.example", "/interaction",
                               {"content-type": "application/x-www-form-urlencoded"},
                               f"code={code}&admin_token=operator-secret".encode()))
    assert ok.status == 200
    g = ps.call(ss, "GET", loc)  # verified by the PS against this GET
    assert g.status == 200 and '"@path";req' in g.headers["Signature-Input"]
    assert '"content-digest";req' not in g.headers["Signature-Input"]


def test_a_pending_url_is_gone_once_it_returned_a_terminal_response():
    """Protocol L2840: "Once a terminal response is returned, the pending URL MUST return
    `410 Gone`". The clarification reply is answered with the decision; after it the URL
    is gone for every method. The record itself stays: the decision is still on file."""
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    loc = r.headers["Location"]
    a = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                  "clarification_response": "status report"})
    assert a.status == 200
    for m, b in (("GET", None), ("POST", {"action": "clarification_response",
                                          "clarification_response": "again"}),
                 ("DELETE", None)):
        assert ps.call(ss, m, loc, b).status == 410, m
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == a.json()["decision"]
    # A 0.1.x snapshot keeps no `gone`: an answered clarification is gone all the same.
    p = ss.store.pending[loc.rsplit("/", 1)[1]]
    p.gone = p.cancelled = False
    assert ps.call(ss, "GET", loc).status == 410


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
    assert bad.status == 410  # Protocol L2840: the terminal answer was returned, URL is gone


@pytest.mark.req("SUP-P16", "REF-009", "REF-050")
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


@pytest.mark.req("SUP-051", "SUP-053", "SUP-054", "SUP-055", "SUP-056")
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
