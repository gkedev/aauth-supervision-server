"""Hardening regressions: sdi reuse, issuance vs answers, connect replay, the PS verifier,
covered query and digests, snapshot quarantine, strict Content-Length (one test per defect)."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import threading

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.http_server import serve
from aauth_supervision_server.httpsig import HttpResponse, check_content_digest, verify_response
from aauth_supervision_server.jwk import key_from_jwk
from aauth_supervision_server.store import Store

HR, MAIL, CAL = "https://hr.example", "https://mail.example", "https://calendar.example"
SEND = {"operations": [{"operationId": "send_email"}]}


@pytest.mark.req("SUP-028")
def test_sdi_reuse_for_a_different_act_is_refused():
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=(HR, MAIL, CAL))
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, HR, proposal={
        "operations": [{"operationId": "get"}], "parameters": {},
        "result": {"contains": ["salary"]}})
    ps.issued(ss, SUB, AGENT, s256, sdi, HR, proposal=prop)
    ps.auth_token_request(ss, SUB, AGENT, s256, CAL, sdi="d-reuse")
    ext = SEND | {"parameters": {"to": "x@evil.example"}}
    _, fresh, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=ext)
    assert fresh.json()["decision"] == "deny"
    _, reused, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=ext, sdi="d-reuse")
    assert reused.status == 400 and "different request" in reused.json()["detail"]


def test_issuance_does_not_answer_an_ask():
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), resources=(HR, MAIL, CAL))
    other = "https://unlisted.example"
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, other)
    assert r.json()["decision"] == "ask"
    ps.issued(ss, SUB, AGENT, s256, sdi, other)  # the PS skipped the person
    rec = ss.store.decisions[f"{ps.issuer}|{sdi}"]
    assert rec.decision == "ask"  # still unanswered
    hist = ss.store.missions[f"{ps.issuer}|{s256}"].history
    assert hist and "(issued after ask)" in hist[-1].detail  # but the fact counts
    # A later genuine answer still works, and only it can create reach.
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "mission")
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "resolved_allow"


@pytest.mark.req("SUP-019", "SUP-022")
def test_captured_connect_or_disconnect_cannot_replay():
    ss, ps, _ = make_env()
    conn = {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB}
    disc = {"action": "disconnect", "id": "c-2", "iat": 2, "sub": SUB}
    assert ps.call(ss, "POST", "/connect", conn).json()["status"] == "connected"
    assert ps.call(ss, "POST", "/connect", disc).json()["status"] == "disconnected"
    # A replayed copy of the original connect does not undo the person's disconnect.
    assert ps.call(ss, "POST", "/connect", conn).json()["status"] == "disconnected"
    assert f"{ps.issuer}|{SUB}" not in ss.store.connections
    # A fresh connect does.
    fresh = {"action": "connect", "id": "c-3", "iat": 3, "sub": SUB}
    assert ps.call(ss, "POST", "/connect", fresh).json()["status"] == "connected"
    assert ps.call(ss, "POST", "/connect", disc).json()["status"] == "connected"


def test_ps_verifier_binds_issuer_and_window():
    ss, ps, clock = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c", "iat": 1, "sub": SUB})
    resp = ss.handle(req)
    hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.body)
    key = key_from_jwk(ps.ss_jwk)
    need = ["@status", "content-type", "content-digest"]
    assert verify_response(hr, req, key, need, expected_issuer="https://ss.example",
                           now=clock()) == "https://ss.example"
    with pytest.raises(SignatureError, match="not the SS called"):
        verify_response(hr, req, key, need, expected_issuer="https://other-ss.example", now=clock())
    with pytest.raises(SignatureError, match="window"):
        verify_response(hr, req, key, need, now=clock() + 3600)
    # A second complete label (one that also verifies nothing) is ambiguous: refuse.
    hr.headers["signature-key"] += ', decoy=jwks_uri;id="https://evil.example";dwk="x";kid="k"'
    hr.headers["signature-input"] += ', decoy=("@status");created=1'
    hr.headers["signature"] += ", decoy=:AAAA:"
    with pytest.raises(SignatureError, match="exactly one"):
        verify_response(hr, req, key, need, now=clock())


def test_query_must_be_covered():
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c", "iat": 1, "sub": SUB})
    req.query = "x=1"
    r = ss.handle(req)
    assert r.status in (400, 401)


def test_every_present_digest_must_match():
    body = b'{"a":1}'
    good = base64.b64encode(hashlib.sha256(body).digest()).decode()
    bad512 = base64.b64encode(b"\0" * 64).decode()
    assert check_content_digest(f"sha-256=:{good}:", body)
    assert not check_content_digest(f"sha-256=:{good}:, sha-512=:{bad512}:", body)
    assert not check_content_digest("md5=:AAAA:", body)  # nothing recognized


def test_unreadable_snapshot_is_quarantined(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(json.dumps({"version": 1, "missions": {"k": {"bogus": 1}}}))
    s = Store(str(p))
    assert s.load_error and not s.missions
    assert any(f.name.startswith("state.json.unreadable-") for f in tmp_path.iterdir())
    p.write_text(json.dumps({"version": 99}))
    assert "version" in Store(str(p)).load_error


@pytest.mark.parametrize("cl", ["+5", "5, 5", "0x5"])
def test_strict_content_length(cl):
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
        c.putrequest("POST", "/decision", skip_accept_encoding=True)
        c.putheader("Host", "ss.example")
        c.putheader("Content-Length", cl)
        c.endheaders()
        assert c.getresponse().status == 400
        c.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
