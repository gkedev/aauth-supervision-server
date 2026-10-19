"""Hardening regressions: issuer origin, no request of the PS, member types and
stalled connections (one test per defect)."""

from __future__ import annotations

import socket
import threading
import time

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server import http_server
from aauth_supervision_server.service import ServerConfig

CAL = "https://calendar.example"


@pytest.mark.req("SUP-008")
@pytest.mark.parametrize("issuer", ["http://ss.example", "https://", "https://ss.example?x=1",
                                    "https://ss.example#f", "https://u@ss.example"])
def test_issuer_must_be_an_https_origin(issuer):
    # Endpoint URLs are built from the issuer, so the issuer itself is what is checked.
    with pytest.raises(ValueError, match="issuer must be an https URL"):
        ServerConfig(issuer=issuer)
    assert ServerConfig(issuer="https://ss.example").authority == "ss.example"


@pytest.mark.req("SUP-P01")
def test_ss_makes_no_request_of_the_ps_on_any_path():
    # Connect, proposal, approval, decisions, events, resolution and replay: the only
    # outbound fetches are the PS's metadata and JWKS (key discovery).
    env = make_env()
    ss, ps, clock = env
    s256 = connected(env)
    sdi, _, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    ps.issued(ss, SUB, AGENT, s256, sdi, CAL)
    ask_sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    assert r.json()["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, s256, ask_sdi, "allow", "once")
    ss2, _, _ = make_env()
    ss2.resolver = ss.resolver
    ss2.clock = clock
    ss2.cfg.trusted_ps = ss.cfg.trusted_ps
    ps.ss_jwk = ss2.key.public_jwk()
    ps.replay_to(ss2, SUB, AGENT)
    assert f"{ps.issuer}|{s256}" in ss2.store.missions
    calls = ss.resolver.fetcher.calls  # type: ignore[attr-defined]
    allowed = {ps.issuer + "/.well-known/aauth-person.json", ps.issuer + "/.well-known/jwks.json"}
    assert calls and set(calls) <= allowed


@pytest.mark.parametrize("member, value", [
    ("sub", 0), ("sub", []), ("sdi", {"a": 1}), ("agent", True), ("iat", "1"),
    ("iat", float("nan")), ("iat", 2 ** 53),
    ("description", ["x"]), ("parameters", "x"), ("tools", {}), ("resources", "x"),
    ("aud", [1]), ("exp", "soon")])
def test_a_member_of_the_wrong_type_is_invalid_request(member, value):
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    body = {"sdi": "p-1", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": "a.b.c",
            "description": "# d", member: value}
    r = ps.call(ss, "POST", "/mission", body)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    assert member in r.json()["detail"]


def test_a_stalled_client_releases_its_connection(monkeypatch):
    monkeypatch.setattr(http_server, "READ_TIMEOUT", 0.3)
    ss, _, _ = make_env()
    httpd = http_server.serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        s = socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5)
        s.sendall(b"POST /event HTTP/1.1\r\nHost: ss.example\r\nContent-Length: 100\r\n\r\n{")
        t0 = time.monotonic()
        assert s.recv(1024) == b""  # the server closes the stalled connection
        assert time.monotonic() - t0 < 4
        s.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
