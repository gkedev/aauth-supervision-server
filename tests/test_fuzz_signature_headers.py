"""Malformed signature headers get a clean 4xx, never a 500.

Every supervision request is signed, so the three signature headers are the first
untrusted input the SS parses. A broken header must map to invalid_signature (or
another 4xx), not to the defensive server_error catch-all in handle().
"""

from __future__ import annotations

import json

import pytest
from conftest import SUB, make_env

from aauth_supervision_server.httpsig import HttpRequest

# Structurally broken Structured-Field values and odd signature members.
BROKEN = [
    "", " ", "sig", "sig=", "sig=()", "=()", "sig=(,)", "sig=(\"@method\"",
    "sig=(\"@method\");created", "sig=(\"@method\");created=", "sig=:not-base64:",
    "sig=:::", "sig=(\"@method\");created=abc", "sig=\x00", "sig=(\"@method\" \"@method\")",
    "a=(),b=(),c=(),d=(),e=()", "sig=(" + " ".join(['"x"'] * 500) + ")",
    "SIG=(), sig=()", "sig=1.5", "sig=?1", "sig=@token", "sig=(;x=1)",
    "sig=(\"@authority\");keyid=\"k\";alg=\"ed25519\"", "💥=()", "sig=" + "a" * 10000,
    "sig=(), sig=()",  # duplicate dictionary keys
]


def _signed(env):
    ss, ps, _ = env
    assert ps.connect(ss, SUB).status == 200
    # A fresh connect request we can mutate per iteration.
    return ps.build("POST", "/connect",
                    {"action": "connect", "id": "c-fuzz", "iat": 1, "sub": SUB})


@pytest.mark.parametrize("field", ["signature", "signature-input", "signature-key"])
def test_malformed_signature_header_is_a_clean_4xx(field):
    env = make_env()
    ss, ps, _ = env
    base = _signed(env)
    bad = []
    for payload in BROKEN:
        headers = dict(base.headers)
        headers[field] = payload
        req = HttpRequest("POST", base.authority, "/connect", headers, base.body, "")
        resp = ss.handle(req)
        if resp.status == 500 or resp.status == 200:
            bad.append((payload[:40], resp.status, resp.body[:120]))
    assert not bad, f"{field}: {len(bad)} payloads were not a clean 4xx: {bad[:5]}"


def test_all_three_headers_simultaneously_broken():
    env = make_env()
    ss, ps, _ = env
    base = _signed(env)
    for payload in BROKEN:
        headers = dict(base.headers)
        for f in ("signature", "signature-input", "signature-key"):
            headers[f] = payload
        req = HttpRequest("POST", base.authority, "/connect", headers, base.body, "")
        resp = ss.handle(req)
        assert resp.status not in (200, 500), (payload[:40], resp.status)
        err = json.loads(resp.body)
        assert err.get("error")  # a named protocol error, not a bare crash


def test_missing_signature_headers():
    env = make_env()
    ss, ps, _ = env
    base = _signed(env)
    for drop in (["signature"], ["signature-input"], ["signature-key"],
                 ["signature", "signature-input", "signature-key"]):
        headers = {k: v for k, v in base.headers.items() if k not in drop}
        req = HttpRequest("POST", base.authority, "/connect", headers, base.body, "")
        resp = ss.handle(req)
        assert resp.status == 401 and json.loads(resp.body)["error"] == "invalid_signature"
