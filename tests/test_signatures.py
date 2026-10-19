from __future__ import annotations

import base64
import hashlib
import time

import pytest

from aauth_supervision_server import sfv
from aauth_supervision_server.egress import EgressPolicy, FetchError, HttpsFetcher, StaticFetcher
from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.httpsig import (
    HttpRequest,
    HttpResponse,
    build_components,
    check_content_digest,
    content_digest,
    sign_message,
    signature_base,
    verify_request,
    verify_response,
)
from aauth_supervision_server.jwk import SigningKey, key_from_jwk
from aauth_supervision_server.resolver import JwksUriResolver

PS = "https://ps.example"
SK_HDR = 'sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="k1"'
REQ = ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"]


def _ps(alg: str = "Ed25519"):
    key = SigningKey.generate("k1", alg)
    fetcher = StaticFetcher({
        f"{PS}/.well-known/aauth-person.json": {"issuer": PS, "jwks_uri": f"{PS}/jwks"},
        f"{PS}/jwks": {"keys": [key.public_jwk()]},
    })
    return key, JwksUriResolver(fetcher)


def _signed(key, body=b'{"a":1}', created=None, names=REQ, sk=SK_HDR):
    req = HttpRequest("POST", "ss.example", "/decision",
                      {"content-type": "application/json", "content-digest": content_digest(body)},
                      body)
    h = sign_message(names, key, sk, req, created=created)
    req.headers.update({k.lower(): v for k, v in h.items()})
    return req


# ------------------------------------------------------------------- sfv


def test_sfv_roundtrip_dictionary():
    v = 'sig=("@method" "content-digest";req);created=1;keyid="k", b=?0, c=tok;x=1'
    d = sfv.parse_dictionary(v)
    assert sfv.ser_dictionary(d) == v


@pytest.mark.parametrize("bad", ['a=', 'a=(', 'a="x', 'A=1', 'a=1,', 'a=:%%:'])
def test_sfv_rejects(bad):
    with pytest.raises(sfv.SFVError):
        sfv.parse_dictionary(bad)


# --------------------------------------------------------- content-digest


def test_content_digest_roundtrip():
    assert check_content_digest(content_digest(b"x"), b"x")
    assert not check_content_digest(content_digest(b"x"), b"y")
    assert not check_content_digest(None, b"x")


def test_rfc9530_example():
    # RFC 9530 B.1: {"hello": "world"}
    body = b'{"hello": "world"}'
    assert content_digest(body) == "sha-256=:" + base64.b64encode(
        hashlib.sha256(body).digest()).decode() + ":"


# ------------------------------------------------------- signature base


def test_signature_base_rfc9421_shape():
    req = HttpRequest("post", "Example.COM:443", "/foo", {"content-type": "application/json"})
    comps = build_components(["@method", "@authority", "@path", "content-type"], 1618884473, "k")
    base = signature_base(comps, req).decode()
    assert base == (
        '"@method": POST\n"@authority": example.com\n"@path": /foo\n'
        '"content-type": application/json\n'
        '"@signature-params": ("@method" "@authority" "@path" "content-type")'
        ';created=1618884473;keyid="k"'
    )


@pytest.mark.req("SUP-029")
def test_response_req_components():
    req = HttpRequest("POST", "ss.example", "/decision", {"content-digest": "sha-256=:AA==:"})
    resp = HttpResponse(200, {"content-type": "application/json", "content-digest": "x"})
    comps = build_components(["@status", "content-digest", "content-digest;req", "@path;req"], 5)
    base = signature_base(comps, req, resp).decode().splitlines()
    assert base[:4] == ['"@status": 200', '"content-digest": x',
                        '"content-digest";req: sha-256=:AA==:', '"@path";req: /decision']


# ------------------------------------------------------------- verification


@pytest.mark.req("SUP-011", "VER-001")
@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_verify_ok(alg):
    key, res = _ps(alg)
    v = verify_request(_signed(key), res, required=REQ)
    assert v.id == PS and v.kid == "k1"


@pytest.mark.req("VER-016")
def test_missing_headers():
    _, res = _ps()
    with pytest.raises(SignatureError) as e:
        verify_request(HttpRequest("POST", "a", "/"), res, required=REQ)
    assert e.value.error == "invalid_signature" and e.value.status == 401


@pytest.mark.req("SUP-011", "VER-016")
def test_required_components():
    key, res = _ps()
    req = _signed(key, names=["@method", "@authority", "@path", "signature-key"])
    with pytest.raises(SignatureError) as e:
        verify_request(req, res, required=REQ)
    assert e.value.error == "invalid_input"


@pytest.mark.req("VER-017")
def test_window_and_skew():
    key, res = _ps()
    now = int(time.time())
    with pytest.raises(SignatureError) as e:
        verify_request(_signed(key, created=now - 120), res, required=REQ, now=now)
    assert e.value.error == "invalid_signature"
    with pytest.raises(SignatureError) as e:
        verify_request(_signed(key, created=now + 120), res, required=REQ, now=now)
    assert e.value.error == "clock_skew"


def test_tampered_body_and_signature():
    key, res = _ps()
    req = _signed(key)
    req.body = b'{"a":2}'
    with pytest.raises(SignatureError):
        verify_request(req, res, required=REQ)
    req = _signed(key)
    req.headers["content-type"] = "text/plain"
    with pytest.raises(SignatureError) as e:
        verify_request(req, res, required=REQ)
    assert e.value.error == "invalid_signature"


@pytest.mark.req("VER-008", "VER-018")
def test_wrong_scheme():
    key, res = _ps()
    req = _signed(key, sk='sig=hwk;kty="OKP";crv="Ed25519";x="AA";alg="Ed25519"')
    with pytest.raises(SignatureError) as e:
        verify_request(req, res, required=REQ)
    assert e.value.error == "unsupported_scheme"
    assert e.value.headers["Accept-Signature-Scheme"] == "jwks_uri"


@pytest.mark.req("VER-008", "VER-019")
def test_wrong_dwk_and_unknown_kid():
    key, res = _ps()
    req = _signed(key, sk='sig=jwks_uri;id="https://ps.example";dwk="aauth-agent.json";kid="k1"')
    with pytest.raises(SignatureError):
        verify_request(req, res, required=REQ)
    req = _signed(key, sk='sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="zz"')
    with pytest.raises(SignatureError) as e:
        verify_request(req, res, required=REQ)
    assert e.value.error == "unknown_key"


@pytest.mark.req("SUP-030", "REF-019", "REF-020", "VER-019")
def test_issuer_mismatch_and_missing():
    key = SigningKey.generate("k1")
    for meta, code in (({"issuer": "https://evil.example", "jwks_uri": f"{PS}/jwks"},
                        "issuer_mismatch"), ({"jwks_uri": f"{PS}/jwks"}, "issuer_missing")):
        res = JwksUriResolver(StaticFetcher({f"{PS}/.well-known/aauth-person.json": meta,
                                             f"{PS}/jwks": {"keys": [key.public_jwk()]}}))
        with pytest.raises(SignatureError) as e:
            verify_request(_signed(key), res, required=REQ)
        assert e.value.error == code


@pytest.mark.req("VER-030")
def test_cross_origin_jwks_refused():
    key = SigningKey.generate("k1")
    res = JwksUriResolver(StaticFetcher({
        f"{PS}/.well-known/aauth-person.json": {"issuer": PS, "jwks_uri": "https://cdn.example/j"},
        "https://cdn.example/j": {"keys": [key.public_jwk()]}}))
    with pytest.raises(SignatureError):
        verify_request(_signed(key), res, required=REQ)


@pytest.mark.parametrize("jwk,code", [
    ({"kty": "OKP", "crv": "Ed25519", "x": "AA"}, "unsupported_algorithm"),
    ({"kty": "OKP", "crv": "Ed25519", "x": "AA", "alg": "EdDSA"}, "unsupported_algorithm"),
    ({"kty": "oct", "k": "AA", "alg": "HS256"}, "unsupported_algorithm"),
    ({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA", "alg": "Ed25519"}, "invalid_key"),
])
@pytest.mark.req("VER-002", "VER-003", "VER-004", "VER-005")
def test_algorithm_determination(jwk, code):
    with pytest.raises(SignatureError) as e:
        key_from_jwk(jwk)
    assert e.value.error == code


@pytest.mark.req("SUP-029")
def test_response_signing_roundtrip():
    ss = SigningKey.generate("ss1")
    req = _signed(SigningKey.generate("k1"))
    body = b'{"decision":"allow"}'
    resp = HttpResponse(200, {"content-type": "application/json",
                              "content-digest": content_digest(body)}, body)
    names = ["@status", "content-type", "content-digest", "content-digest;req",
             "@authority;req", "@path;req"]
    h = sign_message(names, ss, 'sig=jwks_uri;id="https://ss.example";dwk="aauth-supervisor.json";'
                     'kid="ss1"', req, resp)
    resp.headers.update({k.lower(): v for k, v in h.items()})
    assert verify_response(resp, req, key_from_jwk(ss.public_jwk()), names) == "https://ss.example"
    resp.body = b'{"decision":"deny"}'
    with pytest.raises(SignatureError):
        verify_response(resp, req, key_from_jwk(ss.public_jwk()), names)


def test_rfc9421_b26_ed25519_vector():
    """RFC 9421 Appendix B.2.6: signing with Ed25519 reproduces the published signature."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    pem = (b"-----BEGIN PRIVATE KEY-----\n"
           b"MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
           b"-----END PRIVATE KEY-----\n")
    k = load_pem_private_key(pem, None)
    req = HttpRequest("POST", "example.com", "/foo",
                      {"date": "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json",
                       "content-length": "18"}, query="param=Value&Pet=dog")
    comps = build_components(["date", "@method", "@path", "@authority", "content-type",
                              "content-length"], 1618884473, "test-key-ed25519")
    sig = base64.b64encode(k.sign(signature_base(comps, req))).decode()  # type: ignore[call-arg]
    assert sig == ("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lI"
                   "p5WPpBKRCw==")


def test_private_jwk_roundtrip():
    for alg in ("Ed25519", "ES256"):
        k = SigningKey.generate("x", alg)
        k2 = SigningKey.from_private_jwk(k.private_jwk())
        assert key_from_jwk(k.public_jwk()).verify(k2.sign(b"m"), b"m")


def _signed_response(ss, req, created=None):
    body = b'{"decision":"allow"}'
    resp = HttpResponse(200, {"content-type": "application/json",
                              "content-digest": content_digest(body)}, body)
    names = ["@status", "content-type", "content-digest", "content-digest;req",
             "@authority;req", "@path;req"]
    h = sign_message(names, ss, 'sig=jwks_uri;id="https://ss.example";dwk="aauth-supervisor.json";'
                     'kid="ss1"', req, resp, created=created)
    resp.headers.update({k.lower(): v for k, v in h.items()})
    return resp, names


def test_response_window_boundary():
    # Kills the >/>= boundary mutant on the response signature window: a response
    # created exactly `window` seconds ago still verifies; one second past it does not.
    ss = SigningKey.generate("ss1")
    req = _signed(SigningKey.generate("k1"))
    pub = key_from_jwk(ss.public_jwk())
    now = 1_700_000_000
    resp, names = _signed_response(ss, req, created=now - 300)
    # exactly on the window edge: must still verify (strict > keeps the boundary valid)
    assert verify_response(resp, req, pub, names, now=now, window=300) == "https://ss.example"
    # one second beyond the window: must be rejected
    with pytest.raises(SignatureError) as e:
        verify_response(resp, req, pub, names, now=now + 1, window=300)
    assert e.value.error == "invalid_signature"


def test_response_malformed_members():
    # Kills the and/or mutant in the member type-guard: a Signature-Input whose label
    # value is an Item (not an InnerList) must be rejected as malformed, not accepted.
    ss = SigningKey.generate("ss1")
    req = _signed(SigningKey.generate("k1"))
    resp, names = _signed_response(ss, req)
    # Replace the Signature-Input inner list with a bare item for the same label.
    si = sfv.parse_dictionary(resp.headers["signature-input"])
    label = next(iter(si))
    resp.headers["signature-input"] = f'{label}="not-an-inner-list"'
    with pytest.raises(SignatureError) as e:
        verify_response(resp, req, key_from_jwk(ss.public_jwk()), names)
    assert e.value.error == "invalid_signature"
    assert "malformed signature members" in e.value.detail


@pytest.mark.req("VER-030")
def test_egress_refuses_http_and_private():
    f = HttpsFetcher(EgressPolicy(timeout=1))
    with pytest.raises(FetchError):
        f.fetch_json("http://example.com/x")
    with pytest.raises(FetchError):
        f.fetch_json("https://127.0.0.1/x")
