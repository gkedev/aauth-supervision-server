"""RFC 9421 verification at its edges: each check of `httpsig.py` on its own boundary.

`test_signatures.py` and the vectors prove the happy paths and the main attacks. These
pin every individual refusal (and its non-refusal neighbour), so a flipped comparison
or a dropped check fails a test that names it.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.httpsig import (
    MAX_LABELS,
    HttpRequest,
    HttpResponse,
    _check_alg_param,
    build_components,
    check_content_digest,
    content_digest,
    sign_message,
    signature_base,
    verify_request,
    verify_response,
)
from aauth_supervision_server.jwk import SigningKey, VerifyKey, key_from_jwk
from aauth_supervision_server.sfv import InnerList, Item, ser_dictionary

NOW = 1_790_600_000
PS = "https://ps.example"
REQUIRED = ["@method", "@authority", "@path"]
KEY = SigningKey.generate("k1")


class Resolver:
    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        return key_from_jwk(KEY.public_jwk())


def signed(created: Any = NOW, *, extra: dict[str, Any] | None = None, labels: int = 1,
           sk_params: str = f'id="{PS}";dwk="aauth-person.json";kid="k1"',
           query: str = "") -> HttpRequest:
    req = HttpRequest("POST", "ss.example", "/decision", {}, b"", query)
    comps = build_components(REQUIRED, 0, None, extra)
    comps.params["created"] = created
    sig = KEY.sign(signature_base(comps, req))
    names = [f"sig{i}" if i else "sig" for i in range(labels)]
    req.headers["signature-input"] = ser_dictionary({n: comps for n in names})
    req.headers["signature"] = ser_dictionary({n: Item(sig) for n in names})
    req.headers["signature-key"] = ", ".join(f"{n}=jwks_uri;{sk_params}" for n in names)
    return req


def verify(req: HttpRequest, **kw: Any) -> Any:
    return verify_request(req, Resolver(), required=REQUIRED, now=NOW, **kw)


def refused(req: HttpRequest, code: str, **kw: Any) -> SignatureError:
    with pytest.raises(SignatureError) as e:
        verify(req, **kw)
    assert e.value.error == code, e.value.detail
    return e.value


# ------------------------------------------------------------ message types


def test_message_defaults() -> None:
    r = HttpRequest("GET", "a", "/")
    assert (r.headers, r.body, r.query) == ({}, b"", "")
    s = HttpResponse(200)
    assert (s.headers, s.body) == ({}, b"")
    assert HttpRequest("GET", "a", "/").headers is not r.headers


def test_verified_signer_is_immutable() -> None:
    v = verify(signed())
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.id = "x"  # type: ignore[misc]


# ----------------------------------------------------------- content digest


def test_content_digest_variants() -> None:
    body = b'{"a":1}'
    assert check_content_digest(content_digest(body), body) is True
    import base64
    import hashlib
    s512 = base64.b64encode(hashlib.sha512(body).digest()).decode()
    assert check_content_digest(f"sha-512=:{s512}:", body) is True  # sha-256 absent
    assert check_content_digest("md5=:AAAA:", body) is False  # no known algorithm
    assert check_content_digest("((not a dictionary", body) is False
    assert check_content_digest("sha-256=1", body) is False  # not a byte sequence
    assert check_content_digest("sha-256=(1 2)", body) is False  # an inner list
    assert check_content_digest(None, body) is False


# ----------------------------------------------------------- signature base


def _base(names: list[str], req: HttpRequest, resp: HttpResponse | None = None) -> str:
    return signature_base(build_components(names, 1), req, resp).decode()


def test_query_and_target_uri_components() -> None:
    req = HttpRequest("GET", "SS.Example:443", "/pending/x", {}, b"", "a=1&b=2")
    assert '"@query": ?a=1&b=2' in _base(["@query"], req)
    assert '"@target-uri": https://ss.example/pending/x?a=1&b=2' in _base(["@target-uri"], req)
    bare = HttpRequest("GET", "ss.example", "", {}, b"", "")
    assert '"@query": ?\n' in _base(["@query"], bare)
    assert '"@target-uri": https://ss.example/\n' in _base(["@target-uri"], bare)


def test_status_is_a_response_component_only() -> None:
    req = HttpRequest("GET", "ss.example", "/")
    with pytest.raises(SignatureError, match="@status only on a response"):
        _base(["@status"], req)
    with pytest.raises(SignatureError, match="@status only on a response"):
        _base(["@status;req"], req, HttpResponse(200))
    assert '"@status": 200' in _base(["@status"], req, HttpResponse(200))


def test_header_values_are_trimmed_and_only_obs_fold_is_collapsed() -> None:
    req = HttpRequest("GET", "ss.example", "/", {"x-a": "  a  b  ", "x-b": "a\n   b"})
    assert '"x-a": a  b\n' in _base(["x-a"], req)
    assert '"x-b": a b\n' in _base(["x-b"], req)


# --------------------------------------------------------------- algorithm


def test_alg_parameter_must_match_the_key_when_present() -> None:
    vk = key_from_jwk(KEY.public_jwk())
    _check_alg_param(InnerList([], {}), vk)
    _check_alg_param(InnerList([], {"alg": "ed25519"}), vk)
    for bad in ("ecdsa-p256-sha256", 7):
        with pytest.raises(SignatureError, match="does not match the key"):
            _check_alg_param(InnerList([], {"alg": bad}), vk)


# ------------------------------------------------------- request verification


def test_valid_request_verifies() -> None:
    v = verify(signed())
    assert (v.id, v.dwk, v.kid, v.label, v.created) == (PS, "aauth-person.json", "k1", "sig",
                                                       NOW)


def test_all_three_headers_are_required() -> None:
    for drop in ("signature-input", "signature", "signature-key"):
        req = signed()
        del req.headers[drop]
        e = refused(req, "invalid_signature")
        assert "required" in e.detail


def test_a_label_must_appear_in_all_three_headers() -> None:
    req = signed()
    req.headers["signature"] = req.headers["signature"].replace("sig=", "other=")
    assert "no label" in refused(req, "invalid_signature").detail


@pytest.mark.parametrize("header,value", [
    ("signature-input", "sig=:YWJj:"),       # not an inner list of components
    ("signature", 'sig=("x")'),              # not a byte-sequence item
    ("signature", 'sig="not-bytes"'),        # an item, but not a byte sequence
    ("signature-key", 'sig=("jwks_uri")'),   # not an item
])
def test_each_signature_member_must_have_its_shape(header: str, value: str) -> None:
    """Each member is checked on its own: one well-formed member never covers for another."""
    req = signed()
    req.headers[header] = value
    assert refused(req, "invalid_signature").detail == "malformed signature member"


def test_when_every_label_fails_the_first_failure_is_reported() -> None:
    req = signed(labels=2)
    req.headers["signature-key"] = ('sig=jwks_uri;id="https://ps.example";dwk="x.json";kid="k1", '
                                    'sig1=jwks_uri;id="https://ps.example"')
    e = refused(req, "invalid_key")
    assert e.detail == "dwk 'x.json', expected 'aauth-person.json'"


def test_label_count_limit_is_inclusive() -> None:
    assert verify(signed(labels=MAX_LABELS)).label == "sig"
    assert MAX_LABELS == 4
    e = refused(signed(labels=MAX_LABELS + 1), "invalid_signature")
    assert e.detail == "more than 4 signatures"


def test_default_window_is_60_seconds_both_ways_and_inclusive() -> None:
    assert verify(signed(NOW - 60)).created == NOW - 60
    assert "older" in refused(signed(NOW - 61), "invalid_signature").detail
    assert verify(signed(NOW + 60)).created == NOW + 60
    refused(signed(NOW + 61), "clock_skew")


def test_created_must_be_an_integer() -> None:
    for bad in ("x", True):
        assert "created" in refused(signed(bad), "invalid_signature").detail


def test_expires_is_honoured_and_inclusive() -> None:
    assert verify(signed(extra={"expires": NOW})).created == NOW
    assert "expired" in refused(signed(extra={"expires": NOW - 1}), "invalid_signature").detail
    assert verify(signed(extra={"expires": True})).created == NOW  # not an integer: ignored


def test_signature_key_needs_non_empty_id_dwk_and_kid() -> None:
    for params in (f'id="{PS}";dwk="aauth-person.json";kid=""',
                   'id="";dwk="aauth-person.json";kid="k1"',
                   f'id="{PS}";kid="k1"'):
        e = refused(signed(sk_params=params), "invalid_key")
        assert e.detail == "jwks_uri requires id, dwk and kid"


def test_dwk_is_checked_unless_disabled() -> None:
    req = signed(sk_params=f'id="{PS}";dwk="other.json";kid="k1"')
    assert "expected" in refused(req, "invalid_key").detail
    assert verify(req, expected_dwk=None).dwk == "other.json"


# ------------------------------------------------------ response verification


def _signed_response(created: int = NOW) -> tuple[HttpResponse, HttpRequest]:
    req = HttpRequest("POST", "ss.example", "/decision", {}, b"")
    body = b'{"decision":"allow"}'
    resp = HttpResponse(200, {"content-type": "application/json",
                              "content-digest": content_digest(body)}, body)
    sk = 'sig=jwks_uri;id="https://ss.example";dwk="aauth-supervisor.json";kid="k1"'
    h = sign_message(["@status", "content-type", "content-digest"], KEY, sk, req, resp,
                     created=created)
    resp.headers.update({k.lower(): v for k, v in h.items()})
    return resp, req


def vresp(resp: HttpResponse, req: HttpRequest, **kw: Any) -> str:
    kw.setdefault("now", NOW)
    return verify_response(resp, req, key_from_jwk(KEY.public_jwk()),
                           ["@status", "content-digest"], **kw)


def test_response_default_window_is_300_seconds_inclusive() -> None:
    resp, req = _signed_response(NOW - 300)
    assert vresp(resp, req) == "https://ss.example"
    resp, req = _signed_response(NOW - 301)
    with pytest.raises(SignatureError, match="outside the window"):
        vresp(resp, req)


def test_response_window_none_skips_only_the_age_check() -> None:
    """For a retried decision, "the same signed response" (L316, findings F6)."""
    resp, req = _signed_response(NOW - 10**9)
    assert vresp(resp, req, window=None) == "https://ss.example"
    resp.body = resp.body + b" "
    with pytest.raises(SignatureError, match="Content-Digest mismatch"):
        vresp(resp, req, window=None)


def test_response_needs_all_three_signature_headers() -> None:
    for drop in ("signature-input", "signature", "signature-key"):
        resp, req = _signed_response()
        del resp.headers[drop]
        with pytest.raises(SignatureError, match="unsigned response"):
            vresp(resp, req)


def test_response_label_must_be_complete() -> None:
    resp, req = _signed_response()
    resp.headers["signature"] = resp.headers["signature"].replace("sig=", "other=")
    with pytest.raises(SignatureError, match="exactly one complete"):
        vresp(resp, req)


def test_response_created_must_be_an_integer() -> None:
    resp, req = _signed_response()
    resp.headers["signature-input"] = resp.headers["signature-input"].replace(
        f"created={NOW}", 'created="x"')
    with pytest.raises(SignatureError, match="no created time"):
        vresp(resp, req)


def test_response_must_cover_what_the_ps_requires() -> None:
    resp, req = _signed_response()
    with pytest.raises(SignatureError, match="does not cover") as e:
        verify_response(resp, req, key_from_jwk(KEY.public_jwk()), ["@status", "@path;req"],
                        now=NOW)
    assert e.value.error == "invalid_input"


def test_response_with_forged_signature_bytes_is_refused() -> None:
    # The body and its digest are intact; only the signature is wrong.
    resp, req = _signed_response()
    other = SigningKey.generate("k1")
    sig = other.sign(b"anything")
    resp.headers["signature"] = ser_dictionary({"sig": Item(sig)})
    with pytest.raises(SignatureError, match="does not verify"):
        vresp(resp, req)
