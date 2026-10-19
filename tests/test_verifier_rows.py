"""The SS as the verifier of every PS request (core, HTTP Message Signatures Profile).

Supervision L181: every PS request is signed "with an HTTP Sig ([Protocol], HTTP Message
Signatures Profile)", the PS signing as a server under `jwks_uri`; L627: a request whose
signature does not verify is answered 401 with `Signature-Error`. So the SS performs the
core's Verification (Server) steps (Protocol L2242-L2250) and discovers keys as the core's
JWKS Discovery and Caching says (L2280-L2288). These tests drive the SS end to end with
requests a PS could send, each breaking one rule; the matrix rows are `VER-*`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import SUB, make_env

from aauth_supervision_server.httpsig import (
    HttpRequest,
    build_components,
    content_digest,
    signature_base,
)
from aauth_supervision_server.jwk import SigningKey, b64u, key_from_jwk
from aauth_supervision_server.sfv import Item, Token, parse_dictionary, ser_dictionary
from aauth_supervision_server.store import Store

BASE = ["@method", "@authority", "@path", "signature-key"]
BODY = ["content-digest", "content-type"]


def _jwks_url(ps: Any) -> str:
    return f"{ps.issuer}/.well-known/jwks.json"


def _signed(ps: Any, clock: Any, *, names: list[str] | None = None, sk: str | None = None,
            keyid: str | None = None, params: dict[str, Any] | None = None,
            key: SigningKey | None = None, created: bool = True,
            query: str = "") -> HttpRequest:
    """A connect from `ps`, signed as the profile has it unless told otherwise."""
    raw = json.dumps({"action": "connect", "id": ps.nid("c"), "iat": int(clock()),
                      "sub": SUB}, separators=(",", ":")).encode()
    req = HttpRequest("POST", "ss.example", "/connect",
                      {"content-type": "application/json", "content-digest": content_digest(raw)},
                      raw, query)
    req.headers["signature-key"] = sk or (f'sig=jwks_uri;id="{ps.issuer}";'
                                          f'dwk="aauth-person.json";kid="{ps.key.kid}"')
    comps = build_components(names or BASE + BODY, int(clock()), keyid, params)
    if not created:
        del comps.params["created"]
    sig = (key or ps.key).sign(signature_base(comps, req))
    req.headers["signature-input"] = ser_dictionary({"sig": comps})
    req.headers["signature"] = ser_dictionary({"sig": Item(sig)})
    return req


def _signature_error(r: Any) -> str:
    member = parse_dictionary(r.headers["Signature-Error"])["error"]
    assert isinstance(member, Item) and isinstance(member.value, Token)
    return member.value.value


def _refused(r: Any, code: str) -> None:
    """A signature failure as the profile answers it: 401, `Signature-Error` naming the
    code, and the code in the problem body too (Supervision L627)."""
    assert r.status == 401, (r.status, r.body)
    assert _signature_error(r) == code
    assert r.headers["Content-Type"] == "application/problem+json"
    assert json.loads(r.body)["error"] == code


def _connected(ss: Any, ps: Any) -> bool:
    return Store.k(ps.issuer, SUB) in ss.store.connections


# ------------------------------------------------------------ verification steps


def _case(name: str, ss: Any, ps: Any, clock: Any) -> HttpRequest:
    now = int(clock())
    if name == "signature-missing":
        req = _signed(ps, clock)
        del req.headers["signature"]
        return req
    if name == "path-uncovered":
        return _signed(ps, clock, names=["@method", "@authority", "signature-key"] + BODY)
    if name == "created-missing":
        return _signed(ps, clock, created=False)
    if name == "created-not-an-integer":
        return _signed(ps, clock, params={"created": now + 0.5})
    if name == "created-too-old":
        return _signed(ps, clock, params={"created": now - 61})
    if name == "created-ahead":
        return _signed(ps, clock, params={"created": now + 61})
    if name == "expires-past":
        return _signed(ps, clock, params={"expires": now - 1})
    if name == "scheme-hwk":
        return _signed(ps, clock, sk='sig=hwk;kty="OKP";crv="Ed25519";x="AA"')
    if name == "kid-unknown":
        return _signed(ps, clock, sk=f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";'
                                     f'kid="no-such-key"')
    if name == "issuer-mismatch":
        ss.resolver.fetcher.documents[f"{ps.issuer}/.well-known/aauth-person.json"][
            "issuer"] = "https://elsewhere.example"
        return _signed(ps, clock)
    if name == "alg-absent":
        jwk = ps.key.public_jwk()
        del jwk["alg"]
        ss.resolver.fetcher.documents[_jwks_url(ps)] = {"keys": [jwk]}
        return _signed(ps, clock)
    assert name == "signature-wrong"
    return _signed(ps, clock, key=SigningKey.generate(ps.key.kid))


STEPS = [("signature-missing", "invalid_signature"),        # step 1
         ("path-uncovered", "invalid_input"),               # step 2
         ("created-missing", "invalid_signature"),          # step 3, L2232
         ("created-not-an-integer", "invalid_signature"),   # step 3, L2234
         ("created-too-old", "invalid_signature"),          # step 3
         ("created-ahead", "clock_skew"),                   # step 3
         ("expires-past", "invalid_signature"),             # L2270
         ("scheme-hwk", "unsupported_scheme"),              # step 4
         ("kid-unknown", "unknown_key"),                    # step 5
         ("issuer-mismatch", "issuer_mismatch"),            # step 5
         ("alg-absent", "unsupported_algorithm"),           # step 6
         ("signature-wrong", "invalid_signature")]          # step 7


@pytest.mark.req("VER-012", "VER-013", "VER-016", "VER-017", "VER-019", "VER-021", "VER-023")
@pytest.mark.parametrize("name,code", STEPS, ids=[n for n, _ in STEPS])
def test_every_verification_failure_is_a_401_naming_its_error(name: str, code: str) -> None:
    # Protocol L2242: the server "MUST perform the following steps. Any failure MUST result
    # in a `401` response with the appropriate `Signature-Error` header"; L2254: "`401` for
    # every signature failure". `created` is REQUIRED and an Integer (L2232, L2234), within
    # the 60 second default window both ways (L2246), and a past `expires` is rejected
    # (L2270). The control: the same request, signed as the profile has it, connects.
    ss, ps, clock = make_env()
    _refused(ss.handle(_case(name, ss, ps, clock)), code)
    assert not _connected(ss, ps)
    ss2, ps2, clock2 = make_env()
    assert ss2.handle(_signed(ps2, clock2)).status == 200


@pytest.mark.req("VER-009", "VER-016")
@pytest.mark.parametrize("component", BASE)
def test_a_request_signature_must_cover_each_base_component(component: str) -> None:
    # Protocol L2204-L2209: the signature MUST cover `@method`, `@authority`, `@path` and
    # `signature-key`; step 2 (L2245) refuses one that does not with `invalid_input` and
    # `required_input` naming what is required.
    ss, ps, clock = make_env()
    r = ss.handle(_signed(ps, clock, names=[c for c in BASE if c != component] + BODY))
    _refused(r, "invalid_input")
    required = parse_dictionary(r.headers["Signature-Error"])["required_input"]
    assert component in [str(i.value) for i in required.items]  # type: ignore[union-attr]
    assert not _connected(ss, ps)


@pytest.mark.req("VER-011", "VER-016")
def test_a_query_is_a_further_component_the_ss_requires() -> None:
    # Protocol L2216: "Servers MAY require further covered components; the agent learns of
    # them ... from an `invalid_input` error response that includes `required_input`". The
    # SS requires `@query` on a request that has one.
    ss, ps, clock = make_env()
    r = ss.handle(_signed(ps, clock, query="x=1"))
    _refused(r, "invalid_input")
    required = parse_dictionary(r.headers["Signature-Error"])["required_input"]
    assert "@query" in [str(i.value) for i in required.items]  # type: ignore[union-attr]
    assert not _connected(ss, ps)
    assert ss.handle(_signed(ps, clock, names=BASE + BODY + ["@query"], query="x=1")).status == 200


# ------------------------------------------------------------ keying material


SCHEMES = ['sig=hwk;kty="OKP";crv="Ed25519";x="AA"', 'sig=jwt;jwt="a.b.c"',
           'sig=jkt-jwt;jwt="a.b.c"', 'sig=x-unregistered;id="https://ps.example"',
           'sig="jwks_uri";id="https://ps.example";dwk="aauth-person.json";kid="ps-key-1"']


@pytest.mark.req("VER-008", "VER-018")
@pytest.mark.parametrize("sk", SCHEMES, ids=["hwk", "jwt", "jkt-jwt", "unregistered", "string"])
def test_a_ps_that_signs_under_another_scheme_is_told_the_one_accepted(sk: str) -> None:
    # Protocol L2187: a PS signing in its own right "MUST use the `jwks_uri` scheme". Step 4
    # (L2247): any other scheme, or an unregistered value, is `unsupported_scheme` with
    # `Accept-Signature-Scheme`, never a scheme-specific or undefined failure.
    ss, ps, clock = make_env()
    r = ss.handle(_signed(ps, clock, sk=sk))
    _refused(r, "unsupported_scheme")
    assert r.headers["Accept-Signature-Scheme"] == "jwks_uri"


@pytest.mark.req("VER-008")
def test_a_ps_must_name_its_person_server_metadata_as_dwk() -> None:
    # Protocol L2187: `dwk` MUST be the signer's own metadata document's name, for a PS
    # `aauth-person.json`. Another document of the same host, with the right issuer and
    # the same keys, does not make the signer a PS.
    ss, ps, clock = make_env()
    docs = ss.resolver.fetcher.documents
    docs[f"{ps.issuer}/.well-known/aauth-agent.json"] = dict(
        docs[f"{ps.issuer}/.well-known/aauth-person.json"])
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-agent.json";kid="{ps.key.kid}"'
    _refused(ss.handle(_signed(ps, clock, sk=sk)), "invalid_key")
    assert not _connected(ss, ps)


@pytest.mark.req("VER-015")
def test_the_key_is_the_one_signature_key_names_whatever_keyid_says() -> None:
    # Protocol L2238: where `keyid` and `Signature-Key` both name a key, "the verifier MUST
    # take the key from `Signature-Key`". The PS's JWKS holds two keys.
    ss, ps, clock = make_env()
    other = SigningKey.generate("ps-key-2")
    ss.resolver.fetcher.documents[_jwks_url(ps)] = {"keys": [ps.key.public_jwk(),
                                                             other.public_jwk()]}
    r = ss.handle(_signed(ps, clock, keyid="ps-key-2"))
    assert r.status == 200 and _connected(ss, ps)
    ss2, ps2, clock2 = make_env()
    ss2.resolver.fetcher.documents[_jwks_url(ps2)] = {"keys": [ps2.key.public_jwk(),
                                                               other.public_jwk()]}
    sk = f'sig=jwks_uri;id="{ps2.issuer}";dwk="aauth-person.json";kid="ps-key-2"'
    _refused(ss2.handle(_signed(ps2, clock2, sk=sk, keyid=ps2.key.kid)), "invalid_signature")


# ------------------------------------------------------------ algorithms


@pytest.mark.req("VER-001")
@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_a_ps_signing_with_ed25519_or_es256_is_verified(alg: str) -> None:
    # Protocol L2166: "Every party MUST support `Ed25519` ... and SHOULD support `ES256`".
    ss, ps, clock = make_env()
    ps.key = SigningKey.generate("ps-key-1", alg)
    ps.install(ss.resolver.fetcher)
    assert ps.connect(ss, SUB).status == 200 and _connected(ss, ps)


def _okp(jwk: dict[str, Any], **change: Any) -> dict[str, Any]:
    return {k: v for k, v in (jwk | change).items() if v is not None}


ALGS = [("absent", {"alg": None}, "unsupported_algorithm"),
        ("polymorphic", {"alg": "EdDSA"}, "unsupported_algorithm"),
        ("none", {"alg": "none"}, "unsupported_algorithm"),
        ("symmetric", {"kty": "oct", "crv": None, "x": None, "k": b64u(b"secret" * 6),
                       "alg": "HS256"}, "unsupported_algorithm"),
        ("kty-disagrees", {"alg": "ES256"}, "invalid_key"),
        ("crv-disagrees", {"crv": "X25519"}, "invalid_key")]


@pytest.mark.req("VER-002", "VER-003", "VER-004", "VER-005", "VER-016", "VER-020")
@pytest.mark.parametrize("name,change,code", ALGS, ids=[a[0] for a in ALGS])
def test_the_algorithm_comes_from_a_fully_specified_alg_that_agrees_with_the_key(
        name: str, change: dict[str, Any], code: str) -> None:
    # Protocol L2170-L2173: `alg` MUST be present and fully specified (a verifier MUST
    # reject a key without one); `EdDSA`, `none` and symmetric algorithms MUST NOT be used;
    # a key whose `kty` or `crv` disagrees with its `alg` MUST be rejected. Step 6 (L2249):
    # `unsupported_algorithm` with `Accept-Signature-Alg`, naming exactly the algorithms
    # accepted (L2252), or `invalid_key` for the disagreement.
    ss, ps, clock = make_env()
    ss.resolver.fetcher.documents[_jwks_url(ps)] = {"keys": [_okp(ps.key.public_jwk(),
                                                                  **change)]}
    r = ps.connect(ss, SUB)
    _refused(r, code)
    if code == "unsupported_algorithm":
        assert [a.strip() for a in r.headers["Accept-Signature-Alg"].split(",")] == [
            "Ed25519", "ES256"]
    assert not _connected(ss, ps)


@pytest.mark.req("VER-027")
def test_the_key_is_selected_by_kid_whatever_else_the_jwks_holds() -> None:
    # Protocol L2282: a verifier "MUST select the key matching `kid` without requiring any
    # other member of the JWKS to be usable, and MUST NOT fail because an unselected member
    # names a key type or algorithm it does not implement".
    ss, ps, clock = make_env()
    jwk = ps.key.public_jwk()
    others = [{"kty": "RSA", "alg": "RS256", "n": b64u(b"\xc3" * 256), "e": "AQAB",
               "kid": "rsa-1"},
              {"kty": "oct", "alg": "HS256", "k": b64u(b"secret" * 6), "kid": "hmac-1"},
              _okp(jwk, alg=None, kid="no-alg-1"), _okp(jwk, alg="EdDSA", kid="eddsa-1"),
              {"kty": "EC", "crv": "P-521", "alg": "ES512", "x": "AA", "y": "AA",
               "kid": "p521-1"},
              "not a key", {"kid": 7}]
    ss.resolver.fetcher.documents[_jwks_url(ps)] = {"keys": [*others, jwk]}
    assert ps.connect(ss, SUB).status == 200 and _connected(ss, ps)


@pytest.mark.req("VER-021")
def test_a_403_after_the_signature_carries_no_signature_error() -> None:
    # Protocol L2254: "A `403` response denies access", and "such a response MUST NOT
    # include a `Signature-Error`, `Accept-Signature-Scheme`, or `Accept-Signature-Alg`
    # header". The SS's 403 is `unsupported_iss` (Supervision L632).
    ss, ps, clock = make_env()
    ss.cfg.trusted_ps.clear()
    r = ps.connect(ss, SUB)
    assert (r.status, r.json()["error"]) == (403, "unsupported_iss")
    assert not {"signature-error", "accept-signature-scheme", "accept-signature-alg"} & {
        h.lower() for h in r.headers}


# ------------------------------------------------------------ the SS's own keys


@pytest.mark.req("VER-026")
@pytest.mark.parametrize("alg,kty,crv", [("Ed25519", "OKP", "Ed25519"), ("ES256", "EC", "P-256")])
def test_every_key_the_ss_publishes_names_its_algorithm(alg: str, kty: str, crv: str) -> None:
    # Protocol L2280: "Every key an AAuth server publishes at its `jwks_uri` MUST carry a
    # fully-specified `alg` member". A PS verifies the SS's answer with the key as published.
    ss, ps, clock = make_env()
    ss.key = SigningKey.generate("ss-key-2", alg)
    keys = ss.handle(HttpRequest("GET", "ss.example", "/.well-known/jwks.json")).json()["keys"]
    assert [(k["kid"], k["alg"], k["kty"], k["crv"]) for k in keys] == [("ss-key-2", alg, kty,
                                                                         crv)]
    assert key_from_jwk({k: v for k, v in keys[0].items() if k != "use"}).alg == alg
    ps.ss_jwk = keys[0]
    assert ps.connect(ss, SUB).status == 200  # verified by the PS with the published key


# ------------------------------------------------------------ discovery and caching


def _fetches(ss: Any, ps: Any) -> tuple[int, int]:
    calls = ss.resolver.fetcher.calls
    return (calls.count(f"{ps.issuer}/.well-known/aauth-person.json"),
            calls.count(_jwks_url(ps)))


@pytest.mark.req("VER-028")
def test_a_signers_keys_are_cached_and_fetched_at_most_once_a_minute() -> None:
    # Protocol L2284: "Implementations MUST cache JWKS responses" and "MUST NOT fetch a given
    # issuer's JWKS more frequently than once per minute". Requests within the cache's
    # lifetime cost no fetch; a request after it costs one of each document.
    ss, ps, clock = make_env()
    for _ in range(3):
        assert ps.connect(ss, SUB).status == 200
    assert _fetches(ss, ps) == (1, 1)
    clock.t += 59
    assert ps.connect(ss, SUB).status == 200
    assert _fetches(ss, ps) == (1, 1)
    clock.t += ss.resolver.ttl
    assert ps.connect(ss, SUB).status == 200
    assert _fetches(ss, ps) == (2, 2)


@pytest.mark.req("VER-029")
def test_a_cached_key_that_fails_is_refreshed_once_before_the_request_is_refused() -> None:
    # Protocol L2286: "If a cached key matching the JWT `kid` fails signature verification,
    # the verifier SHOULD refresh the issuer's JWKS once and retry", within the floor. A PS
    # that replaces its key under the same `kid` is verified a minute later, at the cost
    # of one fetch; a signature no key verifies costs no more than that.
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    ps.key = SigningKey.generate(ps.key.kid, "ES256")
    ps.install(ss.resolver.fetcher)
    clock.t += 61
    assert ps.connect(ss, SUB).status == 200
    assert _fetches(ss, ps)[1] == 2
    forged = _signed(ps, clock, key=SigningKey.generate(ps.key.kid, "ES256"))
    _refused(ss.handle(forged), "invalid_signature")
    assert _fetches(ss, ps)[1] == 2
