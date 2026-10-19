"""Key discovery is for parties the SS accepts, and it degrades gracefully.

* A signer the SS does not accept (not a trusted PS, and no open registration) is refused
  before any fetch: otherwise any caller makes the SS fetch two documents per invented id
  and keep them (Signature-Key -09 L2379: verifiers MUST implement cache limits).
* The key cache is bounded.
* A failed refetch (an unknown kid, or the TTL running out while the PS host is briefly
  down) keeps the keys already held: core L2284, "If a JWKS fetch fails, implementations
  SHOULD use the cached JWKS if available". One request with a made-up kid must not lock
  a trusted PS out.
* A body that names a member twice is refused: the SS evaluates one value, and a signed
  decision whose request a reader parses the other way would say something else (L344).
* A Content-Length that is not ASCII digits is a 400, not a dropped connection.
* Egress judges an IPv4 address embedded in a NAT64 or IPv4-compatible IPv6 address.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, SUB, Clock, connected, make_env

from aauth_supervision_server.egress import FetchError, StaticFetcher, _is_public
from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy, PolicyConfig
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.testing import SimulatedPS


class CountingFetcher(StaticFetcher):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.down = False

    def fetch_json(self, url: str) -> Any:
        self.urls.append(url)
        if self.down:
            raise FetchError("host down")
        return super().fetch_json(url)


def _ss(fetcher: StaticFetcher, clock: Clock, trusted: str) -> SupervisionServer:
    cfg = ServerConfig(issuer="https://ss.example", trusted_ps={trusted: TrustedPS(True)})
    return SupervisionServer(cfg, Policy(PolicyConfig()), JwksUriResolver(fetcher), None,
                             clock=clock)


def test_a_signer_the_ss_does_not_accept_causes_no_fetch() -> None:
    clock, fetcher = Clock(), CountingFetcher()
    stranger = SimulatedPS(issuer="https://n1.attacker.example", clock=clock)
    stranger.install(fetcher)
    ss = _ss(fetcher, clock, "https://ps.example")
    r = stranger.connect(ss, SUB)
    assert r.status == 403 and r.json()["error"] == "unsupported_iss"
    assert fetcher.urls == []


def test_the_key_cache_is_bounded() -> None:
    clock, fetcher = Clock(), StaticFetcher()
    resolver = JwksUriResolver(fetcher, max_entries=3)
    for i in range(5):
        ps = SimulatedPS(issuer=f"https://ps{i}.example", clock=clock)
        ps.install(fetcher)
        resolver.resolve(ps.issuer, "aauth-person.json", ps.key.kid, clock())
        clock.t += 1
    assert len(resolver._entries) == 3
    assert all(e.meta is not None for e in resolver._entries.values())


def test_a_made_up_kid_while_the_host_is_down_does_not_lock_out_the_ps() -> None:
    clock, fetcher = Clock(), CountingFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    ss = _ss(fetcher, clock, ps.issuer)
    assert ps.connect(ss, SUB).status == 200
    clock.t += 60                                     # a refetch is due (L2284)
    fetcher.down = True
    real = ps.key
    ps.key = SigningKey.generate("made-up")          # anyone can name a kid
    assert ps.connect(ss, SUB).status == 401
    ps.key = real
    clock.t += 1
    assert ps.connect(ss, SUB).status == 200          # served from the keys already held


def test_keys_past_their_ttl_are_used_while_the_host_is_down() -> None:
    clock, fetcher = Clock(), CountingFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    ss = _ss(fetcher, clock, ps.issuer)
    assert ps.connect(ss, SUB).status == 200
    clock.t += 400                                    # past the 300 s TTL
    fetcher.down = True
    assert ps.connect(ss, SUB).status == 200
    clock.t += 25 * 3600                              # but not for more than a day
    assert ps.connect(ss, SUB).status == 401


def test_a_failed_refetch_still_counts_toward_the_refetch_floor() -> None:
    clock, fetcher = Clock(), CountingFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    ss = _ss(fetcher, clock, ps.issuer)
    assert ps.connect(ss, SUB).status == 200
    clock.t += 60                                     # a refetch is due (L2284)
    fetcher.down = True
    ps.key = SigningKey.generate("made-up")
    before = len(fetcher.urls)
    for _ in range(5):
        ps.connect(ss, SUB)
    assert len(fetcher.urls) - before == 1           # one attempt, not one per request


def test_a_member_named_twice_is_refused() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), tools=[{"name": "WebSearch", "description": "x"}])
    body = (f'{{"sdi":"d-dup","act":"permission","iat":{int(clock())},"sub":"{SUB}",'
            f'"agent":"{AGENT}","mission_s256":"{s256}","action":"DeleteAllRecords",'
            f'"action":"WebSearch"}}').encode()
    req = ps.build("POST", "/decision", json.loads(body))
    from aauth_supervision_server.httpsig import content_digest, sign_message
    req.body = body
    req.headers["content-digest"] = content_digest(body)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    req.headers.update({k.lower(): v for k, v in sign_message(
        ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"],
        ps.key, sk, req, created=int(clock())).items()})
    r = ss.handle(req)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


@pytest.mark.parametrize("ip", ["64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "::127.0.0.1",
                                "::a9fe:a9fe"])
def test_an_embedded_private_ipv4_is_not_public(ip: str) -> None:
    assert not _is_public(ip)


def test_a_public_ipv4_embedded_in_nat64_is_public() -> None:
    assert _is_public("64:ff9b::808:808")


@pytest.mark.parametrize("jwks", [{"keys": 5}, {"keys": [{"kid": "ps-key-1", "alg": ["x"]}]},
                                  {"keys": [{"kid": "ps-key-1", "alg": {"a": 1}}]}])
def test_malformed_key_material_is_a_signature_error_not_a_server_error(jwks: Any) -> None:
    clock, fetcher = Clock(), StaticFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    fetcher.documents[f"{ps.issuer}/.well-known/jwks.json"] = jwks
    r = ps.connect(_ss(fetcher, clock, ps.issuer), SUB)
    assert r.status == 401 and "Signature-Error" in r.headers


def test_a_content_length_of_non_ascii_digits_is_a_400() -> None:
    import socket
    import threading

    from aauth_supervision_server import http_server
    ss, _, _ = make_env()
    httpd = http_server.serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        s = socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5)
        s.sendall(b"POST /event HTTP/1.1\r\nHost: ss.example\r\nContent-Length: \xb2\r\n\r\n")
        head = s.recv(1024)
        assert head.startswith(b"HTTP/1.1 400 "), head
        s.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_an_unaccepted_signer_beside_the_ps_fails_only_its_own_label() -> None:
    # Signature-Key -09 Section 3.2: several signatures. An unaccepted signer in the first
    # label costs no fetch and does not stop the PS's own label from verifying.
    from aauth_supervision_server.httpsig import sign_message
    clock, fetcher = Clock(), CountingFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    ss = _ss(fetcher, clock, ps.issuer)
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-m", "iat": int(clock()),
                                        "sub": SUB})
    names = ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"]
    sk = ('a=jwks_uri;id="https://n1.attacker.example";dwk="aauth-person.json";kid="x", '
          f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"')
    ha = sign_message(names, SigningKey.generate("x"), sk, req, label="a", created=int(clock()))
    hs = sign_message(names, ps.key, sk, req, label="sig", created=int(clock()))
    req.headers["signature-key"] = sk
    for h in ("Signature-Input", "Signature"):
        req.headers[h.lower()] = ha[h] + ", " + hs[h]
    assert ss.handle(req).status == 200
    assert not any("attacker" in u for u in fetcher.urls)


def test_failed_discoveries_do_not_grow_the_attempt_table_without_bound() -> None:
    clock, fetcher = Clock(), CountingFetcher()
    fetcher.down = True
    resolver = JwksUriResolver(fetcher, max_entries=3)
    for i in range(10):
        with pytest.raises(SignatureError):
            resolver.resolve(f"https://n{i}.example", "aauth-person.json", "k", clock())
    with pytest.raises(SignatureError):
        resolver.resolve("http://plain.example", "aauth-person.json", "k", clock())
    assert len(resolver._entries) <= 3
    assert ("http://plain.example", "aauth-person.json") not in resolver._entries


@pytest.mark.req("REF-014")
@pytest.mark.parametrize("pid", ["https://host.example/~mallory", "https://host.example:8443",
                                 "https://Host.Example", "https://host.example/"])
def test_a_ps_id_that_is_not_a_server_identifier_is_refused_before_any_fetch(pid: str) -> None:
    """Protocol L2187: a PS signing in its own right names its `issuer` as `id`, and an
    issuer is a server identifier (L1948-L1969): https, host only, lowercase. Under open
    registration any other `id` would reach connect, so a party serving files under a
    path or a port of a shared host could pass for a PS of its own."""
    clock, fetcher = Clock(), CountingFetcher()
    ps = SimulatedPS(issuer=pid, clock=clock)
    ps.install(fetcher)
    ss = _ss(fetcher, clock, "https://ps.example")
    ss.cfg.open_registration = True
    r = ps.connect(ss, SUB)
    assert r.status == 401 and r.headers["Signature-Error"] == "error=invalid_key"
    assert fetcher.urls == []


def test_a_trusted_ps_is_named_by_its_server_identifier() -> None:
    with pytest.raises(ValueError):
        ServerConfig(issuer="https://ss.example", trusted_ps={"https://PS.example": TrustedPS()})
    with pytest.raises(ValueError):
        ServerConfig.from_dict({"issuer": "https://ss.example",
                                "trusted_ps": {"https://ps.example/": {}}})
