"""Key discovery under hostile metadata, outages and concurrent requests.

Protocol L2284: "Implementations MUST NOT fetch a given issuer's JWKS more frequently
than once per minute. If a JWKS fetch fails, implementations SHOULD use the cached JWKS if
available and SHOULD retry with exponential backoff. Cached JWKS entries SHOULD be
discarded after a maximum of 24 hours". Signature-Key -09 L2377-L2379: "Verifiers MUST
implement cache limits."

- A URL `urllib` cannot read (a port out of range or not a number, an unbalanced
  bracket), or a host name DNS cannot carry (RFC 1035 2.3.4: labels of 63 octets or
  less), is a failed discovery (`invalid_key`), not a server error.
- While a signer's key host is down its keys are fetched at most once a minute, and less
  often the longer the outage lasts; the keys held are served meanwhile, and a signer
  with none is refused without a new fetch.
- Requests for one signer that arrive together make one fetch.
- The cache is shared by request threads: it is locked, it evicts the signer used least
  recently, and it never evicts a trusted PS.
"""
from __future__ import annotations

import itertools
import json
import random
import sys
import threading
from collections import OrderedDict
from typing import Any

import pytest

from aauth_supervision_server import resolver
from aauth_supervision_server.egress import FetchError, HttpsFetcher, StaticFetcher
from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import SERVER_ID
from aauth_supervision_server.resolver import JwksUriResolver

PS = "https://ps.example"
DWK = "aauth-person.json"
META = f"{PS}/.well-known/{DWK}"
JWKS = f"{PS}/.well-known/jwks.json"


class Network(StaticFetcher):
    """Documents in memory; a URL in `down` fails as an unreachable host would."""

    def __init__(self) -> None:
        super().__init__()
        self.down: set[str] = set()

    def fetch_json(self, url: str) -> Any:
        if url in self.down or "*" in self.down:
            self.calls.append(url)
            raise FetchError(f"connection refused: {url}")
        return super().fetch_json(url)


def _signer(net: Network, issuer: str = PS) -> SigningKey:
    key = SigningKey.generate("k1")
    net.documents[f"{issuer}/.well-known/{DWK}"] = {"issuer": issuer,
                                                   "jwks_uri": f"{issuer}/.well-known/jwks.json"}
    net.documents[f"{issuer}/.well-known/jwks.json"] = {"keys": [key.public_jwk()]}
    return key


# ------------------------------------------------------------ URLs and names

@pytest.mark.parametrize("url", ["https://ps.example:99999/jwks.json",
                                 "https://ps.example:abc/jwks.json",
                                 "https://[ps.example/jwks.json"])
def test_a_jwks_uri_urllib_cannot_read_is_an_invalid_key(url: str) -> None:
    class Real(Network):
        def fetch_json(self, u: str) -> Any:
            return super().fetch_json(u) if u in self.documents else HttpsFetcher().fetch_json(u)

    net = Real()
    _signer(net)
    net.documents[META]["jwks_uri"] = url
    with pytest.raises(SignatureError) as e:
        JwksUriResolver(net).resolve(PS, DWK, "k1", 1000.0)
    assert e.value.error == "invalid_key"


@pytest.mark.parametrize("url", ["https://ps.example:99999/x", "https://ps.example:abc/x",
                                 "https://[ps.example/x", "https://" + "a" * 64 + ".example/x"])
def test_the_fetcher_reports_a_url_it_cannot_use_as_a_failed_fetch(url: str) -> None:
    with pytest.raises(FetchError):
        HttpsFetcher().fetch_json(url)


def test_a_signer_id_urllib_cannot_read_is_an_invalid_key() -> None:
    with pytest.raises(SignatureError) as e:
        JwksUriResolver(Network()).resolve("https://[ps.example", DWK, "k1", 1000.0)
    assert e.value.error == "invalid_key"


def test_a_server_identifier_has_labels_and_a_name_dns_can_carry() -> None:
    assert SERVER_ID.fullmatch("https://" + "a" * 63 + ".example")
    assert not SERVER_ID.fullmatch("https://" + "a" * 64 + ".example")
    longest = ".".join(["a" * 63] * 3 + ["a" * 61])  # 253 characters
    assert len(longest) == 253 and SERVER_ID.fullmatch("https://" + longest)
    assert not SERVER_ID.fullmatch("https://" + longest + "a")
    assert not SERVER_ID.fullmatch("https://a." + longest[2:] + "a")


# ------------------------------------------------------------ outages

@pytest.mark.req("VER-028")
def test_during_an_outage_keys_are_fetched_at_most_once_a_minute_and_served_meanwhile() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net)
    t0 = 1_000_000.0
    r.resolve(PS, DWK, "k1", t0)
    net.down = {"*"}
    net.calls.clear()
    for i in range(30):  # every second for 30 s, all past the 300 s TTL
        assert r.resolve(PS, DWK, "k1", t0 + 301 + i).jwk["kid"] == "k1"
    assert len(net.calls) == 1


@pytest.mark.req("VER-028")
def test_the_wait_between_failed_fetches_grows_up_to_an_hour() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net)
    t0 = 1_000_000.0
    r.resolve(PS, DWK, "k1", t0)
    net.down = {"*"}
    net.calls.clear()
    attempts: list[float] = []
    t = t0 + 301
    while t < t0 + 301 + 6 * 3600:
        before = len(net.calls)
        r.resolve(PS, DWK, "k1", t)
        if len(net.calls) > before:
            attempts.append(t)
        t += 10
    gaps = [b - a for a, b in itertools.pairwise(attempts)]
    assert gaps[:4] == [60, 120, 240, 480]
    assert max(gaps) <= 3600 and gaps[-1] == 3600


@pytest.mark.req("VER-028")
def test_keys_held_too_long_are_not_served() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net)
    t0 = 1_000_000.0
    r.resolve(PS, DWK, "k1", t0)
    net.down = {"*"}
    with pytest.raises(SignatureError):
        r.resolve(PS, DWK, "k1", t0 + 24 * 3600 + 1)


def test_a_signer_with_no_keys_held_is_refused_without_a_new_fetch_within_the_minute() -> None:
    net = Network()
    _signer(net)
    net.down = {"*"}
    r = JwksUriResolver(net)
    for dt in (0, 1, 30, 59):
        with pytest.raises(SignatureError) as e:
            r.resolve(PS, DWK, "k1", 1000.0 + dt)
        assert e.value.error == "invalid_key"
    assert len(net.calls) == 1
    net.down = set()
    assert r.resolve(PS, DWK, "k1", 1060.0).jwk["kid"] == "k1"


def test_an_unknown_kid_waits_out_the_same_backoff() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net)
    t0 = 1_000_000.0
    r.resolve(PS, DWK, "k1", t0)
    net.down = {"*"}
    net.calls.clear()
    for t in (60, 100, 120, 200, 239):
        with pytest.raises(SignatureError):
            r.resolve(PS, DWK, "made-up", t0 + t)
    assert len(net.calls) == 2  # at 60 (a refetch is due) and 120 (60 s after a failure)
    assert r.resolve(PS, DWK, "k1", t0 + 239).jwk["kid"] == "k1"


# ------------------------------------------------------------ concurrency and the cache

class Slow(Network):
    """Every fetch waits for `release`."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()

    def fetch_json(self, url: str) -> Any:
        self.release.wait(5)
        return super().fetch_json(url)


def test_requests_for_one_signer_that_arrive_together_make_one_fetch() -> None:
    net = Slow()
    _signer(net)
    r = JwksUriResolver(net)
    got: list[Any] = []
    threads = [threading.Thread(target=lambda: got.append(r.resolve(PS, DWK, "k1", 1000.0)))
               for _ in range(4)]
    for t in threads:
        t.start()
    net.release.set()
    for t in threads:
        t.join(10)
    assert len(got) == 4 and net.calls == [META, JWKS]


def test_the_cache_is_safe_to_share_between_request_threads() -> None:
    key = SigningKey.generate("k1")
    signers = [f"https://n{i}.example" for i in range(400)]
    net = Network()
    for s in signers:
        net.documents[f"{s}/.well-known/{DWK}"] = {"issuer": s, "jwks_uri": f"{s}/jwks"}
        net.documents[f"{s}/jwks"] = {"keys": [key.public_jwk()]}
    r = JwksUriResolver(net, max_entries=32)
    errors: list[BaseException] = []

    def work(seed: int) -> None:
        rnd = random.Random(seed)
        for j in range(600):
            try:
                r.resolve(rnd.choice(signers), DWK, "k1", 1_000_000.0 + j)
            except SignatureError:
                pass
            except BaseException as e:  # noqa: BLE001 - anything else is the defect
                errors.append(e)

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        threads = [threading.Thread(target=work, args=(k,)) for k in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
    finally:
        sys.setswitchinterval(old)
    assert errors == []


def test_the_signer_used_least_recently_is_evicted() -> None:
    net = Network()
    keys = {n: _signer(net, f"https://{n}.example") for n in ("a", "b", "c")}
    r = JwksUriResolver(net, max_entries=2)
    r.resolve("https://a.example", DWK, keys["a"].kid, 1000.0)
    r.resolve("https://b.example", DWK, keys["b"].kid, 1001.0)
    r.resolve("https://a.example", DWK, keys["a"].kid, 1002.0)   # used again
    r.resolve("https://c.example", DWK, keys["c"].kid, 1003.0)
    net.calls.clear()
    r.resolve("https://a.example", DWK, keys["a"].kid, 1004.0)
    assert net.calls == []                                     # still held
    # b was evicted, and its keys were fetched four seconds ago: not again within the
    # minute (Protocol L2284), so it is served the keys it held.
    r.resolve("https://b.example", DWK, keys["b"].kid, 1005.0)
    assert net.calls == []
    r.resolve("https://b.example", DWK, keys["b"].kid, 1001.0 + 300)   # past the TTL
    assert net.calls == ["https://b.example/.well-known/aauth-person.json",
                         "https://b.example/.well-known/jwks.json"]


def test_a_signer_outside_its_fetch_floor_is_evicted_first() -> None:
    net = Network()
    keys = {n: _signer(net, f"https://{n}.example") for n in ("a", "b", "c")}
    r = JwksUriResolver(net, max_entries=2)
    r.resolve("https://a.example", DWK, keys["a"].kid, 1000.0)
    r.resolve("https://b.example", DWK, keys["b"].kid, 1010.0)
    r.resolve("https://a.example", DWK, keys["a"].kid, 1065.0)   # used again, not fetched
    r.resolve("https://c.example", DWK, keys["c"].kid, 1066.0)
    net.calls.clear()
    # b is used least recently, but within its floor; a's floor has passed: a goes.
    r.resolve("https://b.example", DWK, keys["b"].kid, 1067.0)
    assert net.calls == []


def test_the_floors_remembered_are_bounded() -> None:
    net = Network()
    names = [f"s{i}" for i in range(40)]
    keys = {n: _signer(net, f"https://{n}.example") for n in names}
    r = JwksUriResolver(net, max_entries=2)
    for i, n in enumerate(names):
        try:  # once as many floors are kept as the table holds, a new signer is refused
            r.resolve(f"https://{n}.example", DWK, keys[n].kid, 1000.0 + i / 100)
        except SignatureError:
            pass
    assert len(r._floors) <= 4 * r.max_entries
    # Once its floor has passed, a remembered signer is forgotten at the next eviction.
    r.resolve("https://s0.example", DWK, keys["s0"].kid, 2000.0)
    assert r._floors == {}


def test_a_trusted_ps_is_never_evicted() -> None:
    net = Network()
    key = _signer(net)
    others = {i: _signer(net, f"https://n{i}.example") for i in range(10)}
    r = JwksUriResolver(net, max_entries=3, keep=frozenset({PS}))
    t0 = 1_000_000.0
    r.resolve(PS, DWK, key.kid, t0)
    for i, k in others.items():
        r.resolve(f"https://n{i}.example", DWK, k.kid, t0 + 1 + i)
    net.down = {"*"}
    assert r.resolve(PS, DWK, key.kid, t0 + 400).jwk["kid"] == key.kid  # held, though stale


def test_a_refused_discovery_is_refused_the_same_way_until_the_next_fetch() -> None:
    net = Network()
    _signer(net)
    net.documents[META]["issuer"] = "https://other.example"
    r = JwksUriResolver(net)
    for dt in (0, 30):
        with pytest.raises(SignatureError) as e:
            r.resolve(PS, DWK, "k1", 1000.0 + dt)
        assert e.value.error == "issuer_mismatch"
    assert net.calls == [META]


def test_the_first_discovery_is_made_whatever_the_clock_reads() -> None:
    net = Network()
    _signer(net)
    assert JwksUriResolver(net).resolve(PS, DWK, "k1", 0.0).jwk["kid"] == "k1"


def test_a_trusted_ps_metadata_is_kept_for_its_connection_page() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net, keep=frozenset({PS}))
    assert r.cached_metadata(PS, DWK) is None
    r.resolve(PS, DWK, "k1", 1000.0)
    assert r.cached_metadata(PS, DWK) == net.documents[META]


def test_after_a_fetch_succeeds_the_wait_starts_over() -> None:
    net = Network()
    _signer(net)
    r = JwksUriResolver(net)
    t0 = 1_000_000.0
    r.resolve(PS, DWK, "k1", t0)
    net.down = {"*"}
    r.resolve(PS, DWK, "k1", t0 + 301)            # fails: the next in 60 s
    r.resolve(PS, DWK, "k1", t0 + 361)            # fails: the next in 120 s
    net.down = set()
    r.resolve(PS, DWK, "k1", t0 + 481)            # succeeds
    net.down = {"*"}
    net.calls.clear()
    with pytest.raises(SignatureError):
        r.resolve(PS, DWK, "made-up-1", t0 + 541)  # a refetch is due 60 s after a success
    assert net.calls == [META]


def test_the_table_is_only_touched_under_its_lock() -> None:
    net = Network()
    keys = {n: _signer(net, f"https://{n}.example") for n in ("a", "b")}
    r = JwksUriResolver(net, max_entries=1)

    class Checked(OrderedDict):  # type: ignore[type-arg]
        def get(self, *a: Any) -> Any:
            assert r._lock.locked()
            return super().get(*a)

        def __setitem__(self, k: Any, v: Any) -> None:
            assert r._lock.locked()
            super().__setitem__(k, v)

        def move_to_end(self, *a: Any, **kw: Any) -> None:
            assert r._lock.locked()
            super().move_to_end(*a, **kw)

        def popitem(self, *a: Any, **kw: Any) -> Any:
            assert r._lock.locked()
            return super().popitem(*a, **kw)

        def __delitem__(self, k: Any) -> None:
            assert r._lock.locked()
            super().__delitem__(k)

    r._entries = Checked()
    r._floors = Checked()
    # Evicted within its floor, then past it (another kind of eviction): both locked.
    for n, t in (("a", 1000.0), ("a", 1000.0), ("b", 1001.0), ("a", 1100.0), ("b", 1200.0)):
        r.resolve(f"https://{n}.example", DWK, keys[n].kid, t)


def test_a_refusal_repeated_from_the_cache_holds_nothing_from_earlier_requests() -> None:
    # The failure kept for the backoff window is raised afresh each time: re-raising one
    # exception object grows its traceback by every request's frames.
    net = Network()
    r = JwksUriResolver(net)
    raised = []
    for i in range(200):
        with pytest.raises(SignatureError) as e:
            r.resolve(PS, DWK, "k1", 1000.0 + i * 0.1)
        raised.append(e.value)
    frames, tb = 0, raised[-1].__traceback__
    while tb is not None:
        frames, tb = frames + 1, tb.tb_next
    assert frames < 10 and raised[-1] is not raised[-2]
    assert {(x.error, x.detail) for x in raised} == {(raised[0].error, raised[0].detail)}


def test_a_fetch_that_failed_unexpectedly_still_waits_out_the_floor() -> None:
    class Broken(Network):
        def fetch_json(self, url: str) -> Any:
            self.calls.append(url)
            raise RuntimeError("a bug in the fetcher")

    net = Broken()
    r = JwksUriResolver(net)
    with pytest.raises(RuntimeError):                       # surfaces, as any bug does
        r.resolve(PS, DWK, "k1", 1000.0)
    with pytest.raises(SignatureError) as e:                # within the minute: no fetch
        r.resolve(PS, DWK, "k1", 1030.0)
    assert e.value.error == "invalid_key" and net.calls == [META]


def test_a_flood_of_signers_never_makes_the_resolver_forget_a_live_floor() -> None:
    # The floors of evicted signers are kept for the minute the draft requires; when as
    # many are kept as the table holds, a new signer is refused, without a fetch, rather
    # than a live floor forgotten.
    net = Network()
    names = [f"s{i}" for i in range(30)]
    keys = {n: _signer(net, f"https://{n}.example") for n in ["victim"] + names}
    r = JwksUriResolver(net, max_entries=2)
    r.resolve("https://victim.example", DWK, keys["victim"].kid, 1000.0)
    refused = 0
    for i, n in enumerate(names):
        try:
            r.resolve(f"https://{n}.example", DWK, keys[n].kid, 1000.0 + i / 100)
        except SignatureError:
            refused += 1
    assert refused > 0 and len(r._floors) <= 4 * r.max_entries
    net.calls.clear()
    # Evicted, and within its minute: served the keys it held, without a fetch.
    assert r.resolve("https://victim.example", DWK, keys["victim"].kid, 1001.0) is not None
    assert net.calls == []
    # Past the minute the floors are let go, and new signers are looked up again.
    r.resolve("https://s29.example", DWK, keys["s29"].kid, 1061.0)


def test_a_signer_evicted_within_its_floor_keeps_its_keys() -> None:
    # Its floor forbids a fetch within the minute; the keys it held are still its keys, so
    # a churn of other signers cannot lock it out meanwhile.
    net = Network()
    keys = {n: _signer(net, f"https://{n}.example") for n in ("a", "b", "c")}
    r = JwksUriResolver(net, max_entries=1)
    r.resolve("https://a.example", DWK, keys["a"].kid, 1000.0)
    r.resolve("https://b.example", DWK, keys["b"].kid, 1001.0)    # a evicted
    r.resolve("https://c.example", DWK, keys["c"].kid, 1002.0)    # b evicted
    net.calls.clear()
    assert r.resolve("https://a.example", DWK, keys["a"].kid, 1010.0) is not None
    assert net.calls == []


def test_signers_holding_no_keys_are_evicted_first() -> None:
    net = Network()
    key = _signer(net, "https://a.example")
    r = JwksUriResolver(net, max_entries=2)
    r.resolve("https://a.example", DWK, key.kid, 1000.0)
    for i in range(5):                                # made-up signers: nothing to fetch
        with pytest.raises(SignatureError):
            r.resolve(f"https://junk{i}.example", DWK, "k1", 1001.0 + i)
    assert ("https://a.example", DWK) in r._entries


def test_only_bounded_keys_and_metadata_are_kept() -> None:
    net = Network()
    key = _signer(net)
    net.documents[META].update({"name": "Acme", "junk": [{}] * 10_000})
    net.documents[JWKS]["keys"] += [{"kid": f"x{i}", "kty": "OKP", "pad": "p" * 5000}
                                    for i in range(1000)]
    r = JwksUriResolver(net)
    r.resolve(PS, DWK, key.kid, 1000.0)
    (e,) = r._entries.values()
    assert e.jwks is not None and len(e.jwks["keys"]) <= resolver.MAX_KEYS
    assert e.meta == {"issuer": PS, "jwks_uri": JWKS, "name": "Acme"}


def test_a_flood_of_made_up_signers_does_not_keep_a_new_signer_out() -> None:
    # A made-up signer's metadata fetch fails: its JWKS was never fetched, so the floor
    # Protocol L2284 sets on JWKS fetches does not bind it, and it gives way to a new one.
    net = Network()
    key = _signer(net, "https://new.example")
    r = JwksUriResolver(net, max_entries=2)
    for i in range(40):
        with pytest.raises(SignatureError):
            r.resolve(f"https://junk{i}.example", DWK, "k1", 1000.0 + i / 100)
    assert r.resolve("https://new.example", DWK, key.kid, 1001.0) is not None


def test_a_key_with_members_the_ss_does_not_read_is_kept_without_them() -> None:
    # RFC 7517 Section 4: members a verifier does not understand are ignored (Signature-Key
    # -09 L633-L636); a certificate chain or a WebCrypto flag does not make the key unusable.
    net = Network()
    key = _signer(net)
    jwk = dict(net.documents[JWKS]["keys"][0], x5c=["MIIB" + "A" * 3000], ext=True)
    net.documents[JWKS]["keys"] = [jwk]
    r = JwksUriResolver(net)
    assert r.resolve(PS, DWK, key.kid, 1000.0) is not None
    (e,) = r._entries.values()
    assert e.jwks is not None and "x5c" not in e.jwks["keys"][0]


def test_names_under_one_domain_hold_only_that_domain_s_share() -> None:
    # Names made under one domain, each serving keys, churn only that domain's share of
    # the table: a signer of another domain, evicted or new, is still served.
    net = Network()
    honest = _signer(net, "https://ps.honest.example")
    new = _signer(net, "https://ps.new.example")
    junk = {i: _signer(net, f"https://n{i}.evil.example") for i in range(40)}
    r = JwksUriResolver(net, max_entries=4, max_per_domain=2)
    r.resolve("https://ps.honest.example", DWK, honest.kid, 1000.0)
    for i, k in junk.items():
        try:
            r.resolve(f"https://n{i}.evil.example", DWK, k.kid, 1001.0 + i / 100)
        except SignatureError:
            pass
    assert r.resolve("https://ps.honest.example", DWK, honest.kid, 1011.0) is not None
    assert r.resolve("https://ps.new.example", DWK, new.kid, 1011.0) is not None


def test_the_keys_kept_of_a_signer_are_bounded_in_bytes() -> None:
    net = Network()
    key = _signer(net)
    pad = [{"kid": f"x{i}", "kty": "RSA", "n": "n" * 2000, "e": "AQAB", "x": "x" * 2000,
            "y": "y" * 2000} for i in range(40)]
    net.documents[JWKS]["keys"] = [net.documents[JWKS]["keys"][0]] + pad
    r = JwksUriResolver(net)
    assert r.resolve(PS, DWK, key.kid, 1000.0) is not None
    (e,) = r._entries.values()
    assert len(json.dumps(e.jwks)) <= resolver.MAX_KEYS_BYTES


def test_a_domain_s_share_frees_a_signer_past_its_floor() -> None:
    net = Network()
    keys = {i: _signer(net, f"https://n{i}.one.example") for i in range(3)}
    r = JwksUriResolver(net, max_per_domain=2)
    r.resolve("https://n0.one.example", DWK, keys[0].kid, 1000.0)
    r.resolve("https://n1.one.example", DWK, keys[1].kid, 1001.0)
    # The share is full; past n0's floor, n0 makes room for n2.
    assert r.resolve("https://n2.one.example", DWK, keys[2].kid, 1061.0) is not None
    assert ("https://n0.one.example", DWK) not in r._entries


def test_a_key_s_operations_are_kept_when_they_are_short_strings() -> None:
    net = Network()
    key = _signer(net)
    jwk = net.documents[JWKS]["keys"][0]
    net.documents[JWKS]["keys"] = [dict(jwk, key_ops=["verify"]),
                                   dict(jwk, kid="bad", key_ops=["v" * 5000])]
    r = JwksUriResolver(net)
    assert r.resolve(PS, DWK, key.kid, 1000.0) is not None
    (e,) = r._entries.values()
    assert e.jwks is not None and [k["kid"] for k in e.jwks["keys"]] == [key.kid]


def test_made_up_names_under_a_signer_s_domain_do_not_push_it_out() -> None:
    # Names nobody serves documents for, under an honest signer's domain, give way to each
    # other in the domain's share; the honest signer's entry and keys stay.
    net = Network()
    key = _signer(net, "https://ps.corp.example")
    r = JwksUriResolver(net, max_per_domain=2)
    r.resolve("https://ps.corp.example", DWK, key.kid, 1000.0)
    for i in range(10):                                   # each within its backoff
        with pytest.raises(SignatureError):
            r.resolve(f"https://a{i}.corp.example", DWK, "k1", 1400.0 + i)
    assert r.resolve("https://ps.corp.example", DWK, key.kid, 1410.0) is not None


def test_a_jwks_publishing_private_key_material_is_refused() -> None:
    net = Network()
    key = _signer(net)
    net.documents[JWKS]["keys"] = [dict(net.documents[JWKS]["keys"][0], d="secret")]
    r = JwksUriResolver(net)
    with pytest.raises(SignatureError, match="private key material"):
        r.resolve(PS, DWK, key.kid, 1000.0)


def test_a_signer_whose_keys_are_being_fetched_is_not_taken_for_a_made_up_name() -> None:
    # Made-up names under its domain arrive while its first fetch is in flight (another
    # request's thread): its entry stays, and its keys are fetched once.
    class Busy(Network):
        def __init__(self) -> None:
            super().__init__()
            self.during: list[Any] = []

        def fetch_json(self, url: str) -> Any:
            while self.during:
                self.during.pop()()
            return super().fetch_json(url)

    net = Busy()
    key = _signer(net, "https://ps.corp.example")
    r = JwksUriResolver(net, max_per_domain=2)

    def junk(i: int) -> Any:
        def run() -> None:
            with pytest.raises(SignatureError):
                r.resolve(f"https://a{i}.corp.example", DWK, "k1", 1000.0)
        return run

    net.during = [junk(i) for i in range(4)]
    assert r.resolve("https://ps.corp.example", DWK, key.kid, 1000.0) is not None
    net.calls.clear()
    for t in range(1, 5):
        assert r.resolve("https://ps.corp.example", DWK, key.kid, 1000.0 + t) is not None
    assert net.calls == []


def test_a_signer_whose_host_is_down_keeps_its_backoff_in_a_full_share() -> None:
    # Down at first contact, it is tried and unreached, like a made-up name; pushed out of
    # its domain's share, it keeps its floor, so it is not fetched again within its wait.
    net = Network()
    net.down.add(f"https://ps.corp.example/.well-known/{DWK}")
    r = JwksUriResolver(net, max_per_domain=2)
    with pytest.raises(SignatureError):
        r.resolve("https://ps.corp.example", DWK, "k1", 1000.0)
    for t in range(1, 30):
        for j in range(2):                               # two names made up between its tries
            with pytest.raises(SignatureError):
                r.resolve(f"https://a{t}-{j}.corp.example", DWK, "k1", 1000.0 + t)
        with pytest.raises(SignatureError):
            r.resolve("https://ps.corp.example", DWK, "k1", 1000.0 + t)
    assert net.calls.count(f"https://ps.corp.example/.well-known/{DWK}") == 1


def test_the_floor_table_keeps_a_signer_whose_keys_are_being_fetched() -> None:
    # Made-up names of other domains fill the table while its first fetch is in flight: its
    # entry becomes a floor, and the floors that give way are made-up names', not its own.
    class Busy(Network):
        def __init__(self) -> None:
            super().__init__()
            self.during: list[Any] = []

        def fetch_json(self, url: str) -> Any:
            while self.during:
                self.during.pop()()
            return super().fetch_json(url)

    net = Busy()
    key = _signer(net, "https://ps.honest.example")
    r = JwksUriResolver(net, max_entries=1)

    def junk(i: int) -> Any:
        def run() -> None:
            with pytest.raises(SignatureError):
                r.resolve(f"https://n.junk{i}.example", DWK, "k1", 1000.0)
        return run

    net.during = [junk(i) for i in range(12)]
    assert r.resolve("https://ps.honest.example", DWK, key.kid, 1000.0) is not None
    net.calls.clear()
    assert r.resolve("https://ps.honest.example", DWK, key.kid, 1001.0) is not None
    assert net.calls == []


def test_the_floors_stay_within_their_bound_under_churn_of_made_up_names() -> None:
    # Names made up under one domain, pushed out of its share within their wait, keep a
    # floor only while the table of floors has room: it never passes four times the table.
    net = Network()
    r = JwksUriResolver(net, max_entries=4, max_per_domain=2)
    for i in range(200):
        with pytest.raises(SignatureError):
            r.resolve(f"https://n{i}.junk.example", DWK, "k1", 1000.0 + i / 10)
    assert len(r._floors) <= 4 * r.max_entries


def test_a_down_signer_pushed_out_by_churn_is_fetched_at_most_once_a_minute() -> None:
    # Its floor lasts its own wait; pushed out of the cache by other signers past it, it
    # starts its backoff over, but is never fetched more often than once a minute
    # (Protocol L2284), and no more often than once per period it asks.
    def fetches(churn: bool) -> list[float]:
        net = Network()
        url = f"https://ps.corp.example/.well-known/{DWK}"
        net.down.add(url)
        r = JwksUriResolver(net, max_per_domain=2)
        for t in range(0, 16 * 60, 70):
            if churn:
                for j in range(2):
                    with pytest.raises(SignatureError):
                        r.resolve(f"https://a{t}-{j}.corp.example", DWK, "k1", 1000.0 + t)
            with pytest.raises(SignatureError):
                r.resolve("https://ps.corp.example", DWK, "k1", 1000.0 + t)
            if net.calls.count(url) > len(times):
                times.append(t)
        return times

    times: list[float] = []
    churned = fetches(churn=True)
    assert all(b - a >= 60 for a, b in zip(churned, churned[1:], strict=False))
    times = []
    assert len(fetches(churn=False)) <= len(churned)


def test_made_up_names_are_evicted_before_a_signer_holding_keys() -> None:
    # A flood of names nobody serves documents for, under other domains, fills the cache:
    # they make room for each other, and a signer whose keys are held keeps them.
    net = Network()
    key = _signer(net)
    r = JwksUriResolver(net, max_entries=4)
    r.resolve(PS, DWK, key.kid, 1000.0)
    net.down.add(META)
    net.down.add(JWKS)
    for i in range(40):
        with pytest.raises(SignatureError):
            r.resolve(f"https://n.junk{i}.example", DWK, "k1", 1070.0 + i)
    assert r.resolve(PS, DWK, key.kid, 1120.0) is not None   # its host down, its keys held


def test_a_made_up_name_back_from_its_floor_takes_its_domain_s_share() -> None:
    net = Network()
    r = JwksUriResolver(net, max_entries=64, max_per_domain=2)
    for i in range(30):
        for name in (f"https://n{i}.evil.example", f"https://n{max(i - 1, 0)}.evil.example"):
            try:
                r.resolve(name, DWK, "k1", 1000.0 + i)
            except SignatureError:
                pass
    held = [k for k, e in r._entries.items() if e.domain == "evil.example"]
    assert len(held) <= 2


def test_a_made_up_name_evicted_past_its_wait_leaves_no_floor() -> None:
    # Its floor protects no fetch once its wait is over: it is forgotten, not floored.
    net = Network()
    r = JwksUriResolver(net, max_entries=4)
    for i in range(4):
        with pytest.raises(SignatureError):
            r.resolve(f"https://n.junk{i}.example", DWK, "k1", 1000.0)
    with pytest.raises(SignatureError):
        r.resolve("https://n.later.example", DWK, "k1", 1000.0 + 2 * 3600)
    assert len(r._entries) == 4
    assert not any(k.startswith("https://n.junk") for k in r._floors)
