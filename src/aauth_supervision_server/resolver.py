"""jwks_uri key discovery (Signature-Key 3.6) with a small, bounded, thread-safe cache."""

from __future__ import annotations

import json
import logging
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .egress import EgressPolicy, Fetcher, FetchError
from .errors import SignatureError
from .jwk import VerifyKey, key_from_jwk

LOG = logging.getLogger("aauth_supervision_server")

# What is kept of a signer's documents, so that an entry costs little whatever they hold
# (Signature-Key -09 L2379): of its JWKS the first keys, each with the members a key is
# found and read by (others are ignored, RFC 7517 Section 4; an RSA modulus of 8192 bits
# is 1,366 characters), of its metadata the members the SS reads.
MAX_KEYS = 32
MAX_KEYS_BYTES = 16 * 1024  # of the keys kept, as JSON: about twenty RSA keys of 4096 bits
MAX_KEY_MEMBER = 2048
MAX_KEY_OPS = 16
MAX_META_STR = 2048
_META_KEPT = ("issuer", "jwks_uri", "name")
_KEY_KEPT = ("kty", "crv", "x", "y", "n", "e", "kid", "alg", "use", "key_ops")
# Private key members (RFC 7518 Section 6): a key published with any is refused when used.
_KEY_PRIVATE = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


@dataclass
class _Entry:
    """What is known of one signer's keys. Read and written under `lock`, which is also
    held for the signer's fetch: requests for one signer that arrive together make one."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    jwks: dict[str, Any] | None = None
    meta: dict[str, Any] | None = None
    fetched: float = 0.0   # the last fetch that succeeded
    tried: float = -math.inf  # the last fetch attempted
    failures: int = 0      # failed fetches since the last that succeeded
    reached: bool = False  # whether its JWKS was ever requested (the floor binds that)
    domain: str = ""       # `signer_domain` of the signer, counted against its domain's share
    error: SignatureError | None = None


@dataclass
class JwksUriResolver:
    fetcher: Fetcher
    policy: EgressPolicy = field(default_factory=EgressPolicy)
    ttl: float = 300.0
    # Protocol L2284: "MUST NOT fetch a given issuer's JWKS more frequently than once per
    # minute. If a JWKS fetch fails, implementations SHOULD use the cached JWKS if
    # available and SHOULD retry with exponential backoff." The wait after a fetch is
    # `refetch_interval`, doubled for each failure in a row after the first, up to
    # `max_backoff`.
    refetch_interval: float = 60.0
    max_backoff: float = 3600.0
    # Signature-Key -09 L2379: an unbounded cache is a resource exhaustion attack.
    max_entries: int = 1024
    # Entries and floors one domain's signers hold together (`signer_domain`): names made
    # under one domain churn only that share of the table.
    max_per_domain: int = 64
    # Core L2284: when a fetch fails, the cached JWKS is used if available, up to a day.
    max_stale: float = 24 * 3600.0
    # Signers whose entries are never evicted (the trusted PSes): other signers'
    # discoveries cannot push their keys out, so a brief outage of their key host does
    # not lock them out. They are kept apart from, and not counted in, `max_entries`.
    keep: frozenset[str] = frozenset()
    _entries: OrderedDict[tuple[str, str], _Entry] = field(default_factory=OrderedDict)
    # An evicted signer's entry while its floor lasts (`_evict`): when its keys were last
    # tried, and the keys it held, which stay its keys until it may fetch again.
    _floors: OrderedDict[tuple[str, str], _Entry] = field(default_factory=OrderedDict)
    _kept: dict[tuple[str, str], _Entry] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        now = time.time() if now is None else now
        meta_url = _meta_url(signer_id, dwk, self.policy)
        e = self._entry((signer_id, dwk), now)
        with e.lock:
            key = _find(self._jwks(e, signer_id, meta_url, now), kid)
            if key is None:
                # An unknown kid is a rotation: refetch, within the same floor.
                key = _find(self._jwks(e, signer_id, meta_url, now, force=True), kid)
        if key is None:
            raise SignatureError("unknown_key", f"kid {kid!r} not in JWKS of {signer_id}")
        return key

    def refresh(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        """The key for `kid` once the signer's JWKS is refetched, within the same floor:
        for a cached key that failed to verify, which may have been replaced under its
        `kid` (Protocol L2286; Signature-Key -09 Section 7.2). Within the floor, the key
        already held."""
        now = time.time() if now is None else now
        meta_url = _meta_url(signer_id, dwk, self.policy)
        e = self._entry((signer_id, dwk), now)
        with e.lock:
            key = _find(self._jwks(e, signer_id, meta_url, now, force=True), kid)
        if key is None:
            raise SignatureError("unknown_key", f"kid {kid!r} not in JWKS of {signer_id}")
        return key

    def cached_metadata(self, signer_id: str, dwk: str) -> dict[str, Any] | None:
        """The signer's metadata as last fetched for key discovery (no network)."""
        with self._lock:
            e = self._kept.get((signer_id, dwk)) or self._entries.get((signer_id, dwk))
        return e.meta if e is not None else None

    def _entry(self, k: tuple[str, str], now: float) -> _Entry:
        """The signer's entry, made the most recently used; beyond `max_entries` one is
        evicted (`_evict`). A new entry for a signer evicted within its floor starts from
        when its keys were last tried."""
        with self._lock:
            if k[0] in self.keep:
                return self._kept.setdefault(k, _Entry())
            e = self._entries.get(k)
            if e is None:
                # A signer back within its floor takes its place again: the table does not
                # grow. A new one needs room in its domain's share and in the table.
                self._prune(now)
                back = self._floors.get(k)
                if back is not None and not back.reached:
                    self._domain_room(back.domain, now)  # an entry again: in its share
                e = self._floors.pop(k) if k in self._floors else None
                if e is None:
                    domain = signer_domain(k[0])
                    self._domain_room(domain, now)
                    if len(self._entries) >= self.max_entries and not self._room(now):
                        raise SignatureError("invalid_key", "too many signers' keys are "
                                             "being looked up; try again in a minute")
                    e = _Entry(domain=domain)
                self._entries[k] = e
                while len(self._entries) > self.max_entries:
                    self._evict(now)
            else:
                self._entries.move_to_end(k)
            return e

    def _prune(self, now: float) -> None:
        """Forget the floors past their wait: the minute Protocol L2284 requires, longer for
        a signer whose fetches failed. A signer whose floor is forgotten starts over, never
        fetched more than once a minute."""
        for k in [k for k, f in self._floors.items() if now - f.tried >= self._wait(f)]:
            del self._floors[k]

    def _domain_room(self, domain: str, now: float) -> None:
        """Make room in `domain`'s share for a new signer: one whose JWKS was never
        requested goes first (a name nobody serves documents for, made up under someone
        else's domain: no fetch the floor protects, and no keys), then one of its entries
        past its floor; with none, the signer is refused, and only that domain's
        signers are."""
        # A floor of a name never reached holds no keys and no share: it only keeps that
        # name's backoff, and gives way first when the table of floors is full (`_room`).
        held = [(t, k) for t in (self._floors, self._entries) for k, f in t.items()
                if f.domain == domain and (t is self._entries or f.reached)]
        if len(held) < self.max_per_domain:
            return
        for t, k in sorted(held, key=lambda tk: not _made_up(tk[0][tk[1]])):
            f = t[k]
            if _made_up(f) or (t is self._entries and f.tried > -math.inf
                               and now - f.tried >= self._wait(f)):
                del t[k]
                if t is self._entries and now - f.tried < self._wait(f) and (
                        len(self._floors) < 4 * self.max_entries):
                    self._floors[k] = f  # within its wait: its floor stays (L2284)
                return
        raise SignatureError("invalid_key", "too many of this domain's signers' keys are "
                             "being looked up; try again in a minute")

    def _room(self, now: float) -> bool:
        """Whether a new signer can be taken without forgetting a live fetch floor: one
        held is past its floor, or the floors kept (each for the one minute Protocol
        L2284 requires, "MUST NOT fetch a given issuer's JWKS more frequently than once
        per minute") leave room for one more, at most four times `max_entries`."""
        if len(self._floors) >= 4 * self.max_entries:
            # A signer whose JWKS was never requested (its metadata could not be had: one
            # made up, most likely) has no fetch the floor protects: its floor gives way.
            free = next((k for k, f in self._floors.items() if _made_up(f)), None)
            if free is not None:
                del self._floors[free]
        return len(self._floors) < 4 * self.max_entries or any(
            now - e.tried >= self._wait(e) for e in self._entries.values())

    def _evict(self, now: float) -> None:
        """Evict a name nobody serves documents for first (`_made_up`), so that a flood of
        them makes room for each other and a signer whose keys are held keeps them; then
        the signer used least recently whose fetch floor has passed, one holding no keys
        first; with none, the one used least recently that holds no keys, then the one
        used least recently. One evicted within its floor is remembered with what it held
        (`_room` made sure there is room to)."""
        newest = next(reversed(self._entries))
        others = [(k, e) for k, e in self._entries.items() if k != newest]
        gone = next((k for k, e in others if _made_up(e)), None)
        if gone is not None:
            f = self._entries.pop(gone)
            if now - f.tried < self._wait(f) and len(self._floors) < 4 * self.max_entries:
                self._floors[gone] = f
            return
        past = [(k, e) for k, e in others if now - e.tried >= self._wait(e)]
        gone = next((k for k, e in past if e.jwks is None), next((k for k, _ in past), None))
        if gone is not None:
            del self._entries[gone]
            return
        k = next((k for k, e in others if e.jwks is None), next(iter(self._entries)))
        self._floors[k] = self._entries.pop(k)

    def _wait(self, e: _Entry) -> float:
        return self._wait_of(e.failures)

    def _wait_of(self, failures: int) -> float:
        if not failures:
            return self.refetch_interval
        return min(self.refetch_interval * 2 ** (failures - 1), self.max_backoff)

    def _jwks(self, e: _Entry, signer_id: str, meta_url: str, now: float,
              force: bool = False) -> dict[str, Any]:
        """The signer's JWKS: from the cache within the TTL (unless `force`), else fetched
        if the floor allows. Otherwise, or if the fetch fails, the keys already held while
        they are less than `max_stale` old, so neither a brief outage nor a request naming
        a made-up kid locks a known signer out; with none held, the last failure."""
        fresh = e.jwks is not None and now - e.fetched < self.ttl
        if (fresh and not force) or now - e.tried < self._wait(e):
            return self._held(e, now)
        e.tried = now
        try:
            e.jwks, e.meta = self._fetch(e, signer_id, meta_url)
        except SignatureError as err:
            e.failures, e.error = e.failures + 1, err
            return self._held(e, now)
        e.fetched, e.failures, e.error = now, 0, None
        return e.jwks

    def _held(self, e: _Entry, now: float) -> dict[str, Any]:
        if e.jwks is not None and now - e.fetched < self.max_stale:
            return e.jwks
        # A new exception each time: one object raised again by every request in the
        # backoff window would carry all of their frames.
        if e.error is not None:
            raise SignatureError(e.error.error, e.error.detail)
        raise SignatureError("invalid_key", "the signer's keys are not available")

    def _fetch(self, entry: _Entry, signer_id: str, meta_url: str
               ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            meta = self.fetcher.fetch_json(meta_url)
        except FetchError as e:
            # Why (an address this SS resolved, a name it could not) is the operator's, not
            # the signer's: under open registration the signer is anyone.
            LOG.warning("key discovery for %r: metadata fetch failed: %r", signer_id, str(e))
            raise SignatureError("invalid_key", "metadata fetch failed") from e
        if not isinstance(meta, dict) or "issuer" not in meta:
            raise SignatureError("issuer_missing", f"{meta_url} has no issuer")
        if meta["issuer"] != signer_id:
            raise SignatureError("issuer_mismatch", f"issuer {meta['issuer']!r} != {signer_id!r}")
        jwks_uri = meta.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise SignatureError("invalid_key", "metadata has no jwks_uri")
        try:
            host = urlsplit(jwks_uri).hostname
        except ValueError as e:  # an unbalanced bracket, for one
            raise SignatureError("invalid_key", "jwks_uri is not a URL") from e
        if host != urlsplit(signer_id).hostname and not self.policy.allow_cross_origin_jwks:
            raise SignatureError("invalid_key", "cross-origin jwks_uri not admitted")
        entry.reached = True
        try:
            jwks = self.fetcher.fetch_json(jwks_uri)
        except FetchError as e:
            LOG.warning("key discovery for %r: JWKS fetch failed: %r", signer_id, str(e))
            raise SignatureError("invalid_key", "JWKS fetch failed") from e
        if not isinstance(jwks, dict):
            raise SignatureError("invalid_key", "JWKS is not an object")
        if not isinstance(jwks.get("keys", []), list):
            raise SignatureError("invalid_key", "JWKS `keys` is not an array")
        keys: list[dict[str, Any]] = []
        size = 0
        for k in map(_kept_key, jwks.get("keys", [])):
            if k is None:
                continue
            size += len(json.dumps(k))
            if len(keys) == MAX_KEYS or size > MAX_KEYS_BYTES:
                break
            keys.append(k)
        kept = {m: v[:MAX_META_STR] if m == "name" else v for m, v in meta.items()
                if m in _META_KEPT and isinstance(v, str)
                and (m == "name" or len(v) <= MAX_META_STR)}
        return {"keys": keys}, kept


# Suffixes under which names are registered by different holders, so that a domain is one
# label more: countries' second levels, and hosting services that give each customer a
# name of its own. A fixed list, not complete: a suffix missing from it counts as one
# domain for everyone under it (stricter for them, never looser).
_SECOND_LEVELS = {
    "uk": "co org me ltd plc net ac gov sch nhs police",
    "au": "com net org edu gov id asn", "nz": "co org net ac govt geek school",
    "jp": "co ne or ac go ed gr lg", "kr": "co or ne ac go re",
    "br": "com net org gov edu", "cn": "com net org gov edu ac",
    "in": "co net org firm gen ind ac edu gov", "za": "co org net gov ac web",
    "mx": "com org gob edu net", "ar": "com org net gob edu", "tr": "com net org gov edu",
    "sg": "com net org gov edu", "hk": "com net org gov edu", "tw": "com net org gov edu idv",
    "il": "co org net ac gov", "my": "com net org gov edu", "ph": "com net org gov edu",
    "pk": "com net org gov edu", "id": "co or ac go web my", "th": "co or ac go in",
    "vn": "com net org gov edu", "ua": "com net org gov edu", "es": "com org nom gob edu",
    "pl": "com net org", "co": "com net org", "pe": "com net org gob edu",
    "ke": "co or ac go", "ng": "com net org gov edu", "eg": "com net org gov edu",
}
_SUFFIXES = frozenset(
    [f"{s}.{tld}" for tld, ss in _SECOND_LEVELS.items() for s in ss.split()] + [
        "github.io", "gitlab.io", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
        "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com", "azurewebsites.net",
        "azurestaticapps.net", "cloudfront.net", "blogspot.com", "fly.dev", "onrender.com",
        "glitch.me", "ngrok.io", "ngrok.app", "ngrok-free.app", "deno.dev", "run.app",
        "a.run.app", "repl.co", "replit.app", "surge.sh", "readthedocs.io",
        "amplifyapp.com", "elasticbeanstalk.com", "s3.amazonaws.com"])


def _made_up(f: _Entry) -> bool:
    """Tried, with its JWKS never requested, and not being fetched now: a name nobody
    serves documents for. One never tried, or in flight, is not that."""
    return not f.reached and f.tried > -math.inf and not f.lock.locked()


def signer_domain(signer_id: str) -> str:
    """The domain a signer's name is made under: one label more than the longest suffix
    of `_SUFFIXES` it ends with, else its host's last two labels. Any number of names can
    be made under a domain one holds (a wildcard DNS entry); fairness between signers
    counts them as one. An address is its own."""
    try:
        labels = (urlsplit(signer_id).hostname or signer_id).rstrip(".").split(".")
    except ValueError:
        return signer_id
    if labels[-1].isdigit():
        return ".".join(labels)
    n = max((k + 1 for k in (2, 3) if ".".join(labels[-k:]) in _SUFFIXES), default=2)
    return ".".join(labels[-n:])


def _meta_url(signer_id: str, dwk: str, policy: EgressPolicy) -> str:
    """The signer's metadata URL, or `invalid_key` for an id or `dwk` that cannot name one.
    Refused here, before any entry is made: no fetch is involved."""
    try:
        parts = urlsplit(signer_id)
        host = parts.hostname
    except ValueError as e:  # an unbalanced bracket, for one
        raise SignatureError("invalid_key", "signer id is not a URL") from e
    if not signer_id.startswith("https://") and host not in policy.allow_http_hosts:
        raise SignatureError("invalid_key", "signer id is not an HTTPS URL")
    if "/" in dwk or not dwk:
        raise SignatureError("invalid_key", "bad dwk")
    if parts.query or parts.fragment or "@" in parts.netloc or "?" in signer_id \
            or "#" in signer_id:
        raise SignatureError("invalid_key", "signer id must not carry userinfo, query or fragment")
    return signer_id.rstrip("/") + "/.well-known/" + dwk


def _kept_key(k: Any) -> dict[str, Any] | None:
    """A JWK with only the members a key is found and read by, or None for one with such
    a member that is not a short string (`key_ops`: a short array of them)."""
    if not isinstance(k, dict):
        return None
    out: dict[str, Any] = {}
    if any(m in k for m in _KEY_PRIVATE):
        out["d"] = ""  # what `key_from_jwk` refuses: a public JWK carrying private material
    for m in _KEY_KEPT:
        if m not in k:
            continue
        v = k[m]
        if m == "key_ops":
            ok = isinstance(v, list) and len(v) <= MAX_KEY_OPS and all(
                isinstance(x, str) and len(x) <= MAX_KEY_MEMBER for x in v)
        else:
            ok = isinstance(v, str) and len(v) <= MAX_KEY_MEMBER
        if not ok:
            return None
        out[m] = v
    return out


def _find(jwks: Any, kid: str) -> VerifyKey | None:
    """The key with this kid. Two keys sharing a kid are ambiguous and refused."""
    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    matches = [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
    if not matches:
        return None
    if len(matches) > 1:
        raise SignatureError("invalid_key", f"kid {kid!r} is not unique in the JWKS")
    use = matches[0].get("use")
    ops = matches[0].get("key_ops")  # RFC 7517 Section 4.3: what the key is for
    if (use is not None and use != "sig") or (
            ops is not None and not (isinstance(ops, list) and "verify" in ops)):
        raise SignatureError("invalid_key", f"key {kid!r} is not a signing key")
    return key_from_jwk({m: v for m, v in matches[0].items() if m not in ("use", "key_ops")})
