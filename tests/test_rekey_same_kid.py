"""A signer that replaces its key under the same `kid` is verified once its JWKS is refetched.

Protocol L2286 and Signature-Key -09 Section 7.2: when a cached key matching the `kid`
fails verification, the verifier SHOULD refresh the issuer's JWKS once and retry before
refusing, subject to the once-per-minute fetch floor. So a PS that re-keys is served from
the next minute on, not refused until the cache's TTL ends; and a request that does not
verify costs at most one fetch a minute.
"""
from __future__ import annotations

from conftest import SUB, make_env

from aauth_supervision_server.jwk import SigningKey


def _jwks_fetches(fetcher) -> int:
    return sum(1 for u in fetcher.calls if u.endswith("jwks.json"))


def test_a_rekeyed_signer_is_verified_after_one_refetch() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    fetcher = ss.resolver.fetcher
    ps.key = SigningKey.generate(ps.key.kid)       # new key material, same kid
    ps.install(fetcher)
    clock.t += 61                                  # past the floor, inside the 300 s TTL
    before = _jwks_fetches(fetcher)
    assert ps.connect(ss, SUB).status == 200
    assert _jwks_fetches(fetcher) == before + 1
    assert ps.connect(ss, SUB).status == 200       # the new key is now the cached one
    assert _jwks_fetches(fetcher) == before + 1


def test_within_the_floor_a_key_that_fails_is_refused_without_a_fetch() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    fetcher = ss.resolver.fetcher
    ps.key = SigningKey.generate(ps.key.kid)
    ps.install(fetcher)
    clock.t += 10
    before = _jwks_fetches(fetcher)
    r = ps.connect(ss, SUB)
    assert r.status == 401 and r.json()["error"] == "invalid_signature"
    assert _jwks_fetches(fetcher) == before


def test_a_signature_that_never_verifies_costs_one_fetch_a_minute() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    fetcher = ss.resolver.fetcher
    real = ps.key
    ps.key = SigningKey.generate(real.kid)         # a forger's key; the JWKS is unchanged
    clock.t += 61
    before = _jwks_fetches(fetcher)
    for _ in range(3):
        r = ps.connect(ss, SUB)
        assert r.status == 401 and r.json()["error"] == "invalid_signature"
    assert _jwks_fetches(fetcher) == before + 1
    ps.key = real
    assert ps.connect(ss, SUB).status == 200


def test_a_resolver_that_cannot_refresh_refuses_at_once() -> None:
    # `KeyResolver` asks only for `resolve`; one without `refresh` keeps the first answer.
    ss, ps, clock = make_env()
    held = ss.resolver

    class Plain:
        def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None):
            return held.resolve(signer_id, dwk, kid, now)

    ss.resolver = Plain()
    assert ps.connect(ss, SUB).status == 200
    ps.key = SigningKey.generate(ps.key.kid)
    ps.install(held.fetcher)
    clock.t += 61
    r = ps.connect(ss, SUB)
    assert r.status == 401 and r.json()["error"] == "invalid_signature"
