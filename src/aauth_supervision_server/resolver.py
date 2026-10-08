"""jwks_uri key discovery (Signature-Key 3.6) with a small TTL cache."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .egress import EgressPolicy, Fetcher, FetchError
from .errors import SignatureError
from .jwk import VerifyKey, key_from_jwk


@dataclass
class JwksUriResolver:
    fetcher: Fetcher
    policy: EgressPolicy = field(default_factory=EgressPolicy)
    ttl: float = 300.0
    # An unknown kid forces a refetch (key rotation), at most once per this many seconds
    # per signer: otherwise each request with a made-up kid costs two outbound fetches.
    refetch_interval: float = 30.0
    _cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = field(default_factory=dict)
    _meta: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        now = time.time() if now is None else now
        key = _find(self._jwks(signer_id, dwk, now), kid)
        if key is not None:
            return key
        fetched_at = self._cache.get((signer_id, dwk), (0.0, {}))[0]
        if now - fetched_at >= self.refetch_interval:
            self._cache.pop((signer_id, dwk), None)
            key = _find(self._jwks(signer_id, dwk, now), kid)
            if key is not None:
                return key
        raise SignatureError("unknown_key", f"kid {kid!r} not in JWKS of {signer_id}")

    def cached_metadata(self, signer_id: str, dwk: str) -> dict[str, Any] | None:
        """The signer's metadata as last fetched for key discovery (no network)."""
        return self._meta.get((signer_id, dwk))

    def _jwks(self, signer_id: str, dwk: str, now: float) -> dict[str, Any]:
        hit = self._cache.get((signer_id, dwk))
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        if not signer_id.startswith("https://") and urlsplit(signer_id).hostname not in \
                self.policy.allow_http_hosts:
            raise SignatureError("invalid_key", "signer id is not an HTTPS URL")
        if "/" in dwk or not dwk:
            raise SignatureError("invalid_key", "bad dwk")
        parts = urlsplit(signer_id)
        if parts.query or parts.fragment or "@" in parts.netloc or "?" in signer_id \
                or "#" in signer_id:
            raise SignatureError("invalid_key", "signer id must not carry userinfo, query or fragment")
        meta_url = signer_id.rstrip("/") + "/.well-known/" + dwk
        try:
            meta = self.fetcher.fetch_json(meta_url)
        except FetchError as e:
            raise SignatureError("invalid_key", f"metadata fetch failed: {e}") from e
        if not isinstance(meta, dict) or "issuer" not in meta:
            raise SignatureError("issuer_missing", f"{meta_url} has no issuer")
        if meta["issuer"] != signer_id:
            raise SignatureError("issuer_mismatch", f"issuer {meta['issuer']!r} != {signer_id!r}")
        jwks_uri = meta.get("jwks_uri")
        if not isinstance(jwks_uri, str):
            raise SignatureError("invalid_key", "metadata has no jwks_uri")
        if (urlsplit(jwks_uri).hostname != urlsplit(signer_id).hostname
                and not self.policy.allow_cross_origin_jwks):
            raise SignatureError("invalid_key", "cross-origin jwks_uri not admitted")
        try:
            jwks = self.fetcher.fetch_json(jwks_uri)
        except FetchError as e:
            raise SignatureError("invalid_key", f"JWKS fetch failed: {e}") from e
        if not isinstance(jwks, dict):
            raise SignatureError("invalid_key", "JWKS is not an object")
        self._cache[(signer_id, dwk)] = (now, jwks)
        self._meta[(signer_id, dwk)] = meta
        return jwks


def _find(jwks: Any, kid: str) -> VerifyKey | None:
    """The key with this kid. Two keys sharing a kid are ambiguous and refused."""
    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    matches = [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
    if not matches:
        return None
    if len(matches) > 1:
        raise SignatureError("invalid_key", f"kid {kid!r} is not unique in the JWKS")
    use = matches[0].get("use")
    if use is not None and use != "sig":
        raise SignatureError("invalid_key", f"key {kid!r} is not a signing key")
    return key_from_jwk({m: v for m, v in matches[0].items() if m not in ("use", "key_ops")})
