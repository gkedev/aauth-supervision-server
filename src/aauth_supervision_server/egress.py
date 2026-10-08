"""Outbound fetches for key discovery, under egress admission (Signature-Key 7.3).

- HTTPS only; response size and timeout limits; no redirects.
- Private, loopback and link-local destinations refused unless admitted by config.
- DNS rebinding defence: the address is resolved once, checked, and the TLS
  connection is made to that pinned address with the original host as SNI.
- Cross-origin jwks_uri (JWKS host != metadata host) refused unless admitted.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit


class FetchError(Exception):
    pass


class Fetcher(Protocol):
    def fetch_json(self, url: str) -> Any: ...


@dataclass
class EgressPolicy:
    max_bytes: int = 256 * 1024
    timeout: float = 5.0
    allow_private_hosts: frozenset[str] = frozenset()  # hostnames admitted to private ranges
    allow_cross_origin_jwks: bool = False
    allow_http_hosts: frozenset[str] = frozenset()  # test/dev only: plain http admitted


def _is_public(ip: str) -> bool:
    """A globally routable unicast address. `is_global` also excludes shared (CGNAT),
    documentation and benchmarking ranges that `is_private` misses; an IPv4-mapped
    IPv6 address is judged by the IPv4 address it maps to."""
    a = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


@dataclass
class HttpsFetcher:
    """Real network fetcher with egress admission."""

    policy: EgressPolicy = field(default_factory=EgressPolicy)

    def fetch_json(self, url: str) -> Any:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.username is not None or parts.password is not None or parts.fragment:
            raise FetchError(f"URL with userinfo or fragment refused: {url}")
        if parts.scheme != "https" and not (parts.scheme == "http"
                                             and host in self.policy.allow_http_hosts):
            raise FetchError(f"non-HTTPS fetch refused: {url}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as e:
            raise FetchError(f"cannot resolve {host}") from e
        ip = infos[0][4][0]
        if not _is_public(ip) and host not in self.policy.allow_private_hosts:
            raise FetchError(f"destination {host} -> {ip} is not public")
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = _PinnedHTTPSConnection(host, port, ip, self.policy.timeout)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=self.policy.timeout)
        try:
            conn.request("GET", path, headers={"Host": parts.netloc, "Accept": "application/json"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                raise FetchError("redirect refused")
            if resp.status != 200:
                raise FetchError(f"HTTP {resp.status} from {url}")
            # `timeout` bounds each socket read; this bounds the whole body, so a server
            # trickling one byte at a time cannot hold the fetch open indefinitely.
            deadline = time.monotonic() + self.policy.timeout
            chunks: list[bytes] = []
            size = 0
            while size <= self.policy.max_bytes:
                if time.monotonic() > deadline:
                    raise FetchError(f"fetch exceeded {self.policy.timeout}s: {url}")
                chunk = resp.read1(min(65536, self.policy.max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            data = b"".join(chunks)
            if len(data) > self.policy.max_bytes:
                raise FetchError("response too large")
        except (OSError, http.client.HTTPException) as e:
            raise FetchError(f"fetch failed: {url}: {e}") from e
        finally:
            conn.close()
        try:
            return json.loads(data)
        except ValueError as e:
            raise FetchError(f"not JSON: {url}") from e


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        assert self._context is not None  # type: ignore[attr-defined]
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


@dataclass
class StaticFetcher:
    """In-memory fetcher for tests and simulations: url -> JSON document."""

    documents: dict[str, Any] = field(default_factory=dict)
    calls: list[str] = field(default_factory=list)

    def fetch_json(self, url: str) -> Any:
        self.calls.append(url)
        if url not in self.documents:
            raise FetchError(f"no document at {url}")
        return json.loads(json.dumps(self.documents[url]))
