"""Outbound fetches for key discovery, under egress admission (Signature-Key 7.3).

- HTTPS only (plain http only for hosts the configuration admits); response size and
  timeout limits; no redirects.
- Private, loopback and link-local destinations refused unless admitted by config.
- DNS rebinding defence: the address is resolved once, checked, and the TLS
  connection is made to that pinned address with the original host as SNI.
- Cross-origin jwks_uri (JWKS host != metadata host) refused unless admitted.
"""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import json
import socket
import ssl
import threading
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
    a: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(a, ipaddress.IPv6Address):
        if a in _SITE_LOCAL:
            return False  # deprecated (RFC 3879), and global on some Python versions
        if a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        elif a in _NAT64 or a in _NAT64_LOCAL or a in _IPV4_COMPATIBLE:
            # The IPv4 address a NAT64 or IPv4-compatible address carries is where it goes.
            a = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
        elif a.sixtofour is not None:
            a = a.sixtofour  # 6to4 (RFC 3056): likewise, judged alike on every version
    return a.is_global and not a.is_multicast


_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.IPv6Network("64:ff9b:1::/48")  # RFC 8215, the low 32 bits
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")


@dataclass
class HttpsFetcher:
    """Real network fetcher with egress admission."""

    policy: EgressPolicy = field(default_factory=EgressPolicy)

    def fetch_json(self, url: str) -> Any:
        """Fetch under one deadline, `policy.timeout`, over every step: name resolution
        (which has no timeout of its own), connect, TLS, the status line and headers (a
        server trickling them one byte at a time keeps each read within a socket timeout),
        and the body. Past it the connection's socket is shut down, which ends the worker's
        read, and a worker that finishes resolving or connecting later sends nothing; a
        resolver still waiting is left to the OS's own resolver timeout, on a daemon
        thread that holds no socket."""
        box: dict[str, Any] = {}
        lock = threading.Lock()
        worker = threading.Thread(target=self._run, args=(url, box, lock), daemon=True)
        worker.start()
        worker.join(self.policy.timeout)
        with lock:
            if "value" not in box and "error" not in box:
                box["late"] = True
                conn = box.get("conn")
                if conn is not None:
                    # Shutting the socket down ends the worker's read now, and the worker
                    # then closes the connection itself (close() alone would wait for the
                    # response's file to let go of the socket). A worker that has just
                    # closed it on its own way out leaves no socket to shut down.
                    with contextlib.suppress(OSError, AttributeError):
                        conn.sock.shutdown(socket.SHUT_RDWR)
                raise FetchError(f"fetch exceeded {self.policy.timeout}s: {url}")
        if "error" in box:
            e = box["error"]
            if isinstance(e, ValueError):
                # A URL `urllib` cannot read (a port out of range, an unbalanced bracket)
                # or a host name IDNA refuses (a label longer than 63) is a failed fetch.
                raise FetchError(f"fetch failed: {url}: {e}") from e
            raise e
        return box["value"]

    def _run(self, url: str, box: dict[str, Any], lock: threading.Lock) -> None:
        try:
            value = self._fetch(url, box, lock)
        except Exception as e:  # handed to the caller, which raises it
            with lock:
                box["error"] = e
        else:
            with lock:
                box["value"] = value

    def _fetch(self, url: str, box: dict[str, Any], lock: threading.Lock) -> Any:
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
        def still_wanted() -> None:
            if box.get("late"):  # the caller has given up and raised already
                raise FetchError(f"fetch exceeded {self.policy.timeout}s: {url}")

        try:
            # Past the deadline the caller shuts a published connection's socket down. A
            # worker that only finishes resolving or connecting after that must not go on
            # to send the request, so it connects first and publishes the connection only
            # if it is still wanted.
            with lock:
                still_wanted()
            conn.connect()
            with lock:
                still_wanted()
                box["conn"] = conn
            conn.request("GET", path, headers={"Host": parts.netloc, "Accept": "application/json"})
            resp = conn.getresponse()
            if 300 <= resp.status < 400:
                raise FetchError("redirect refused")
            if resp.status != 200:
                raise FetchError(f"HTTP {resp.status} from {url}")
            chunks: list[bytes] = []
            size = 0
            while size <= self.policy.max_bytes:
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
        except (ValueError, RecursionError) as e:
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
