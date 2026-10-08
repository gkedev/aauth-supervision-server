"""HttpsFetcher network paths, exercised against a loopback server (no internet).

Loopback is admitted explicitly per test (`allow_private_hosts`, `allow_http_hosts`), so
these tests also prove the defaults refuse it.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aauth_supervision_server.egress import EgressPolicy, FetchError, HttpsFetcher

HOST = "127.0.0.1"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:  # keep test output quiet
        pass

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        p = self.path
        if p == "/ok":
            self._send(200, b'{"keys": []}')
        elif p == "/ok?x=1":
            self._send(200, b'{"q": true}')
        elif p == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif p == "/missing":
            self._send(404, b"{}")
        elif p == "/big":
            self._send(200, b'"' + b"a" * 4096 + b'"')
        elif p == "/notjson":
            self._send(200, b"<html>")
        elif p == "/trickle":
            self.send_response(200)
            self.send_header("Content-Length", "64")
            self.end_headers()
            for _ in range(64):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.05)
        else:
            self._send(500, b"{}")

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def port() -> Iterator[int]:
    srv = ThreadingHTTPServer((HOST, 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _admitted(**kw: object) -> HttpsFetcher:
    return HttpsFetcher(EgressPolicy(allow_private_hosts=frozenset({HOST}),
                                     allow_http_hosts=frozenset({HOST}), **kw))  # type: ignore[arg-type]


def test_defaults_refuse_plain_http(port: int) -> None:
    with pytest.raises(FetchError, match="non-HTTPS"):
        HttpsFetcher().fetch_json(f"http://{HOST}:{port}/ok")


def test_defaults_refuse_loopback_even_when_http_admitted(port: int) -> None:
    f = HttpsFetcher(EgressPolicy(allow_http_hosts=frozenset({HOST})))
    with pytest.raises(FetchError, match="not public"):
        f.fetch_json(f"http://{HOST}:{port}/ok")


def test_admitted_fetch_returns_json(port: int) -> None:
    assert _admitted().fetch_json(f"http://{HOST}:{port}/ok") == {"keys": []}


def test_query_string_is_sent(port: int) -> None:
    assert _admitted().fetch_json(f"http://{HOST}:{port}/ok?x=1") == {"q": True}


def test_redirect_is_refused(port: int) -> None:
    with pytest.raises(FetchError, match="redirect refused"):
        _admitted().fetch_json(f"http://{HOST}:{port}/redirect")


def test_non_200_is_refused(port: int) -> None:
    with pytest.raises(FetchError, match="HTTP 404"):
        _admitted().fetch_json(f"http://{HOST}:{port}/missing")


def test_oversize_body_is_refused(port: int) -> None:
    with pytest.raises(FetchError, match="too large"):
        _admitted(max_bytes=1024).fetch_json(f"http://{HOST}:{port}/big")


def test_non_json_body_is_refused(port: int) -> None:
    with pytest.raises(FetchError, match="not JSON"):
        _admitted().fetch_json(f"http://{HOST}:{port}/notjson")


def test_trickled_body_hits_the_whole_body_deadline(port: int) -> None:
    # Each read returns within the socket timeout, but the body as a whole does not.
    with pytest.raises(FetchError, match="exceeded"):
        _admitted(timeout=0.5).fetch_json(f"http://{HOST}:{port}/trickle")


def test_unresolvable_host_is_refused() -> None:
    with pytest.raises(FetchError, match="cannot resolve"):
        HttpsFetcher().fetch_json("https://does-not-exist.invalid/x")


def test_pinned_tls_to_a_non_tls_server_fails_cleanly(port: int) -> None:
    # HTTPS path: the pinned connection dials the resolved IP and starts TLS; a plain
    # HTTP listener makes the handshake fail, which must surface as FetchError.
    f = HttpsFetcher(EgressPolicy(allow_private_hosts=frozenset({HOST}), timeout=2))
    with pytest.raises(FetchError, match="fetch failed"):
        f.fetch_json(f"https://{HOST}:{port}/ok")
