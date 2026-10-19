"""The loopback listener answers every request it reads, in the protocol's error format, and
never lets one request's bytes be read as another's.

- A header block the standard library cannot read whole (whitespace between a field name
  and its colon, a line with no colon, an obsolete line folding) is a 400 and the
  connection closes: the fields after such a line, Content-Length included, would be
  lost and the body read as the next request (RFC 9112 5.1, 5.2).
- A request target is origin-form or absolute-form (RFC 9112 3.2): `//host/path` never
  names another authority; an absolute-form target's authority is the one the request
  is for, whatever Host says (3.2.2); a target `urllib` cannot read is a 400.
- An HTTP/1.1 request with no Host is a 400 (RFC 9112 3.2).
- Every refusal, the listener's own and the standard library's, is
  `application/problem+json` with an `error` member (Supervision L627; Protocol, Error
  Response Format).
- A method a resource does not support is a 405 naming those it does (RFC 9110 15.5.6);
  HEAD is GET without content (RFC 9110 9.1, 9.3.2).
- An unexpected failure is logged, with its traceback, for the operator.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import SUB, make_env

from aauth_supervision_server.http_server import ACCESS_LOG, serve
from aauth_supervision_server.httpsig import HttpRequest

SMUGGLED = b"GET /health HTTP/1.1\r\nHost: ss.example\r\n\r\n"


@pytest.fixture
def live() -> Iterator[tuple[Any, Any, int]]:
    ss, ps, clock = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield ss, ps, httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _exchange(port: int, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        try:
            s.sendall(data)
        except OSError:  # the server refused and closed before reading it all
            pass
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except OSError:
            pass
    return out


def _statuses(out: bytes) -> list[int]:
    return [int(m) for m in re.findall(rb"HTTP/1\.[01] (\d{3}) ", out)]


def _problem(out: bytes) -> tuple[int, dict[str, str], dict[str, Any]]:
    head, _, body = out.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    fields = {k.lower(): v.strip() for k, _, v in (x.partition(":") for x in lines[1:])}
    assert fields.get("content-type") == "application/problem+json", out
    return int(lines[0].split()[1]), fields, json.loads(body)


# ------------------------------------------------------------ header block

@pytest.mark.parametrize("bad", [b"X-Note : hello\r\n", b"X-Note\r\n",
                                 b"X-Fold: a\r\n folded\r\n"],
                         ids=["space-before-colon", "no-colon", "obs-fold"])
def test_a_header_block_read_short_is_a_400_and_the_connection_closes(live: Any,
                                                                     bad: bytes) -> None:
    _, _, port = live
    out = _exchange(port, b"POST /interaction HTTP/1.1\r\nHost: ss.example\r\n" + bad
                    + b"Content-Length: " + str(len(SMUGGLED)).encode() + b"\r\n\r\n" + SMUGGLED)
    assert _statuses(out) == [400]
    status, fields, body = _problem(out)
    assert fields["connection"] == "close" and body["error"] == "invalid_request"


# ------------------------------------------------------------ request target

def test_a_target_with_two_leading_slashes_is_the_path_it_says(live: Any) -> None:
    _, _, port = live
    out = _exchange(port, b"GET //evil.example/health HTTP/1.1\r\nHost: ss.example\r\n"
                          b"Connection: close\r\n\r\n")
    assert _statuses(out) == [404]


def _connect_bytes(ps: Any, target: bytes, host: bytes) -> bytes:
    req = ps.build("POST", "/connect", {"action": "connect", "id": ps.nid("c"),
                                        "iat": int(ps.clock()), "sub": SUB})
    head = "".join(f"{k}: {v}\r\n" for k, v in req.headers.items() if k.lower() != "host")
    return (b"POST " + target + b" HTTP/1.1\r\nHost: " + host + b"\r\n" + head.encode()
            + b"Content-Length: " + str(len(req.body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + req.body)


def test_an_absolute_form_target_names_the_authority_whatever_host_says(live: Any) -> None:
    ss, ps, port = live
    out = _exchange(port, _connect_bytes(ps, b"https://evil.example/connect", b"ss.example"))
    status, _, body = _problem(out)
    assert status == 400 and body["detail"] == "request not addressed to this SS (ss.example)"
    out = _exchange(port, _connect_bytes(ps, b"https://ss.example/connect", b"other.example"))
    assert _statuses(out) == [200]


@pytest.mark.parametrize("extra", [b"", b"X-Long: " + b"a" * 70000 + b"\r\n"],
                         ids=["plain", "header-too-long"])
def test_a_target_urllib_cannot_read_gets_a_reply(live: Any, extra: bytes) -> None:
    _, _, port = live
    out = _exchange(port, b"GET http://[x/ HTTP/1.1\r\nHost: ss.example\r\n" + extra
                    + b"Connection: close\r\n\r\n")
    status, _, body = _problem(out)
    assert status in (400, 431) and body["error"] == "invalid_request"


@pytest.mark.parametrize("target", [b"http://ss.example:abc/health", b"ftp://ss.example/health",
                                    b"http://user@ss.example/health", b"health", b"*"])
def test_a_target_neither_origin_nor_absolute_form_is_a_400(live: Any, target: bytes) -> None:
    _, _, port = live
    out = _exchange(port, b"GET " + target + b" HTTP/1.1\r\nHost: ss.example\r\n"
                          b"Connection: close\r\n\r\n")
    status, _, body = _problem(out)
    assert status == 400 and body["error"] == "invalid_request"


def test_an_http_1_1_request_without_host_is_a_400(live: Any) -> None:
    _, _, port = live
    out = _exchange(port, b"GET /health HTTP/1.1\r\nConnection: close\r\n\r\n")
    status, _, body = _problem(out)
    assert status == 400 and body["error"] == "invalid_request"
    assert _statuses(_exchange(port, b"GET /health HTTP/1.0\r\n\r\n")) == [200]


# ------------------------------------------------------------ the error format

@pytest.mark.parametrize("raw,want", [
    (b"POST /decision HTTP/1.1\r\nHost: ss.example\r\nTransfer-Encoding: chunked\r\n\r\n"
     b"0\r\n\r\n", 411),
    (b"POST /decision HTTP/1.1\r\nHost: ss.example\r\nContent-Length: 1048577\r\n\r\n", 413),
    (b"POST /event HTTP/1.1\r\nHost: ss.example\r\nContent-Length: 2\r\nContent-Length: 2\r\n"
     b"\r\n{}", 400),
    (b"POST /event HTTP/1.1\r\nHost: ss.example\r\nContent-Length: -2\r\n\r\n", 400),
    (b"GET /health HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n", 400),
    (b"GET /health HTTP/1.1\r\nX-Long: " + b"a" * 70000 + b"\r\n\r\n", 431),
    (b"GET / HTTP/1.1 extra\r\n\r\n", 400),
    (b"PUT /decision HTTP/1.1\r\nHost: ss.example\r\nContent-Length: 0\r\n\r\n", 501),
], ids=["chunked", "too-large", "two-lengths", "negative-length", "two-hosts",
        "header-too-long", "bad-request-line", "unknown-method"])
@pytest.mark.req("REF-049")
def test_every_refusal_is_problem_json_with_an_error(live: Any, raw: bytes, want: int) -> None:
    _, _, port = live
    status, fields, body = _problem(_exchange(port, raw))
    assert status == want and fields["connection"] == "close"
    assert body["error"] == ("server_error" if want >= 500 else "invalid_request")
    assert body["detail"]


@pytest.mark.parametrize("method,path,allow", [
    ("POST", "/health", "GET, HEAD"), ("DELETE", "/.well-known/jwks.json", "GET, HEAD"),
    ("GET", "/decision", "POST"), ("GET", "/mission/abc", "POST"),
    ("DELETE", "/interaction", "GET, HEAD, POST"), ("HEAD", "/pending/p1", "GET, POST, DELETE"),
])
def test_a_method_a_resource_does_not_support_is_a_405(method: str, path: str,
                                                        allow: str) -> None:
    ss, _, _ = make_env()
    r = ss.handle(HttpRequest(method, "ss.example", path))
    assert r.status == 405 and r.headers["Allow"] == allow
    assert r.headers["Content-Type"] == "application/problem+json"
    assert json.loads(r.body)["status"] == 405
    assert ss.handle(HttpRequest(method, "ss.example", "/nothing")).status == 404


def test_head_is_get_without_content(live: Any) -> None:
    _, _, port = live
    out = _exchange(port, b"HEAD /health HTTP/1.1\r\nHost: ss.example\r\n\r\n"
                          b"GET /health HTTP/1.1\r\nHost: ss.example\r\nConnection: close\r\n\r\n")
    assert _statuses(out) == [200, 200]
    first, _, rest = out.partition(b"\r\n\r\n")
    assert b"Content-Length: 15" in first and rest.startswith(b"HTTP/1.1 200")
    assert rest.endswith(b'{"status":"ok"}')


# ------------------------------------------------------------ logs

def test_an_unexpected_failure_is_logged_for_the_operator(caplog: Any) -> None:
    ss, ps, _ = make_env()
    ps.connect(ss, SUB)

    class Boom:
        r3_member = None
        ask_on_mission_update = False

        def __getattr__(self, name: str) -> Any:
            raise RuntimeError("secret internals")

    ss.policy = Boom()  # type: ignore[assignment]
    with caplog.at_level(logging.ERROR, logger="aauth_supervision_server"):
        r = ps.call(ss, "POST", "/mission", {"sdi": ps.nid("d"), "iat": int(ps.clock()),
                                              "sub": SUB, "agent": "aauth:a@agent.example",
                                              "agent_token": "x", "description": "d"})
    assert r.status == 500 and b"secret internals" not in r.body
    (rec,) = (x for x in caplog.records if x.name == "aauth_supervision_server")
    assert rec.exc_info and "secret internals" in str(rec.exc_info[1])
    assert "'/mission'" in rec.getMessage()


def test_the_access_log_of_a_request_line_it_cannot_parse_says_so(live: Any,
                                                                  caplog: Any) -> None:
    _, _, port = live
    with caplog.at_level(logging.INFO, logger=ACCESS_LOG.name):
        _exchange(port, b"GARBAGE\r\n\r\n")
    lines = [r.getMessage() for r in caplog.records if r.name == ACCESS_LOG.name]
    assert lines and not any("None" in m for m in lines), lines


def test_an_authority_error_does_not_echo_what_the_client_sent() -> None:
    ss, _, _ = make_env()
    r = ss.handle(HttpRequest("POST", "x" * 5000 + ".example", "/decision", {}, b"{}"))
    assert r.status == 400
    assert json.loads(r.body)["detail"] == "request not addressed to this SS (ss.example)"


@pytest.mark.parametrize("method", ["post", "Get", "PUT", "PATCH", "OPTIONS", "TRACE"])
def test_a_method_the_server_does_not_implement_is_a_501(method: str) -> None:
    # RFC 9110 9.1: method names are case-sensitive; one the server does not implement
    # SHOULD be a 501, in process as on the listener.
    ss, _, _ = make_env()
    for path in ("/decision", "/health", "/nothing"):
        r = ss.handle(HttpRequest(method, "ss.example", path))
        assert r.status == 501, (method, path)
        assert r.headers["Content-Type"] == "application/problem+json"
        assert json.loads(r.body) == {"error": "server_error",
                                      "detail": "method not implemented"}


def test_a_405_carries_an_error(live: Any) -> None:
    # Supervision L627: errors use the Error Response Format, whose `error` is REQUIRED.
    ss, _, _ = make_env()
    r = ss.handle(HttpRequest("GET", "ss.example", "/decision"))
    assert r.status == 405 and json.loads(r.body)["error"] == "invalid_request"
    _, _, port = live
    status, _, body = _problem(_exchange(
        port, b"post /decision HTTP/1.1\r\nHost: ss.example\r\nContent-Length: 0\r\n\r\n"))
    assert status == 501 and body["error"] == "server_error"


def test_the_server_header_names_the_ss_and_nothing_after_it(live: Any) -> None:
    # RFC 9110 Section 10.2.4: `Server` is a product and an optional version; the field
    # value has no trailing whitespace (Section 5.5).
    _, _, port = live
    out = _exchange(port, b"GET /.well-known/aauth-supervisor.json HTTP/1.1\r\n"
                          b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
    head = out.partition(b"\r\n\r\n")[0].split(b"\r\n")
    assert b"Server: aauth-ss" in head, head


def test_an_http_0_9_request_gets_a_400_with_a_status_line(live: Any) -> None:
    # A request line with no version is HTTP/0.9: no fields, so no Host (RFC 9112 3.2).
    # CPython 3.13.16 and 3.14.8 hand such a request no header block at all; it is refused
    # like any request without Host, and the reply has a status line all the same.
    _, _, port = live
    status, fields, body = _problem(_exchange(port, b"GET /.well-known/aauth-supervisor.json\r\n\r\n"))
    assert status == 400 and fields.get("connection") == "close", (status, fields, body)
