"""A real HTTP listener for the Supervision Server.

The SS is an HTTPS server identified by its `issuer`. This listener speaks plain
HTTP on a LOOPBACK address only and is meant to sit behind a TLS-terminating
reverse proxy that serves the `issuer` origin. It refuses any non-loopback bind:
exposing it directly would put an unencrypted endpoint on the network.

The proxy MUST pass the original `Host` header through, because the SS checks
that a request was addressed to it and the PS signs `@authority`.
"""

from __future__ import annotations

import io
import ipaddress
import json
import logging
import math
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .httpsig import HttpRequest
from .service import SupervisionServer

# One line per request (method, path, status; never bodies or headers). An embedding
# application configures handlers; `aauth-ss serve` logs it to stdout.
ACCESS_LOG = logging.getLogger("aauth_supervision_server.access")

MAX_BODY = 1024 * 1024  # 1 MiB: supervision requests carry tokens and a proposal, not files
# C0 and C1 controls (and the backslash that escapes them) as `\xNN`, as the standard
# library's own `log_message` writes them: a request line may carry ESC and the like
# (only CR LF end it), which a terminal showing the log would act on.
_LOG_ESCAPES = {c: f"\\x{c:02x}" for c in (*range(0x20), *range(0x7F, 0xA0))} | {
    ord("\\"): "\\\\"}
READ_TIMEOUT = 15.0  # seconds; the PS sends a complete request at once
# Seconds for a whole request, its request line, header block and body together (and the
# wait for it on a kept-alive connection): each read is bounded by READ_TIMEOUT, so a
# client sending a byte at a time would otherwise hold its thread for as long as it likes.
# A PS sends a request at once.
REQUEST_DEADLINE = 10.0
# Connections served at once, each on its own thread. One beyond them waits in the listen
# queue until one ends (a burst is queued, not refused, and holds no thread meanwhile).
# While every one is taken, each answer closes its connection, so a kept-alive connection
# does not hold its slot between requests. The listener cannot tell clients apart behind
# the proxy, so limits per client belong there (README, Run it).
MAX_CONNECTIONS = 64
# The listening socket's address option. On Windows SO_REUSEADDR lets a second socket bind
# a port another is listening on (and take its connections); SO_EXCLUSIVEADDRUSE refuses
# that bind. Elsewhere SO_REUSEADDR, as the standard library sets it, only lets a restarted
# SS bind while the old process's connections close.
_BIND_OPTION = getattr(socket, "SO_EXCLUSIVEADDRUSE", socket.SO_REUSEADDR)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _DeadlineReader(io.RawIOBase):
    """A connection's reads: each bounded by READ_TIMEOUT, and a request's all together by
    its deadline, which the handler sets as each request begins."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.deadline = math.inf

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("the request took longer than its deadline")
        self.sock.settimeout(min(READ_TIMEOUT, left))
        return self.sock.recv_into(b)


def make_handler(ss: SupervisionServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "aauth-ss"
        protocol_version = "HTTP/1.1"
        # Socket timeout for every read: a client that stops sending its headers or body
        # (or idles on a keep-alive connection) releases its thread instead of holding it.
        timeout = READ_TIMEOUT

        def version_string(self) -> str:
            # The product alone: the default joins it to the Python version with a space.
            return self.server_version

        def _serve(self) -> None:
            # Every refusal here comes before the declared body is read, so the stream is
            # desynced: the connection closes rather than keep-alive onto the unsent bytes.
            if self.request_version == "HTTP/0.9":
                # No fields, so no Host (RFC 9112 3.2). CPython 3.13.16 and 3.14.8 read none
                # for such a request and leave `headers` a plain dict.
                self._problem(400, "bad Host or request target", close=True)
                return
            if self.headers.defects or self.headers.get_payload() or any(
                    "\r" in v or "\n" in v for v in self.headers.values()):
                # RFC 9112 5.1: whitespace between a field name and its colon MUST be a
                # 400. The standard library ends the header block at such a line (or one
                # with no colon), so the fields after it, Content-Length included, would
                # be lost; and 5.2 lets a server refuse an obsolete line folding.
                self._problem(400, "malformed header field", close=True)
                return
            length = self.headers.get("Content-Length")
            if self.headers.get("Transfer-Encoding"):
                self._problem(411, "Content-Length required", close=True)
                return
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) > 1 or (length is not None
                                    and not (length.isascii() and length.isdigit())):
                self._problem(400, "bad Content-Length", close=True)
                return
            n = int(length) if length else 0
            if n > MAX_BODY:
                self._problem(413, "request too large", close=True)
                return
            hosts = self.headers.get_all("Host") or []
            target = _target(self.path)
            if len(hosts) > 1 or (not hosts and self.request_version != "HTTP/1.0") \
                    or target is None:
                # RFC 9112 3.2: a request with no Host (HTTP/1.1), or more than one, MUST
                # be a 400; and a target is origin-form or absolute-form.
                self._problem(400, "bad Host or request target", close=True)
                return
            body = self.rfile.read(n) if n else b""
            headers: dict[str, str] = {}
            for k, v in self.headers.items():
                # RFC 9110 5.3 / RFC 9421 2.1: repeated field lines combine with ", ", so a
                # second Signature or Signature-Input line cannot silently replace the first.
                k = k.lower()
                headers[k] = f"{headers[k]}, {v}" if k in headers else v
            authority, path, query = target
            # RFC 9112 3.2.2: for an absolute-form target, its authority, not Host.
            req = HttpRequest(self.command, authority or headers.get("host", ""), path,
                              headers, body, query)
            resp = ss.handle(req)
            crowded = getattr(self.server, "crowded", None)
            self._reply(resp.status, resp.headers, resp.body,
                        close=bool(callable(crowded) and crowded()))

        def _problem(self, status: int, detail: str, close: bool = False) -> None:
            """A refusal in the format of every other error (Supervision L627; Protocol,
            Error Response Format)."""
            body = json.dumps({"error": "server_error" if status >= 500 else "invalid_request",
                               "detail": detail}, separators=(",", ":")).encode()
            self._reply(status, {"Content-Type": "application/problem+json"}, body, close=close)

        def send_error(self, code: int, message: str | None = None,
                       explain: str | None = None) -> None:
            # The standard library's own refusals (a request line or header block it
            # cannot parse, a line too long, a method with no handler) take the same form.
            # Its messages quote the request line ("Bad request syntax ('GET ...')"), query
            # and all, which can carry an interaction code: the quote is never written.
            message = (message or HTTPStatus(code).phrase).split(" (", 1)[0]
            self.log_error("code %d, message %s", code, message)
            self._problem(code, message, close=True)

        def _reply(self, status: int, headers: dict[str, str], body: bytes,
                   close: bool = False) -> None:
            if self.request_version == "HTTP/0.9":
                # HTTP/0.9 has no status line and no fields, and the standard library
                # reads a request line it cannot parse as HTTP/0.9: every reply has both.
                self.request_version, close = "HTTP/1.0", True
            if close:
                self.close_connection = True
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            # For HEAD, the length the GET would have (RFC 9110 9.3.2), and no content.
            self.send_header("Content-Length", str(len(body)))
            if close:
                self.send_header("Connection", "close")
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)

        do_GET = _serve
        do_HEAD = _serve
        do_POST = _serve
        do_DELETE = _serve

        def setup(self) -> None:
            super().setup()
            self._reads = _DeadlineReader(self.connection)
            self.rfile = io.BufferedReader(self._reads)

        def handle_one_request(self) -> None:
            self._reads.deadline = time.monotonic() + REQUEST_DEADLINE
            # A client that drops a keep-alive connection (or stops mid-request) is normal.
            # Treat it as the end of the connection instead of letting ConnectionResetError /
            # BrokenPipeError / a read timeout reach socketserver, which prints a traceback.
            try:
                super().handle_one_request()
            except (ConnectionError, BrokenPipeError, TimeoutError):
                self.close_connection = True

        def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
            # Method, target and status: never the query, which carries the interaction
            # code on the connect confirmation page (`{url}?code={code}`). A request line
            # the standard library could not parse is answered before it sets a method,
            # a target or a version.
            target = (getattr(self, "path", "") or "-").partition("?")[0]
            self.log_message('"%s %s %s" %s %s', self.command or "-", target,
                             self.request_version or "-", str(code), str(size))

        def log_message(self, fmt: str, *args: Any) -> None:  # one line per request, no bodies
            ACCESS_LOG.info("%s %s", self.address_string(), (fmt % args).translate(_LOG_ESCAPES))

    return Handler


def _target(t: str) -> tuple[str, str, str] | None:
    """(authority, path, query) of a request target in origin-form (no authority) or
    absolute-form (RFC 9112 3.2.1, 3.2.2); None for any other. An origin-form target is
    split at its first `?` only, never read as a URL (the standard library has already
    turned a leading `//` into `/`)."""
    if t.startswith("/"):
        path, _, query = t.partition("?")
        return "", path, query
    try:
        parts = urlsplit(t)
        parts.port  # noqa: B018 - raises for a port out of range or not a number
    except ValueError:  # an unbalanced bracket, for one
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc \
            or "@" in parts.netloc:
        return None
    return parts.netloc, parts.path or "/", parts.query


def serve(ss: SupervisionServer, host: str = "127.0.0.1", port: int = 8443,
          ready: threading.Event | None = None) -> ThreadingHTTPServer:
    """Bind and return the server (call `.serve_forever()`); loopback addresses only."""
    if not _is_loopback(host):
        raise ValueError(f"refusing to bind {host}: the SS listens on loopback only and is "
                         f"served to the network by a TLS reverse proxy for its issuer")

    cap = MAX_CONNECTIONS
    slots = threading.BoundedSemaphore(cap)
    served = [0]  # connections being served, under `count`
    count = threading.Lock()

    def done() -> None:
        with count:
            served[0] -= 1
        slots.release()

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET  # `::1`
        # The default listen backlog of 5 refuses a burst of PS requests outright.
        request_queue_size = 128
        allow_reuse_address = False  # `_BIND_OPTION` instead

        def server_bind(self) -> None:
            self.socket.setsockopt(socket.SOL_SOCKET, _BIND_OPTION, 1)
            super().server_bind()

        def process_request(self, request: Any, client_address: Any) -> None:
            slots.acquire()  # beyond MAX_CONNECTIONS, the next connection waits for one
            with count:
                served[0] += 1
            try:
                super().process_request(request, client_address)
            except BaseException:
                done()
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                done()

        def crowded(self) -> bool:
            """Whether every slot is taken (see MAX_CONNECTIONS)."""
            with count:
                return served[0] >= cap

        def handle_error(self, request: Any, client_address: Any) -> None:
            # A dropped connection is routine; only unexpected errors are worth a traceback.
            exc = sys.exc_info()[1]
            if isinstance(exc, (ConnectionError, BrokenPipeError, TimeoutError)):
                return
            super().handle_error(request, client_address)

    httpd = Server((host, port), make_handler(ss))
    httpd.daemon_threads = True
    if ready:
        ready.set()
    return httpd
