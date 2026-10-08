"""A real HTTP listener for the Supervision Server.

The SS is an HTTPS server identified by its `issuer`. This listener speaks plain
HTTP on a LOOPBACK address only and is meant to sit behind a TLS-terminating
reverse proxy that serves the `issuer` origin. It refuses any non-loopback bind:
exposing it directly would put an unencrypted endpoint on the network.

The proxy MUST pass the original `Host` header through, because the SS checks
that a request was addressed to it and the PS signs `@authority`.
"""

from __future__ import annotations

import ipaddress
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .httpsig import HttpRequest
from .service import SupervisionServer

# One line per request (method, path, status; never bodies or headers). An embedding
# application configures handlers; `aauth-ss serve` logs it to stdout.
ACCESS_LOG = logging.getLogger("aauth_supervision_server.access")

MAX_BODY = 1024 * 1024  # 1 MiB: supervision requests carry tokens and a proposal, not files
READ_TIMEOUT = 15.0  # seconds; the PS sends a complete request at once


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_handler(ss: SupervisionServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "aauth-ss"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        # Socket timeout for every read: a client that stops sending its headers or body
        # (or idles on a keep-alive connection) releases its thread instead of holding it.
        timeout = READ_TIMEOUT

        def _serve(self) -> None:
            length = self.headers.get("Content-Length")
            # These rejections never read the declared body, so the stream is desynced:
            # the connection must close rather than keep-alive onto the unsent bytes.
            if self.headers.get("Transfer-Encoding"):
                self._reply(411, {"Content-Type": "text/plain"}, b"Content-Length required\n",
                            close=True)
                return
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) > 1 or (length is not None and not length.isdigit()):
                self._reply(400, {"Content-Type": "text/plain"}, b"Bad Content-Length\n",
                            close=True)
                return
            n = int(length) if length else 0
            if n > MAX_BODY:
                self._reply(413, {"Content-Type": "text/plain"}, b"Request too large\n",
                            close=True)
                return
            body = self.rfile.read(n) if n else b""
            parts = urlsplit(self.path)
            headers: dict[str, str] = {}
            for k, v in self.headers.items():
                # RFC 9110 5.3 / RFC 9421 2.1: repeated field lines combine with ", ", so a
                # second Signature or Signature-Input line cannot silently replace the first.
                k = k.lower()
                headers[k] = f"{headers[k]}, {v}" if k in headers else v
            if "host" in headers and "," in headers["host"]:
                self._reply(400, {"Content-Type": "text/plain"}, b"Bad Host\n")
                return
            req = HttpRequest(self.command, headers.get("host", ""), parts.path or "/",
                              headers, body, parts.query)
            resp = ss.handle(req)
            self._reply(resp.status, resp.headers, resp.body)

        def _reply(self, status: int, headers: dict[str, str], body: bytes,
                   close: bool = False) -> None:
            if close:
                self.close_connection = True
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            if close:
                self.send_header("Connection", "close")
            self.end_headers()
            if body:  # do_HEAD is not routed here, so every reply with a body sends it
                self.wfile.write(body)

        do_GET = _serve
        do_POST = _serve
        do_DELETE = _serve

        def handle_one_request(self) -> None:
            # A client that drops a keep-alive connection (or stops mid-request) is normal.
            # Treat it as the end of the connection instead of letting ConnectionResetError /
            # BrokenPipeError / a read timeout reach socketserver, which prints a traceback.
            try:
                super().handle_one_request()
            except (ConnectionError, BrokenPipeError, TimeoutError):
                self.close_connection = True

        def log_message(self, fmt: str, *args: Any) -> None:  # one line per request, no bodies
            ACCESS_LOG.info("%s %s", self.address_string(), fmt % args)

    return Handler


def serve(ss: SupervisionServer, host: str = "127.0.0.1", port: int = 8443,
          ready: threading.Event | None = None) -> ThreadingHTTPServer:
    """Bind and return the server (call `.serve_forever()`); loopback addresses only."""
    if not _is_loopback(host):
        raise ValueError(f"refusing to bind {host}: the SS listens on loopback only and is "
                         f"served to the network by a TLS reverse proxy for its issuer")

    class Server(ThreadingHTTPServer):
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
