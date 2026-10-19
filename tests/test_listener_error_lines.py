"""The listener's own refusals write no part of the request line: not in the error log,
not in the problem `detail`. A request line the standard library cannot parse is quoted
whole by its message, query included, and the query of the confirmation page carries the
interaction code (`{url}?code={code}`).
"""
from __future__ import annotations

import json
import logging
import socket
import threading
from typing import Any

from conftest import make_env

from aauth_supervision_server.http_server import serve


def test_a_malformed_request_line_is_not_echoed(caplog: Any) -> None:
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with caplog.at_level(logging.INFO), socket.create_connection(
                ("127.0.0.1", httpd.server_address[1]), timeout=5) as s:
            s.sendall(b"GET /interaction?code=HK2ZR3DWHE x HTTP/1.1\r\n\r\n")
            out = b""
            while chunk := s.recv(4096):
                out += chunk
    finally:
        httpd.shutdown()
        httpd.server_close()
    head, _, body = out.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 400 ")
    assert json.loads(body) == {"error": "invalid_request", "detail": "Bad request syntax"}
    assert "HK2ZR3DWHE" not in caplog.text and "code 400" in caplog.text
