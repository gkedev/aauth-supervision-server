"""The real listener (loopback HTTP) and the command line."""

from __future__ import annotations

import argparse
import http.client
import io
import json
import threading

import pytest
from conftest import ROOT, SUB, make_env

from aauth_supervision_server import cli
from aauth_supervision_server.http_server import serve


@pytest.fixture
def live():
    ss, ps, clock = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield ss, ps, port
    httpd.shutdown()
    httpd.server_close()


def _send(port, req):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = dict(req.headers) | {"host": req.authority}
    conn.request(req.method, req.path, body=req.body or None, headers=headers)
    r = conn.getresponse()
    out = r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    conn.close()
    return out


def test_signed_request_over_a_socket(live):
    ss, ps, port = live
    status, headers, body = _send(port, ps.build("POST", "/connect", {
        "action": "connect", "id": "c-1", "iat": 1, "sub": SUB}))
    assert status == 200 and json.loads(body)["status"] == "connected"
    status, headers, body = _send(port, ps.build("GET", "/.well-known/aauth-supervisor.json"))
    assert status == 200 and json.loads(body)["issuer"] == "https://ss.example"


def test_socket_rejects_tampered_body(live):
    ss, ps, port = live
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB})
    req.body = req.body.replace(b"c-1", b"c-2")
    status, headers, _ = _send(port, req)
    assert status == 401 and "signature-error" in headers


def test_body_size_limit(live):
    ss, ps, port = live
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.putrequest("POST", "/decision")
    conn.putheader("Host", "ss.example")
    conn.putheader("Content-Length", str(2 * 1024 * 1024))
    conn.endheaders()
    r = conn.getresponse()
    assert r.status == 413
    # The declared 2 MiB body is never read, so the connection must be told to close:
    # keeping it alive would desync the next request onto the unsent bytes.
    assert r.getheader("Connection", "").lower() == "close"
    conn.close()


def test_oversize_and_dropped_connections_log_no_traceback(capsys):
    # Server errors (handle_error) print to the real stderr via socketserver; capture it
    # and prove a client that drops after an error reply, or mid-request, is silent.
    import sys as _sys
    ss, ps, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with capsys.disabled():
            buf = io.StringIO()
            old = _sys.stderr
            _sys.stderr = buf
            try:
                # 1) oversize declared body, then drop
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.putrequest("POST", "/decision")
                c.putheader("Host", "ss.example")
                c.putheader("Content-Length", str(2 * 1024 * 1024))
                c.endheaders()
                assert c.getresponse().status == 413
                c.close()
                # 2) connect, send nothing, drop (raw socket closed immediately)
                import socket as _sock
                s = _sock.create_connection(("127.0.0.1", port), timeout=5)
                s.close()
                import time
                time.sleep(0.4)
            finally:
                _sys.stderr = old
            assert "Traceback" not in buf.getvalue(), buf.getvalue()
            assert "Exception occurred" not in buf.getvalue(), buf.getvalue()
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])
def test_refuses_non_loopback_bind(host):
    ss, _, _ = make_env()
    with pytest.raises(ValueError, match="loopback"):
        serve(ss, host, 0)


def test_cli_check_policy_ok(capsys):
    assert cli.main(["check-policy", str(ROOT / "examples" / "policy.json")]) == 0
    assert "ok" in capsys.readouterr().out


def test_cli_check_policy_rejects_loosening_fallback():
    d = json.loads((ROOT / "examples" / "policy.json").read_text())
    d["rules"][1]["if_unknown"] = "read"  # read_internal -> read on unknown would loosen
    d["prohibited_pairs"].append(["read_sensitive", "teleport"])
    problems = cli.validate_policy(d)
    assert any("loosen" in p for p in problems) and any("teleport" in p for p in problems)


def test_cli_keygen_and_build_server(tmp_path):
    key = tmp_path / "k.json"
    assert cli.main(["keygen", "--kid", "ss-1", "--out", str(key)]) == 0
    assert cli.main(["keygen", "--kid", "ss-1", "--out", str(key)]) == 1  # no silent overwrite
    cfg = json.loads((ROOT / "examples" / "server.json").read_text())
    pol = json.loads((ROOT / "examples" / "policy.json").read_text())
    ss = cli.build_server(cfg, pol, str(key), str(tmp_path / "state.json"))
    assert ss.key is not None and ss.key.kid == "ss-1"
    assert ss.metadata()["jwks_uri"] == "https://ss.example/.well-known/jwks.json"
    assert ss.resolver.keep == frozenset({"https://ps.example"})  # never evicted


def test_cli_explain(capsys):
    assert cli.main(["explain", str(ROOT / "examples" / "policy.json"), "--resource",
                     "https://mail.example", "--operation", "send_email", "--param",
                     "to=a@evil.example", "--provenance", "resource"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "allow" and "class=send_external provenance=resource" in out["trace"][0]
    assert cli.main(["explain", str(ROOT / "examples" / "policy.json"), "--resource",
                     "https://mail.example", "--scope", "mail.send"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "ask" and "uncertain=True" in out["trace"][0]


def test_every_command_describes_each_of_its_options_in_help(monkeypatch):
    """`aauth-ss <command> --help` says what each option and positional argument is for,
    not only its name: every action of every command carries a help text that is shown."""
    parsers = []

    def capture(self, args=None, namespace=None):
        parsers.append(self)
        raise SystemExit(0)

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", capture)
    with pytest.raises(SystemExit):
        cli.main(["demo"])
    (top,) = parsers
    (sub,) = (a for a in top._actions if isinstance(a, argparse._SubParsersAction))
    assert {"keygen", "check-policy", "explain", "serve", "demo"} <= set(sub.choices)
    undescribed = [f"{name} {'/'.join(a.option_strings) or a.dest}"
                   for name, parser in sub.choices.items() for a in parser._actions
                   if not isinstance(a, argparse._HelpAction)
                   and (not a.help or a.help == argparse.SUPPRESS)]
    assert undescribed == []


def test_access_log_goes_through_logging_without_bodies(live, caplog):
    import logging

    _, _, port = live
    with caplog.at_level(logging.INFO, logger="aauth_supervision_server.access"):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/decision", body=b'{"secret": "do-not-log"}',
                  headers={"Host": "ss.example", "Content-Type": "application/json"})
        c.getresponse().read()
        c.close()
    lines = [r.getMessage() for r in caplog.records if r.name == "aauth_supervision_server.access"]
    assert any('"POST /decision HTTP/1.1"' in m for m in lines), lines
    assert not any("do-not-log" in m for m in lines)


def test_the_access_log_keeps_the_path_but_not_the_query(live, caplog):
    """The connect confirmation page takes the interaction code in its query
    (`{url}?code={code}`, Supervision L244). The access log line names the method, path and
    status, never the query, so the code does not end up in the operator's logs."""
    import logging
    _, _, port = live
    with caplog.at_level(logging.INFO, logger="aauth_supervision_server.access"):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/interaction?code=SECRETCODE1", headers={"host": "ss.example"})
        assert conn.getresponse().status == 410
        conn.close()
    lines = [r.getMessage() for r in caplog.records if r.name == "aauth_supervision_server.access"]
    assert any("GET /interaction" in m and "410" in m for m in lines), lines
    assert not any("SECRETCODE1" in m or "?" in m for m in lines), lines


def _raw(port: int, data: bytes) -> bytes:
    import socket
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(data)
        out = b""
        try:
            while chunk := s.recv(4096):
                out += chunk
        except OSError:
            pass
    return out


def test_the_access_log_escapes_control_characters(live, caplog):
    """A request line may carry ESC and other control bytes (only CR LF end it). Written to
    a terminal they would clear it, retitle it or forge a line, so the access log escapes
    them, as the standard library's own `log_message` does. A backslash the client sent is
    doubled, so its text cannot pass for an escaped control character."""
    import logging
    _, _, port = live
    with caplog.at_level(logging.INFO, logger="aauth_supervision_server.access"):
        _raw(port, b"GET /\x1b[2J\x1b]0;x\x07\x9b/y\\x1b HTTP/1.1\r\nHost: ss.example\r\n"
                   b"Connection: close\r\n\r\n")
    lines = [r.getMessage() for r in caplog.records if r.name == "aauth_supervision_server.access"]
    assert any("GET /\\x1b[2J\\x1b]0;x\\x07\\x9b/y\\\\x1b HTTP/1.1" in m and "404" in m
               for m in lines), lines
    assert not any(ch in m for m in lines for ch in "\x1b\x07\x9b"), lines


@pytest.mark.parametrize("line", [b"GARBAGE", b"GET / HTTP/1.1 extra", b"\x1b[2J"])
def test_a_malformed_request_line_gets_a_400_and_no_traceback(line, capsys):
    """The standard library answers a request line it cannot parse with 400, logging it
    before the path is known; the access log line must not need the path."""
    import sys as _sys
    ss, ps, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        with capsys.disabled():
            buf, old = io.StringIO(), _sys.stderr
            _sys.stderr = buf
            try:
                reply = _raw(httpd.server_address[1], line + b"\r\n\r\n")
            finally:
                _sys.stderr = old
    finally:
        httpd.shutdown()
        httpd.server_close()
    # A line that does not parse reads as HTTP/0.9, which has no status line; the reply has
    # one all the same, and the error format of every other refusal.
    assert reply.startswith(b"HTTP/1.1 400 ") and b'{"error":"invalid_request"' in reply, reply
    assert "Traceback" not in buf.getvalue(), buf.getvalue()
