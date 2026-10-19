"""Edges of the listener's limits, key refresh and issuance reports.

- A read that would start after the request's deadline is refused at once.
- A connection whose thread cannot start gives its slot back.
- A cached key that fails, whose `kid` the refetched JWKS no longer holds, is
  `unknown_key` (Protocol L2286: "before returning `unknown_key` (if the key is then
  absent)").
- A person token reported with no `jti` is still booked at each audience that serves on
  identity, and an auth token reported with no `sdi` at each audience.
"""
from __future__ import annotations

import math
import socket
import socketserver
import threading
import time
from typing import Any

import pytest
from conftest import AGENT, SUB, make_env

from aauth_supervision_server import http_server
from aauth_supervision_server.jwk import SigningKey

REC, MAIL = "https://records.example", "https://mail.example"


def test_a_read_after_the_deadline_is_refused_without_waiting() -> None:
    a, b = socket.socketpair()
    try:
        reader = http_server._DeadlineReader(a)
        reader.deadline = time.monotonic() - 1
        with pytest.raises(TimeoutError):
            reader.readinto(bytearray(16))
        reader.deadline = math.inf
        b.sendall(b"x")
        assert reader.readinto(buf := bytearray(16)) == 1 and buf[:1] == b"x"
    finally:
        a.close()
        b.close()


def test_a_connection_whose_thread_cannot_start_gives_its_slot_back(monkeypatch: Any) -> None:
    monkeypatch.setattr(http_server, "MAX_CONNECTIONS", 1)
    httpd = http_server.serve(make_env()[0], "127.0.0.1", 0)

    def fails(self: Any, request: Any, client_address: Any) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(socketserver.ThreadingMixIn, "process_request", fails)
    try:
        for _ in range(2):  # the second would wait for good if the first kept its slot
            done: list[bool] = []

            def call(done: list[bool] = done) -> None:
                with pytest.raises(RuntimeError):
                    httpd.process_request(None, ("127.0.0.1", 1))
                done.append(True)

            t = threading.Thread(target=call, daemon=True)
            t.start()
            t.join(5)
            assert done == [True]
    finally:
        httpd.server_close()


def test_a_failed_key_whose_kid_is_gone_after_the_refetch_is_unknown_key() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    fetcher = ss.resolver.fetcher
    kid = ps.key.kid
    ps.key = SigningKey.generate("rotated")          # the PS now publishes another kid only
    ps.install(fetcher)
    ps.key = SigningKey.generate(kid)                 # a request under the old kid
    clock.t += 61
    r = ps.connect(ss, SUB)
    assert r.status == 401 and r.json()["error"] == "unknown_key"


def test_a_person_token_reported_without_a_jti_is_booked() -> None:
    ss, ps, clock = make_env(serves_on_identity=[REC])
    assert ps.connect(ss, SUB).status == 200
    r = ps.call(ss, "POST", "/event", {"event": "person_token.issued", "id": "e-1",
                                       "sdi": "d-1", "iat": int(clock()), "sub": SUB,
                                       "agent": AGENT, "aud": [REC, MAIL],
                                       "exp": int(clock()) + 60})
    assert r.status == 201
    assert [h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")] == [REC]


def test_an_auth_token_reported_without_an_sdi_is_booked_at_each_audience() -> None:
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    r = ps.call(ss, "POST", "/event", {"event": "auth_token.issued", "id": "e-1",
                                       "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                       "jti": "j-1", "aud": [REC, MAIL],
                                       "exp": int(clock()) + 60})
    assert r.status == 201
    assert sorted(h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")) == [
        MAIL, REC]
