"""The listener bounds a request in time and the connections it serves at once.

`READ_TIMEOUT` bounds each read; `REQUEST_DEADLINE` bounds the whole request, so a client
sending a byte at a time cannot hold a thread for longer. At most `MAX_CONNECTIONS` are
served at once; a connection beyond them waits in the listen queue until one ends.
"""
from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
from conftest import make_env

from aauth_supervision_server import http_server
from aauth_supervision_server.http_server import serve

HEALTH = b"GET /health HTTP/1.1\r\nHost: ss.example\r\nConnection: close\r\n\r\n"


@pytest.fixture
def small(monkeypatch: Any, request: Any) -> Iterator[int]:
    read, deadline = getattr(request, "param", (0.5, 1.5))
    monkeypatch.setattr(http_server, "READ_TIMEOUT", read)
    monkeypatch.setattr(http_server, "REQUEST_DEADLINE", deadline)
    monkeypatch.setattr(http_server, "MAX_CONNECTIONS", 2)
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def _closed_within(s: socket.socket, seconds: float) -> bool:
    s.settimeout(seconds)
    try:
        while s.recv(4096):
            pass
    except TimeoutError:
        return False
    except OSError:
        return True
    return True


def test_a_request_trickled_in_is_cut_off_at_its_deadline(small: int) -> None:
    with socket.create_connection(("127.0.0.1", small), timeout=5) as s:
        start = time.monotonic()
        closed = False
        for byte in HEALTH[:-4]:            # never completes the header block
            try:
                s.sendall(bytes([byte]))
            except OSError:
                closed = True
                break
            time.sleep(0.2)                 # each read well within READ_TIMEOUT
            if time.monotonic() - start > 4:
                break
        assert closed or _closed_within(s, 1.0)
        assert time.monotonic() - start < 4


@pytest.mark.parametrize("small", [(5.0, 10.0)], indirect=True)  # the held ones stay idle
def test_a_connection_beyond_the_cap_waits_for_one_to_end(small: int) -> None:
    held = [socket.create_connection(("127.0.0.1", small), timeout=5) for _ in range(2)]
    try:
        time.sleep(0.2)                     # both are being served (idle, holding slots)
        with socket.create_connection(("127.0.0.1", small), timeout=5) as third:
            third.sendall(HEALTH)
            third.settimeout(0.3)
            with pytest.raises(TimeoutError):
                third.recv(4096)            # no slot yet
            held.pop().close()
            third.settimeout(5)
            assert third.recv(4096).startswith(b"HTTP/1.1 200 ")
    finally:
        for s in held:
            s.close()


def test_a_complete_request_is_served(small: int) -> None:
    with socket.create_connection(("127.0.0.1", small), timeout=5) as s:
        s.sendall(HEALTH)
        assert s.recv(4096).startswith(b"HTTP/1.1 200 ")


@pytest.mark.parametrize("small", [(5.0, 1.0)], indirect=True)
def test_a_read_waiting_past_the_deadline_is_cut_off_at_it(small: int) -> None:
    # One read may wait READ_TIMEOUT (5 s here); the request's deadline (1 s) comes first.
    with socket.create_connection(("127.0.0.1", small), timeout=5) as s:
        start = time.monotonic()
        s.sendall(b"GET /health HTTP/1.1\r\n")         # and then nothing
        assert _closed_within(s, 4.0)
        assert time.monotonic() - start < 3


def test_while_every_slot_is_taken_a_connection_is_closed_after_its_answer(
        monkeypatch: Any) -> None:
    # A kept-alive connection would hold its slot between requests: when none is free,
    # each answer closes its connection, so the next one waiting gets the slot.
    monkeypatch.setattr(http_server, "MAX_CONNECTIONS", 1)
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=5) as s:
            s.sendall(b"GET /health HTTP/1.1\r\nHost: ss.example\r\n\r\n")
            head = s.recv(4096).partition(b"\r\n\r\n")[0]
            assert head.startswith(b"HTTP/1.1 200 ") and b"\r\nConnection: close" in head
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_with_slots_free_a_connection_is_kept_alive(small: int) -> None:
    with socket.create_connection(("127.0.0.1", small), timeout=5) as s:
        s.sendall(b"GET /health HTTP/1.1\r\nHost: ss.example\r\n\r\n")
        head = s.recv(4096).partition(b"\r\n\r\n")[0]
        assert head.startswith(b"HTTP/1.1 200 ") and b"Connection: close" not in head


def test_a_request_has_ten_seconds_whole() -> None:
    assert http_server.REQUEST_DEADLINE == 10.0
