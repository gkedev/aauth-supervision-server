"""Limits that keep one client from costing everyone else, and the state from being lost.

- Signature fields are bounded before they are parsed: an honest one is a few hundred
  bytes, and parsing walks every byte.
- The rate-limit table keeps the signers active in the last minute, not every one ever.
- The listener queues a burst of connections rather than refusing it.
- A state file named `*.tmp` is not the temporary file the snapshot is written through.
- A failed snapshot write removes its temporary file.
- A state file held open by another process (Windows) is retried for a few seconds.
- A clarification states the time left to answer it, not the full timeout again.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.http_server import serve
from aauth_supervision_server.httpsig import HttpRequest, verify_request
from aauth_supervision_server.store import Mission, Store


def _signed_fields(field: str, size: int) -> dict[str, str]:
    headers = {"signature-input": 'sig=("@method");created=1', "signature": "sig=:AAAA:",
               "signature-key": 'sig=jwks_uri;id="https://ps.example";dwk="x"'}
    pad = ", x=" + "a" * size
    headers[field] = headers[field] + pad[: max(0, size - len(headers[field]))]
    return headers


@pytest.mark.parametrize("field", ["signature-input", "signature", "signature-key"])
def test_an_oversized_signature_field_is_refused_before_parsing(field: str) -> None:
    req = HttpRequest("POST", "ss.example", "/decision", _signed_fields(field, 16 * 1024), b"")
    with pytest.raises(SignatureError) as e:
        verify_request(req, resolver=None, required=[], now=1.0)  # type: ignore[arg-type]
    assert e.value.error == "invalid_signature" and "too long" in e.value.detail


@pytest.mark.parametrize("field", ["signature-input", "signature", "signature-key"])
def test_a_signature_field_of_honest_size_is_parsed(field: str) -> None:
    # A field the size of several honest signatures (6 KiB): past the length check,
    # refused (or not) for what it says.
    req = HttpRequest("POST", "ss.example", "/decision", _signed_fields(field, 6 * 1024), b"")
    with pytest.raises(SignatureError) as e:
        verify_request(req, resolver=None, required=[], now=1.0)  # type: ignore[arg-type]
    assert "too long" not in e.value.detail


def test_the_rate_table_keeps_only_signers_active_in_the_last_minute(monkeypatch: Any) -> None:
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_RATE_ROWS", 10)
    ss, ps, clock = make_env()
    ss.cfg.rate_limit_per_minute = 100
    for i in range(30):
        ss._throttle(f"https://ps{i}.example")
    assert len(ss._rate) == 30  # all active within the minute: each keeps its count
    clock.t += 61
    ss._throttle("https://late.example")
    assert list(ss._rate) == ["https://late.example"]


def test_the_listener_queues_a_burst() -> None:
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    try:
        assert httpd.request_queue_size >= 128
    finally:
        httpd.server_close()


def test_a_state_file_named_like_the_temporary_file_survives_a_failed_write(
        tmp_path: Path, monkeypatch: Any) -> None:
    path = tmp_path / "ss.tmp"
    st = Store(str(path))
    st.missions[Store.k("iss", "m")] = Mission("m", AGENT, SUB, "iss")
    st.save()

    real_fdopen = os.fdopen

    class Full:
        """A file the disk fills up halfway through."""

        def __init__(self, f: Any) -> None:
            self.f = f

        def __enter__(self) -> Any:
            return self

        def __exit__(self, *exc: Any) -> None:
            self.f.close()

        def write(self, text: str) -> None:
            self.f.write(text[: len(text) // 2])
            self.f.flush()
            raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fdopen", lambda *a, **kw: Full(real_fdopen(*a, **kw)))
    with pytest.raises(OSError):
        st.save()
    monkeypatch.undo()
    assert Store(str(path)).missions  # the last snapshot written whole is still there


@pytest.mark.parametrize("step", ["fsync", "replace"])
def test_a_failed_write_leaves_no_temporary_file(tmp_path: Path, monkeypatch: Any,
                                                 step: str) -> None:
    # The disk fails the snapshot as it is flushed, or as it replaces the old one: the
    # temporary file the snapshot is written through is removed, and the directory holds
    # the state file alone, as before the write.
    path = tmp_path / "ss.json"
    st = Store(str(path))
    st.save()

    def fail(*a: Any) -> None:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, step, fail)
    with pytest.raises(OSError):
        st.save()
    monkeypatch.undo()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ss.json"]


def test_a_held_state_file_is_retried_for_a_few_seconds(tmp_path: Path,
                                                       monkeypatch: Any) -> None:
    st = Store(str(tmp_path / "ss.json"))
    st.save()
    real, fails = os.replace, [0]
    sleeps: list[float] = []

    def held(a: Any, b: Any) -> None:
        if fails[0] < 8:
            fails[0] += 1
            raise PermissionError("held open")
        real(a, b)
    monkeypatch.setattr(os, "replace", held)
    monkeypatch.setattr("time.sleep", sleeps.append)
    st.save()
    assert fails[0] == 8 and sum(sleeps) >= 1.5


def test_a_clarification_states_the_time_left() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = 120
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    assert r.json()["timeout"] == 120
    clock.t += 100.5
    poll = ps.call(ss, "GET", r.headers["Location"], None)
    assert poll.status == 202 and poll.json()["timeout"] == int(120 - 100.5)  # never later


def test_an_answer_within_the_restated_time_is_accepted() -> None:
    # The recipient MUST respond before the stated deadline (Protocol L1071): the time a
    # poll restates is never later than the one enforced, so answering within it is in time.
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = 120
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    loc = r.headers["Location"]
    clock.t += 0.3
    left = ps.call(ss, "GET", loc, None).json()["timeout"]
    clock.t += left - 0.1
    answer = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                       "clarification_response": "for the team update"})
    assert answer.status != 408, answer.body
