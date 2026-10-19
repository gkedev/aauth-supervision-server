"""`aauth-ss serve` starting up: the state file is held before it is read, a linked state
file is the file it links to, and what the host refuses is an error message, not a
traceback.

- A second `serve` on a state file the first cannot read must not set it aside: the lock
  is taken before the snapshot is read, so the second exits and the first keeps its file.
- Two snapshots set aside in the same second are both kept.
- A `--state` that is a symbolic link (state kept on a mounted volume) is written and
  locked where it points, never replaced by a regular file.
- A port in use, a port out of range, an address the host cannot bind, a state path that
  is a directory: one line on stderr and a non-zero exit, with the state file released.
- `--host ::1` (IPv6 loopback) binds.
"""
from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any

import pytest

from aauth_supervision_server import cli
from aauth_supervision_server import http_server as hs
from aauth_supervision_server.store import StateInUse, Store

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _args(state: Path, *extra: str) -> list[str]:
    return ["serve", "--config", str(EXAMPLES / "server.json"), "--policy",
            str(EXAMPLES / "policy.json"), "--state", str(state), *extra]


class FakeHttpd:
    server_address = ("127.0.0.1", 8443)

    def serve_forever(self) -> None:
        raise KeyboardInterrupt

    def server_close(self) -> None:
        pass


def test_a_second_serve_leaves_the_first_s_unreadable_file_alone(
        monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    monkeypatch.setattr(hs, "serve", lambda ss, host, port: FakeHttpd())
    state = tmp_path / "state.json"
    state.write_text("{not json", encoding="utf-8")
    holder = Store(str(tmp_path / "other.json"))
    holder.path = state
    holder.claim()                                   # the first SS holds it
    try:
        assert cli.main(_args(state)) == 1
        assert "in use by another process" in capsys.readouterr().err
        assert state.read_text(encoding="utf-8") == "{not json"
        assert not list(tmp_path.glob("state.json.unreadable-*"))
    finally:
        holder.release()


def test_two_snapshots_set_aside_in_one_second_are_both_kept(
        monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.setattr("time.time", lambda: 1_790_600_000.0)
    state = tmp_path / "state.json"
    for text in ("{first", "{second"):
        state.write_text(text, encoding="utf-8")
        assert Store(str(state)).load_error
    kept = sorted(p.read_text(encoding="utf-8")
                  for p in tmp_path.glob("state.json.unreadable-*"))
    assert kept == ["{first", "{second"]


def test_a_linked_state_file_is_written_and_held_where_it_points(tmp_path: Path) -> None:
    volume = tmp_path / "volume"
    volume.mkdir()
    target = volume / "state.json"
    link = tmp_path / "state.json"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("this host does not let the test create a symbolic link")
    s = Store(str(link))
    s.connections["x"] = {"iss": "i", "sub": "s"}
    s.save()
    assert link.is_symlink() and json.loads(target.read_text())["connections"]
    s.claim()
    try:
        with pytest.raises(StateInUse):
            Store(str(target)).claim()           # the same file under its own name
    finally:
        s.release()


@pytest.mark.parametrize("port", ["70000", "-1", "http"])
def test_a_port_out_of_range_is_a_usage_error(capsys: Any, tmp_path: Path, port: str) -> None:
    with pytest.raises(SystemExit) as e:
        cli.main(_args(tmp_path / "s.json", "--port", port))
    assert e.value.code == 2 and "Traceback" not in capsys.readouterr().err


def test_a_port_in_use_is_reported_and_the_state_released(capsys: Any, tmp_path: Path) -> None:
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen()
    state = tmp_path / "s.json"
    try:
        assert cli.main(_args(state, "--port", str(busy.getsockname()[1]))) == 1
    finally:
        busy.close()
    err = capsys.readouterr().err               # after the warning that there is no --key
    lines = err.splitlines()
    assert any(x.startswith("error: cannot listen on 127.0.0.1 port") for x in lines)
    assert "Traceback" not in err
    Store(str(state)).claim()                   # released on the way out


def test_a_state_path_that_is_a_directory_is_reported(capsys: Any, tmp_path: Path) -> None:
    assert cli.main(_args(tmp_path)) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_keygen_into_a_path_it_cannot_create_is_reported(capsys: Any, tmp_path: Path) -> None:
    afile = tmp_path / "file"
    afile.write_text("x", encoding="utf-8")
    assert cli.main(["keygen", "--kid", "k", "--out", str(afile / "key.json")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err


def test_the_ipv6_loopback_binds() -> None:
    from conftest import make_env
    try:
        with socket.socket(socket.AF_INET6) as probe:
            probe.bind(("::1", 0))
    except OSError:
        pytest.skip("this host has no IPv6 loopback")
    httpd = hs.serve(make_env()[0], "::1", 0)
    try:
        assert httpd.address_family == socket.AF_INET6
    finally:
        httpd.server_close()


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_serve_names_the_address_it_listens_on(monkeypatch: Any, capsys: Any, tmp_path: Path,
                                               host: str) -> None:
    # With port 0 the system picks one: the line names the port bound, and an IPv6 host in
    # brackets, as a URL writes it (RFC 3986 Section 3.2.2).
    if ":" in host:
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind((host, 0))
        except OSError:
            pytest.skip("this host has no IPv6 loopback")
    real = hs.serve

    def bound(ss: Any, h: str, port: int) -> Any:
        httpd = real(ss, h, port)
        httpd.serve_forever = FakeHttpd().serve_forever  # type: ignore[method-assign]
        return httpd

    monkeypatch.setattr(hs, "serve", bound)
    monkeypatch.setenv("AAUTH_SS_ADMIN_TOKEN", "operator-secret")
    assert cli.main(_args(tmp_path / "s.json", "--host", host, "--port", "0")) == 0
    m = re.search(r"listening on http://(\S+):(\d+) ", capsys.readouterr().out)
    assert m and m.group(1) == (f"[{host}]" if ":" in host else host) and m.group(2) != "0"
