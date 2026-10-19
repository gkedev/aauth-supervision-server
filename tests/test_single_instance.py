"""One SS per port and per state file.

A second SS started while the first still runs (a restart that overlaps the old process,
a second terminal) must fail at once. On Windows SO_REUSEADDR lets a second socket bind
a port another is listening on, so a second SS could bind silently, wait with the state
it had loaded, and take over when the first exits: everything the first recorded in
between would be lost, and its next snapshot would erase it from disk too.

- The listener binds its port for exclusive use.
- `aauth-ss serve` holds its state file (an OS lock on `<state>.lock`, released when the
  process ends however it ends); a second one on the same file exits with an error.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from conftest import make_env

from aauth_supervision_server import cli
from aauth_supervision_server import store as store_mod
from aauth_supervision_server.http_server import serve
from aauth_supervision_server.store import StateInUse, Store

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_a_second_ss_cannot_bind_the_port_the_first_listens_on() -> None:
    first = serve(make_env()[0], "127.0.0.1", 0)
    try:
        with pytest.raises(OSError):
            serve(make_env()[0], "127.0.0.1", first.server_address[1]).server_close()
    finally:
        first.server_close()


def test_the_state_file_is_held_by_one_store_at_a_time(tmp_path: Path) -> None:
    path = str(tmp_path / "ss.json")
    a, b = Store(path), Store(path)
    a.claim()
    with pytest.raises(StateInUse, match="in use by another process"):
        b.claim()
    fd = a._claimed
    a.release()
    with pytest.raises(OSError):
        os.fstat(fd)  # closed: nothing of it is left open
    b.claim()
    b.release()
    b.release()  # releasing what is not held does nothing
    Store().claim()  # no state file: nothing to hold


class FakeHttpd:
    server_address = ("127.0.0.1", 8443)

    def serve_forever(self) -> None:
        raise KeyboardInterrupt

    def server_close(self) -> None:
        pass


def test_a_second_serve_on_the_same_state_file_exits_with_an_error(
        monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    import aauth_supervision_server.http_server as hs
    monkeypatch.setattr(hs, "serve", lambda ss, host, port: FakeHttpd())
    state = tmp_path / "state.json"
    args = ["serve", "--config", str(EXAMPLES / "server.json"), "--policy",
            str(EXAMPLES / "policy.json"), "--state", str(state)]
    holder = Store(str(state))
    holder.claim()
    assert cli.main(args) == 1
    assert "in use by another process" in capsys.readouterr().err
    holder.release()
    assert cli.main(args) == 0
    holder.claim()  # the serve that ran released it on the way out
    holder.release()


class FakeLocks:
    """Stands in for the other platform's lock module: what it is asked, and whether the
    file is held."""

    LOCK_EX, LOCK_NB, LK_NBLCK, LK_UNLCK = 2, 4, 2, 0

    def __init__(self, held: bool = False) -> None:
        self.calls: list[tuple[str, int]] = []
        self.held = held

    def flock(self, fd: int, op: int) -> None:
        self.calls.append(("flock", op))
        if self.held:
            raise BlockingIOError("held")

    def locking(self, fd: int, mode: int, n: int) -> None:
        self.calls.append(("locking", mode))
        if self.held and mode == self.LK_NBLCK:
            raise PermissionError("held")


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_each_platform_takes_its_own_lock(monkeypatch: Any, tmp_path: Path,
                                          platform: str) -> None:
    fake = FakeLocks()
    monkeypatch.setattr(store_mod, "_fcntl", fake if platform == "posix" else None)
    monkeypatch.setattr(store_mod, "_msvcrt", fake if platform == "windows" else None)
    st = Store(str(tmp_path / "ss.json"))
    st.claim()
    st.release()
    assert fake.calls == ([("flock", fake.LOCK_EX | fake.LOCK_NB)] if platform == "posix"
                          else [("locking", fake.LK_NBLCK), ("locking", fake.LK_UNLCK)])
    fake.held = True
    opened: list[int] = []
    real_open = store_mod.os.open

    def recording(*a: Any) -> int:
        opened.append(real_open(*a))
        return opened[-1]
    monkeypatch.setattr(store_mod.os, "open", recording)
    with pytest.raises(StateInUse):
        st.claim()
    with pytest.raises(OSError):
        os.fstat(opened[-1])  # a claim refused leaves nothing open
