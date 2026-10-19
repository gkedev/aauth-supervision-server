"""`aauth-ss keygen` writes the private key to a new owner-only file.

`os.open(path, O_CREAT, 0o600)` sets the mode only when it creates the file (POSIX
open(2)), and follows a symbolic link at the path. So `--force` over an existing,
world-readable key file would leave the new private key world-readable, and a link at
`--out` would write the key wherever it points. The key is written to a new file
created with O_EXCL beside `--out`, which then replaces whatever was there (a file or a
link), never writing through it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from aauth_supervision_server import cli


def test_keygen_force_writes_a_new_file_never_into_the_old_one(tmp_path: Path,
                                                             monkeypatch: Any) -> None:
    out = tmp_path / "k.json"
    out.write_text("old key", encoding="utf-8")
    before = os.stat(out).st_ino
    opened: list[tuple[str, int, int]] = []
    real = os.open

    def spy(path: Any, flags: int, mode: int = 0o777) -> int:
        opened.append((str(path), flags, mode))
        return real(path, flags, mode)
    monkeypatch.setattr(os, "open", spy)
    assert cli.main(["keygen", "--kid", "ss-2", "--out", str(out), "--force"]) == 0
    (path, flags, mode), = opened
    assert path != str(out) and flags & os.O_EXCL and mode == 0o600
    assert json.loads(out.read_text(encoding="utf-8"))["kid"] == "ss-2"
    assert os.stat(out).st_ino != before                  # a new file, not the old one
    assert sorted(p.name for p in tmp_path.iterdir()) == ["k.json"]


def test_a_key_that_cannot_be_put_in_place_leaves_nothing_behind(tmp_path: Path,
                                                                monkeypatch: Any) -> None:
    out = tmp_path / "k.json"

    def refuse(src: Any, dst: Any) -> None:
        raise PermissionError("held")
    monkeypatch.setattr(os, "replace", refuse)
    with pytest.raises(PermissionError):
        cli.cmd_keygen(cli_args(out))
    assert list(tmp_path.iterdir()) == []


def cli_args(out: Path) -> Any:
    import argparse
    return argparse.Namespace(kid="ss-1", alg="Ed25519", out=str(out), force=False)
