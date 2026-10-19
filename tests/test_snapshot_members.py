"""A snapshot member left out is its default, not a reason to set the whole state aside.

The loader takes a missing member of a record as the field's default (`_typed`), the
upgrade step included: a mission written without `history` loads with an empty one, and
no one's state is set aside.
"""
from __future__ import annotations

import json
from pathlib import Path

from aauth_supervision_server.store import Store


def test_a_mission_without_history_loads(tmp_path: Path) -> None:
    path = tmp_path / "ss.json"
    path.write_text(json.dumps({
        "version": Store.VERSION,
        "connections": {"https://ps.example|s": {"iss": "https://ps.example", "sub": "s"}},
        "missions": {"https://ps.example|m1": {"s256": "m1", "agent": "aauth:a@agent.example",
                                               "sub": "s", "iss": "https://ps.example",
                                               "blob": {}}}}), encoding="utf-8")
    s = Store(str(path))
    assert s.load_error == ""
    assert s.missions["https://ps.example|m1"].history == []
    assert "https://ps.example|s" in s.connections
