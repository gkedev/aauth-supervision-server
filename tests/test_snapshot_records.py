"""What a snapshot holds is checked and migrated as a whole, decision records included.

- A 0.1.x decision record still open at the upgrade carries an act whose amount 0.1.x
  booked as 0 when it never saw it; like a 0.1.x history entry, it is read as unseen, so an
  amount budget asks rather than undercounts when the act is issued after the upgrade.
- A snapshot whose `version` is not an integer, whose history holds a member the SS never
  stores (`borrowed`, `open`, `scope` are set only on copies), or that nests past the
  decoder's limit is set aside, as any snapshot the SS cannot read is.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aauth_supervision_server.store import DecisionRecord, HistoryEntry, Mission, Store

ISS = "https://ps.example"


def _snapshot(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    path = tmp_path / "ss.json"
    st = Store(str(path))
    entry = HistoryEntry("payment", "https://pay.example", "configured", at=1, amount=0,
                         detail="uncertain: no amount", amount_known=True)
    st.decisions[Store.k(ISS, "d-1")] = DecisionRecord("d-1", ISS, "s", "a", "auth_token",
                                                       "ask", "", entry)
    m = Mission("m", "a", "s", ISS)
    st.missions[Store.k(ISS, "m")] = m
    st.add_history(m.history, HistoryEntry("read", "https://r.example", "resource", at=1,
                                           detail="rule"), "a")
    st.save()
    return path, json.loads(path.read_text(encoding="utf-8"))


def test_a_v1_record_entry_with_amount_0_is_read_as_unseen(tmp_path: Path) -> None:
    path, data = _snapshot(tmp_path)
    data["version"] = 1
    del data["decisions"][Store.k(ISS, "d-1")]["entry"]["amount_known"]
    path.write_text(json.dumps(data), encoding="utf-8")
    rec = Store(str(path)).decisions[Store.k(ISS, "d-1")]
    assert rec.entry is not None and rec.entry.amount_known is False
    assert rec.entry.token_exp is None  # a template: its token's exp comes at issuance


def test_a_v1_record_entry_with_an_amount_is_left_as_it_is(tmp_path: Path) -> None:
    path, data = _snapshot(tmp_path)
    data["version"] = 1
    entry = data["decisions"][Store.k(ISS, "d-1")]["entry"]
    del entry["amount_known"]
    entry["amount"] = 500
    path.write_text(json.dumps(data), encoding="utf-8")
    rec = Store(str(path)).decisions[Store.k(ISS, "d-1")]
    assert rec.entry is not None and rec.entry.amount_known is True


def test_a_record_entry_that_kept_amount_known_is_left_as_it_is(tmp_path: Path) -> None:
    path, _ = _snapshot(tmp_path)
    rec = Store(str(path)).decisions[Store.k(ISS, "d-1")]
    assert rec.entry is not None and rec.entry.amount_known is True


@pytest.mark.parametrize("damage", ["version true", "borrowed", "open", "scope", "deep",
                                    "record borrowed"])
def test_a_snapshot_the_ss_never_writes_is_set_aside(tmp_path: Path, damage: str) -> None:
    path, data = _snapshot(tmp_path)
    hist = data["missions"][Store.k(ISS, "m")]["history"][0]
    if damage == "version true":
        data["version"] = True
    elif damage == "borrowed":
        hist["borrowed"] = True
    elif damage == "open":
        hist["open"] = "mission"
    elif damage == "scope":
        hist["scope"] = "m-2"
    elif damage == "record borrowed":
        data["decisions"][Store.k(ISS, "d-1")]["entry"]["borrowed"] = True
    text = json.dumps(data)
    if damage == "deep":
        text = text[:-1] + ', "x": ' + "[" * 200_000 + "]" * 200_000 + "}"
    path.write_text(text, encoding="utf-8")
    st = Store(str(path))
    assert st.load_error and st.missions == {}
    assert list(tmp_path.glob("ss.json.unreadable-*"))
