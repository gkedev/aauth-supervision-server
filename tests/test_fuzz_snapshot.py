"""A corrupted state snapshot must never crash the SS.

Everything in the store is rebuilt by PS replay (Supervision, Replay and Recovery),
so a snapshot the SS cannot read is set aside at load and the SS starts empty. These
tests build a realistic session, save it, then corrupt the snapshot every way a
single JSON value can be wrong and assert the SS still starts.
"""

from __future__ import annotations

import json

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Store

# A grab-bag of values of the wrong JSON type for whatever slot they land in.
WRONG = [None, True, False, 0, -1, 1.5, "", "x", [], {}, [1, 2], {"k": "v"},
         "💥", "\u0000", 10 ** 40, [None], {"version": 1}]


def _snapshot(tmp_path):
    """Drive a realistic session and return the saved snapshot path + parsed JSON."""
    snap = tmp_path / "state.json"
    env = make_env()
    ss, ps, _ = env
    ss.store.path = snap
    s256 = connected(env)
    # Two decision requests in the mission (a mail send and an HR read), so connections,
    # missions, decisions and events_seen are all populated.
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                          scope="send", justification="external send")
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example",
                          scope="read", justification="read records")
    ss.store.save()
    return snap, json.loads(snap.read_text(encoding="utf-8"))


def _leaves(node, path=()):
    """Every (path, value) leaf in a nested JSON structure, plus the containers."""
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaves(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaves(v, path + (i,))


def _set(obj, path, value):
    cur = obj
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def test_realistic_snapshot_reloads(tmp_path):
    snap, data = _snapshot(tmp_path)
    assert data["connections"] and data["missions"] and data["decisions"]
    s = Store(str(snap))
    assert s.load_error == ""
    assert len(s.missions) == 1 and len(s.decisions) >= 1


def test_every_single_corruption_is_survived(tmp_path):
    snap, data = _snapshot(tmp_path)
    paths = [p for p, _ in _leaves(data) if p]  # skip the whole-document root
    assert len(paths) > 30  # the realistic session must be rich enough to be a real fuzz
    crashed = []
    for path in paths:
        for bad in WRONG:
            corrupt = json.loads(json.dumps(data))  # deep copy
            try:
                _set(corrupt, path, bad)
            except (KeyError, IndexError, TypeError):
                continue
            snap.write_text(json.dumps(corrupt), encoding="utf-8")
            try:
                s = Store(str(snap))
            except Exception as e:  # noqa: BLE001 - the whole point is that none escape
                crashed.append((path, bad, repr(e)))
                continue
            # Either it loaded, or it set the snapshot aside and started empty.
            if s.load_error:
                assert s.missions == {} and s.decisions == {} and s.connections == {}
            # restore for the next iteration
            snap.write_text(json.dumps(data), encoding="utf-8")
    assert not crashed, f"{len(crashed)} corruptions crashed the SS: {crashed[:5]}"


def test_truncated_and_non_json_snapshots(tmp_path):
    snap, data = _snapshot(tmp_path)
    for raw in ["", "   ", "{", "null", "[]", "42", '{"version": 2}', "\x00\x01",
                json.dumps(data)[:-50]]:
        snap.write_text(raw, encoding="utf-8")
        s = Store(str(snap))
        assert s.load_error or s.missions == {}


def test_unreadable_snapshot_is_moved_aside(tmp_path):
    snap = tmp_path / "state.json"
    snap.write_text('{"version": 1, "missions": {"k": {"nope": 1}}}', encoding="utf-8")
    s = Store(str(snap))
    assert s.load_error and "moved to" in s.load_error
    moved = list(tmp_path.glob("state.json.unreadable-*"))
    assert len(moved) == 1
    # a fresh empty snapshot can be written over the now-clear path
    s.save()
    assert snap.exists()


def test_an_extra_top_level_key_is_ignored(tmp_path):
    snap, data = _snapshot(tmp_path)
    data["surprise"] = {"anything": [1, 2, 3]}
    data["revoked"] = "a member 0.1.x kept"
    snap.write_text(json.dumps(data), encoding="utf-8")
    s = Store(str(snap))
    # unknown top-level keys are simply not read; the known tables still load
    assert s.load_error == "" and len(s.missions) == 1


@pytest.mark.parametrize("key", ["connections", "agents", "missions", "decisions",
                                 "pending", "reach", "events_seen", "agent_history"])
def test_each_table_wrong_container_type(tmp_path, key):
    snap, data = _snapshot(tmp_path)
    data[key] = "not a container"
    snap.write_text(json.dumps(data), encoding="utf-8")
    s = Store(str(snap))
    assert s.load_error and s.missions == {}
