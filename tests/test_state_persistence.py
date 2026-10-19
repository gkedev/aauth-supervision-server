"""How the snapshot is written, versioned, and reported when it cannot be read.

* The format differs from 0.1.x's (history entries carry `token_exp`, `n` and `agent`,
  records `plain`), so the snapshot says version 2. A version 1 (0.1.x) snapshot is read
  and migrated; a snapshot of a later version is set aside, naming the version.
* A snapshot the SS sets aside at start is said so on the console: replay rebuilds
  missions and outstanding tokens, not everything (connections, reach, permission grants
  outside missions), so the operator has to know.
* Replacing the snapshot is retried while another process holds it open (Windows refuses
  the replace for that moment), and a failure that persists is still reported.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_support_branches import EXAMPLES, FakeHttpd

from aauth_supervision_server import cli
from aauth_supervision_server import store as store_mod
from aauth_supervision_server.store import Store


def test_the_snapshot_is_version_2_and_a_version_1_one_still_loads(tmp_path: Path) -> None:
    snap = tmp_path / "ss.json"
    s = Store(str(snap))
    s.connections["k"] = {"iss": "i", "sub": "s"}
    s.save()
    data = json.loads(snap.read_text())
    assert data["version"] == 2
    data["version"] = 1
    snap.write_text(json.dumps(data))
    again = Store(str(snap))
    assert again.load_error == "" and again.connections == {"k": {"iss": "i", "sub": "s"}}
    data["version"] = 3
    snap.write_text(json.dumps(data))
    assert "snapshot version 3" in Store(str(snap)).load_error


def test_a_snapshot_set_aside_at_start_is_reported(monkeypatch: Any, capsys: Any,
                                                    tmp_path: Path) -> None:
    import aauth_supervision_server.http_server as hs

    monkeypatch.setattr(hs, "serve", lambda ss, host, port: FakeHttpd())
    state = tmp_path / "state.json"
    state.write_text("{not json", encoding="utf-8")
    assert cli.main(["serve", "--config", str(EXAMPLES / "server.json"), "--policy",
                     str(EXAMPLES / "policy.json"), "--state", str(state)]) == 0
    err = capsys.readouterr().err
    assert "warning: the state file could not be read and was set aside" in err
    assert "state.json.unreadable-" in err


def test_a_replace_refused_for_a_moment_is_retried(monkeypatch: Any, tmp_path: Path) -> None:
    calls: list[int] = []
    real = store_mod.os.replace

    def flaky(src: Any, dst: Any) -> None:
        calls.append(1)
        if len(calls) < 3:
            raise PermissionError("held open")
        real(src, dst)

    monkeypatch.setattr(store_mod.os, "replace", flaky)
    monkeypatch.setattr(store_mod.time, "sleep", lambda s: None)
    s = Store(str(tmp_path / "ss.json"))
    s.save()
    assert len(calls) == 3 and json.loads((tmp_path / "ss.json").read_text())["version"] == 2


def test_a_replace_refused_for_good_is_an_error(monkeypatch: Any, tmp_path: Path) -> None:
    def refuse(src: Any, dst: Any) -> None:
        raise PermissionError("held open")

    monkeypatch.setattr(store_mod.os, "replace", refuse)
    monkeypatch.setattr(store_mod.time, "sleep", lambda s: None)
    with pytest.raises(PermissionError):
        Store(str(tmp_path / "ss.json")).save()


def test_a_mission_blob_nested_too_deep_is_refused() -> None:
    import hashlib

    from conftest import AGENT, SUB, make_env

    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    deep: Any = []
    for _ in range(100):
        deep = [deep]
    raw = json.dumps({"agent": AGENT, "description": "x", "deep": deep}).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": "e-1", "sdi": "d-1", "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "s256": s256, "mission": b64u(raw)})
    assert r.status == 400 and "nests deeper" in r.json()["detail"]


def test_how_far_ahead_each_ps_runs_is_kept_across_a_restart(tmp_path: Path) -> None:
    # The most a PS's requests for its connected people showed its clocks ahead
    # (`Store.observe_lead`) places its acts: kept by PS, past a disconnect, and a
    # restarted SS reads them as the running one did. A request for nobody connected keeps
    # nothing, and a stored value that is not a finite number sets the snapshot aside.
    snap = tmp_path / "ss.json"
    s = Store(str(snap))
    iss = "https://ps.example"
    assert not s.observe_lead(iss, "p", 12.5) and s.lead_of(iss) is None
    s.connections[Store.k(iss, "p")] = {"iss": iss, "sub": "p"}
    assert s.observe_lead(iss, "p", 12.5)
    assert not s.observe_lead(iss, "p", 3.0)  # the most seen is kept
    del s.connections[Store.k(iss, "p")]      # a disconnect keeps it
    s.save()
    assert Store(str(snap)).lead_of(iss) == 12.5
    data = json.loads(snap.read_text())
    data["leads"][iss] = "12"
    snap.write_text(json.dumps(data))
    assert "leads" in Store(str(snap)).load_error


def test_a_lead_past_the_float_range_sets_the_snapshot_aside(tmp_path: Path) -> None:
    # A snapshot holding an integer no float can carry as a PS's lead is set aside at load,
    # as a damaged snapshot is, never an error on a later request.
    snap = tmp_path / "ss.json"
    s = Store(str(snap))
    s.save()
    data = json.loads(snap.read_text())
    data["leads"] = {"https://ps.example": 10**309}
    snap.write_text(json.dumps(data))
    again = Store(str(snap))
    assert "leads" in again.load_error and again.leads == {}


def test_a_lead_noted_before_an_unexpected_failure_still_reaches_the_disk(
        tmp_path: Path) -> None:
    # A request notes how far ahead the PS runs before its handler; a handler that fails
    # with no protocol error (a pluggable policy that raises) is answered 500. The lead it
    # noted is a change like any other: the next request writes it, even one that changes
    # nothing itself (an event sent again), so a restart reads what memory had.
    from conftest import AGENT, SUB, connected, make_env
    snap = tmp_path / "ss.json"
    ss, ps, clock = make_env()
    ss.store = Store(str(snap))
    hr = "https://hr.example"
    s256 = connected((ss, ps, clock), resources=(hr,))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, hr)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, hr).status == 201
    _, event, _ = ps.sent[-1]
    ps.clock = lambda: clock.t + 30
    decide = ss.policy.decide

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("a bug in a pluggable policy")
    ss.policy.decide = broken  # type: ignore[method-assign]
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, hr)
    assert r.status == 500
    ss.policy.decide = decide  # type: ignore[method-assign]
    lead = ss.store.lead_of(ps.issuer)
    assert lead is not None and lead >= 29
    assert ps.call(ss, "POST", "/event", event).status in (200, 201)
    assert Store(str(snap)).lead_of(ps.issuer) == lead


def test_a_stamp_past_the_signature_window_does_not_move_the_ps_s_lead() -> None:
    # An `iat` in milliseconds, or an hour ahead, is no clock a PS within the window
    # stamps on: the lead its request shows is its signature's alone, accepted or refused.
    from conftest import AGENT, SUB, connected, make_env
    ss, ps, clock = make_env()
    connected((ss, ps, clock), resources=("https://hr.example",))
    before = ss.store.lead_of(ps.issuer)
    assert before is not None and before < 5
    for iat in (int(clock()) * 1000, int(clock()) + 3600):
        ps.call(ss, "POST", "/event", {
            "event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-unknown", "iat": iat,
            "sub": SUB, "agent": AGENT, "jti": ps.nid("at"), "aud": "https://hr.example",
            "scope": None, "exp": iat + 60, "issuer": ps.issuer})
        assert ss.store.lead_of(ps.issuer) == before


def test_what_a_request_changed_before_an_unexpected_failure_reaches_the_disk(
        tmp_path: Path) -> None:
    # A resource's consumption record is booked before the policy decides; a policy that
    # then raises is answered 500. The record is a change all the same: the next request
    # writes it, even one that changes nothing itself, and a restart still has it.
    from conftest import AGENT, SUB, make_env
    inf = "https://inference.example"
    offer = {"unit": "USD", "decimals": 2}
    snap = tmp_path / "ss.json"
    ss, ps, clock = make_env()
    ss.store = Store(str(snap))
    assert ps.connect(ss, SUB).status == 200
    _, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# infer", [inf], [])
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, inf, budget=dict(offer, amount=1000))
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, inf, jti="J1").status == 201
    _, event, _ = ps.sent[-1]
    decide = ss.policy.decide

    def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("a bug in a pluggable policy")
    ss.policy.decide = broken  # type: ignore[method-assign]
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, inf, budget=dict(offer, amount=100),
                                    consumed={"jti": "J1", "consumed": 2400})
    assert r.status == 500
    ss.policy.decide = decide  # type: ignore[method-assign]
    assert ps.call(ss, "POST", "/event", event).status in (200, 201)
    again = Store(str(snap))
    assert [h.consumed for m in again.missions.values() for h in m.history
            if h.resource == inf] == [2400]
