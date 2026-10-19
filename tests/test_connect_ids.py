"""A connect or disconnect is acted on once per `(iss, id)`, and the `id` names that action.

Supervision L238: `action` is `connect` or `disconnect`; L631: an unrecognized `action` is
`invalid_request`. A retried request (the same `id`, the same action) reports the current
state and changes nothing. The same `id` under the other action, or under no recognized
action, is not a retry: it is refused, never answered from the state.
"""
from __future__ import annotations

from conftest import AGENT, SUB, make_env

from aauth_supervision_server.store import Store


def _post(ss, ps, action, cid, iat=1):
    return ps.call(ss, "POST", "/connect", {"action": action, "id": cid, "iat": iat, "sub": SUB})


def test_an_unrecognized_action_under_a_used_id_is_refused() -> None:
    ss, ps, _ = make_env()
    assert _post(ss, ps, "connect", "c-1").status == 200
    r = _post(ss, ps, "pair", "c-1", 2)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_disconnect_under_a_connect_s_id_is_refused_and_changes_nothing() -> None:
    ss, ps, _ = make_env()
    assert _post(ss, ps, "connect", "c-1").status == 200
    r = _post(ss, ps, "disconnect", "c-1", 2)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    assert Store.k(ps.issuer, SUB) in ss.store.connections
    _, after, _ = ps.auth_token_request(ss, SUB, AGENT, "", "https://hr.example")
    assert after.status == 200


def test_a_connect_under_a_disconnect_s_id_is_refused() -> None:
    ss, ps, _ = make_env()
    assert _post(ss, ps, "connect", "c-1").status == 200
    assert _post(ss, ps, "disconnect", "d-1", 2).status == 200
    assert _post(ss, ps, "connect", "d-1", 3).status == 400
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


def test_a_retry_reports_the_current_state() -> None:
    ss, ps, _ = make_env()
    assert _post(ss, ps, "connect", "c-1").json() == {"status": "connected"}
    assert _post(ss, ps, "disconnect", "d-1", 2).json() == {"status": "disconnected"}
    # The connect retried after the disconnect does not undo it.
    assert _post(ss, ps, "connect", "c-1", 3).json() == {"status": "disconnected"}
    assert _post(ss, ps, "disconnect", "d-1", 4).json() == {"status": "disconnected"}
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


def test_a_0_1_x_connect_id_is_still_a_retry() -> None:
    # A 0.1.x snapshot holds the id alone: either action under it reports the state, as
    # 0.1.x did.
    ss, ps, _ = make_env()
    ss.store.events_seen.add(Store.k("connect", ps.issuer, "old-1"))
    for action in ("connect", "disconnect"):
        assert _post(ss, ps, action, "old-1").json() == {"status": "disconnected"}
    assert Store.k(ps.issuer, SUB) not in ss.store.connections
