"""Composition across the mission boundary.

An agent's acts outside any mission and its acts inside a mission compose: reading
inside a mission and sending outside it (or the reverse) is the same chain of what the
agent did. Separate missions compose with each other only as uncertain acts, asked and
never denied (`tests/test_cross_mission.py`), and budgets stay per mission.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import HistoryEntry, Mission, Store

REC, DOCS, CHAT = "https://records.example", "https://docs.example", "https://chat.example"
PAY = "https://pay.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": DOCS, "class": "write"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": PAY, "class": "payment", "amount_param": "amount"}]


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [["read_sensitive", "send_internal"]])
    over.setdefault("prohibited_sequences", [])
    ss, ps, clock = make_env(rules=RULES, **over)
    s256 = connected((ss, ps, clock), resources=(REC, DOCS, CHAT, PAY))
    return ss, ps, clock, s256


def _take(ss: Any, ps: Any, s256: str, resource: str) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource)
    d = r.json()["decision"]
    if d == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
    return str(d)


def test_read_inside_a_mission_then_send_outside_any_mission_is_caught() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, s256, REC) == "allow"
    assert _take(ss, ps, "", CHAT) == "deny"


def test_read_outside_any_mission_then_send_inside_one_is_caught() -> None:
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, "", REC) == "allow"
    assert _take(ss, ps, s256, CHAT) == "deny"


def test_a_sequence_split_across_the_mission_boundary_is_caught() -> None:
    # read_sensitive -> write in the mission, send_internal outside it.
    ss, ps, _, s256 = _env(prohibited_pairs=[],
                           prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    assert _take(ss, ps, s256, REC) == "allow"
    assert _take(ss, ps, s256, DOCS) == "allow"
    assert _take(ss, ps, "", CHAT) == "deny"


def test_order_across_the_boundary_is_the_order_recorded() -> None:
    # write outside, then read inside, then send outside: the write came before the read,
    # but its token is still live, so the sequence is possible and is caught; the same
    # acts as one-off grants in the harmless order are not.
    ss, ps, _, s256 = _env(prohibited_pairs=[],
                           prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    assert _take(ss, ps, "", DOCS) == "allow"
    assert _take(ss, ps, s256, REC) == "allow"
    assert _take(ss, ps, "", CHAT) == "deny"


def test_two_missions_compose_only_as_uncertain() -> None:
    ss, ps, clock, s256 = _env()
    r, other = ps.propose_and_approve(ss, SUB, AGENT, "# Another task", [REC, CHAT],
                                      [{"name": "WebSearch", "description": "Search"}])
    assert r.status == 200 and other and other != s256
    assert _take(ss, ps, s256, REC) == "allow"
    assert _take(ss, ps, other, CHAT) == "ask"


def test_another_providers_agent_outside_any_mission_does_not_compose() -> None:
    # Another agent of the same provider does, as uncertain (tests/test_agent_provider.py).
    ss, ps, _, s256 = _env()
    assert _take(ss, ps, s256, REC) == "allow"
    other = "aauth:other@else.example"
    sdi, r, _ = ps.auth_token_request(ss, SUB, other, "", CHAT)
    assert r.json()["decision"] == "allow"


def test_budgets_stay_per_mission() -> None:
    # Acts outside the mission compose but do not spend the mission's count.
    ss, ps, _, s256 = _env(budgets={"write": {"max_count": 1}})
    assert _take(ss, ps, "", DOCS) == "allow"
    assert _take(ss, ps, s256, DOCS) == "allow"
    assert _take(ss, ps, s256, DOCS) == "deny"


def test_entries_are_numbered_and_the_numbers_survive_a_restart(tmp_path: Any) -> None:
    path = tmp_path / "state.json"
    st = Store(str(path))
    st.missions[Store.k("iss", "m")] = Mission("m", "a", "s", "iss")
    st.add_history(st.history_for("iss", "s", "a", "m"), HistoryEntry("x", "r", "resource"))
    st.add_history(st.history_for("iss", "s", "a", ""), HistoryEntry("y", "r", "resource"))
    st.save()
    again = Store(str(path))
    again.add_history(again.history_for("iss", "s", "a", "m"), HistoryEntry("z", "r", "resource"))
    merged = again.composition_history("iss", "s", "a", "m")
    assert [(h.action_class, h.n, h.borrowed) for h in merged] == [
        ("x", 1, False), ("y", 2, True), ("z", 3, False)]
    assert not any(h.borrowed for h in again._all_history())


def test_unnumbered_0_1_x_entries_come_first_in_time_order() -> None:
    st = Store()
    st.missions[Store.k("iss", "m")] = Mission("m", "a", "s", "iss", history=[
        HistoryEntry("late", "r", "resource", at=20)])
    st.agent_history[Store.k("iss", "s", "a")] = [HistoryEntry("early", "r", "resource", at=10)]
    st.add_history(st.history_for("iss", "s", "a", "m"), HistoryEntry("new", "r", "resource"))
    order = [h.action_class for h in st.composition_history("iss", "s", "a", "m")]
    assert order == ["early", "late", "new"]


def test_no_borrowed_history_returns_the_own_list_itself() -> None:
    st = Store()
    st.missions[Store.k("iss", "m")] = Mission("m", "a", "s", "iss")
    assert st.composition_history("iss", "s", "a", "m") is st.history_for("iss", "s", "a", "m")


def test_an_act_outside_missions_joins_two_missions_only_as_uncertain() -> None:
    # Read in mission A, write in mission B, send outside any mission. The send composes
    # with A, and with B, each certain where the evidence is; through both it composes
    # only as uncertain, as when the send is inside a third mission: asked, never denied.
    ss, ps, _, a = _env(prohibited_pairs=[],
                        prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    r, b = ps.propose_and_approve(ss, SUB, AGENT, "# Another task", [REC, DOCS, CHAT],
                                  [{"name": "WebSearch", "description": "Search"}])
    assert b and b != a
    assert _take(ss, ps, a, REC) == "allow"
    assert _take(ss, ps, b, DOCS) == "allow"
    assert _take(ss, ps, "", CHAT) == "ask"


def test_an_act_outside_missions_still_completes_with_one_mission() -> None:
    ss, ps, _, a = _env(prohibited_pairs=[],
                        prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    assert _take(ss, ps, a, REC) == "allow"
    assert _take(ss, ps, a, DOCS) == "allow"
    assert _take(ss, ps, "", CHAT) == "deny"
