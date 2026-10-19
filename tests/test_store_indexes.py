"""No request walks every person's state under the store lock.

The store keeps indexes beside its tables: missions by person, decisions that may still
be open by person, and pending records by what finds them (an interaction code, an
`sdi`, a person). Each table is only ever added to; an index takes additions as they are
made, catches up with any made directly, and starts again when a snapshot replaces the
table. A decision record that can no longer be open (an allow past its issuance window,
a clarification settled) leaves the index for good.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import (
    EXP_SKEW,
    DecisionRecord,
    HistoryEntry,
    Mission,
    Pending,
    Store,
)

ISS = "https://ps.example"


def test_missions_are_found_by_person() -> None:
    st = Store()
    st.add_mission(Store.k(ISS, "m1"), Mission("m1", AGENT, SUB, ISS))
    st.missions[Store.k(ISS, "m2")] = Mission("m2", AGENT, "other", ISS)  # directly
    st.add_mission(Store.k(ISS, "m3"), Mission("m3", AGENT, SUB, ISS))
    assert [m.s256 for m in st.missions_of(ISS, SUB)] == ["m1", "m3"]
    assert [m.s256 for m in st.missions_of(ISS, "other")] == ["m2"]
    st.missions = {Store.k(ISS, "m4"): Mission("m4", AGENT, SUB, ISS)}  # a snapshot load
    assert [m.s256 for m in st.missions_of(ISS, SUB)] == ["m4"]


def _allow(st: Store, sdi: str, sub: str, at: int) -> None:
    st.record_decision(Store.k(ISS, sdi), DecisionRecord(
        sdi, ISS, sub, AGENT, "auth_token", "allow",
        entry=HistoryEntry("read", "https://r.example", "resource", at=at, detail="rule")))


def test_open_records_are_kept_by_person_and_leave_once_settled() -> None:
    st = Store()
    _allow(st, "d1", SUB, 0)
    _allow(st, "d2", "other", 0)
    assert len(st.open_acts(ISS, SUB, AGENT, "", "", 10.0)) == 1
    assert st.open_records(ISS, SUB) == [Store.k(ISS, "d1")]
    late = 10 + Store.OPEN_ISSUANCE + EXP_SKEW
    assert st.open_acts(ISS, SUB, AGENT, "", "", late) == []
    assert st.open_records(ISS, SUB) == []             # past its window: left for good
    assert st.open_records(ISS, "other") == [Store.k(ISS, "d2")]  # another person's: kept


def test_pending_records_are_found_by_code_sdi_and_person() -> None:
    st = Store()
    st.add_pending(Pending("p1", ISS, "", "connect", {}, code="ABCD-EFGH-JK", sub=SUB))
    st.add_pending(Pending("p2", ISS, "d-1", "clarify", {"sub": SUB}, sub=SUB))
    st.pending["p3"] = Pending("p3", ISS, "d-2", "clarify", {"sub": "other"}, sub="other")
    assert st.pending_by_code("abcdefghjk") is st.pending["p1"]
    assert st.pending_by_code("ABCDEFGHJ0") is None
    assert st.pending_by_sdi(ISS, "d-1") is st.pending["p2"]
    assert st.pending_by_sdi(ISS, "d-2") is st.pending["p3"]
    assert {p.id for p in st.pendings_of(ISS, SUB)} == {"p1", "p2"}


def test_a_settled_clarification_keeps_no_body() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    loc = r.headers["Location"]
    pid = loc.rsplit("/", 1)[1]
    assert ss.store.pending[pid].request  # live: the request is kept to re-decide it
    assert ps.call(ss, "DELETE", loc, None).status == 204
    assert ss.store.pending[pid].request == {}
    assert ps.call(ss, "GET", loc, None).status == 410


def test_a_connect_pending_keeps_only_what_the_page_shows() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    r = ps.connect(ss, SUB)
    assert r.status == 202
    (p,) = (p for p in ss.store.pending.values() if p.kind == "connect")
    assert set(p.request) <= {"tenant", "_ps_name"}


def test_open_clarifications_of_a_person_are_capped(monkeypatch: Any) -> None:
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_OPEN_CLARIFICATIONS", 2)
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    got = []
    for _ in range(3):
        _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                        scope="mail.send")
        got.append(r.json()["decision"])
    assert got == ["clarify", "clarify", "ask"]


def test_a_request_too_large_to_keep_is_not_clarified(monkeypatch: Any) -> None:
    # A clarification keeps its request to decide it again once answered; one past the
    # size kept goes to the person instead.
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_CLARIFY_BODY", 2000)
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    assert r.json()["decision"] == "clarify"
    sdi = ps.nid("d")
    body = {"sdi": sdi, "act": "auth_token", "iat": int(clock()), "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token("https://mail.example", "mail.send",
                                                mission_s256=s256),
            "presented_token": "a.b.c", "description": "x" * 4000}
    assert ps.call(ss, "POST", "/decision", body).json()["decision"] == "ask"


def test_a_timed_out_clarification_found_by_a_later_decision_keeps_no_body() -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = 60
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    pid = r.headers["Location"].rsplit("/", 1)[1]
    clock.t += 61
    ss.store.open_acts(ps.issuer, SUB, AGENT, s256, "", clock())
    assert ss.store.pending[pid].request == {}


def test_a_question_of_an_ended_mission_keeps_no_body_once_it_times_out() -> None:
    # Its mission past `expires_at`, the question leaves the open set unsettled (it can
    # lead to nothing usable); past its deadline, the person's next question settles it.
    from datetime import UTC, datetime
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = 60
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    pid = r.headers["Location"].rsplit("/", 1)[1]
    end = int(clock()) + 10
    ss.store.missions[f"{ps.issuer}|{s256}"].blob["expires_at"] = datetime.fromtimestamp(
        end, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _, other = ps.propose_and_approve(ss, SUB, AGENT, "# more mail", ["https://mail.example"],
                                      [{"name": "WebSearch", "description": "Search"}])
    clock.t = end + EXP_SKEW + 61
    assert ss.store.pending[pid].request
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, other, "https://mail.example",
                                    scope="mail.send")
    assert r.json()["decision"] == "clarify"
    assert ss.store.pending[pid].request == {}

def test_settling_keeps_the_person_a_record_names_only_in_its_request() -> None:
    st = Store()
    p = Pending("p", ISS, "d-1", "clarify", {"sub": SUB, "big": "x" * 100})
    st.add_pending(p)
    st.settle(p)
    assert (p.request, p.sub) == ({}, SUB)
    assert st.pendings_of(ISS, SUB) == [p]


def test_a_table_replaced_by_one_as_large_is_indexed_again() -> None:
    st = Store()
    st.add_mission(Store.k(ISS, "m1"), Mission("m1", AGENT, SUB, ISS))
    assert [m.s256 for m in st.missions_of(ISS, SUB)] == ["m1"]
    st.missions = {Store.k(ISS, "m2"): Mission("m2", AGENT, SUB, ISS),
                   Store.k(ISS, "m3"): Mission("m3", AGENT, "other", ISS)}  # a snapshot load
    assert [m.s256 for m in st.missions_of(ISS, SUB)] == ["m2"]
    assert [m.s256 for m in st.missions_of(ISS, "other")] == ["m3"]


def test_a_key_dropped_from_an_index_stays_dropped() -> None:
    from aauth_supervision_server.store import _Index
    index = _Index(lambda k, v: [v])
    table: dict[str, Any] = {}
    index.put(table, "a", "group")
    index.drop("group", "a")
    assert list(index.get(table, "group")) == []
    index.put(table, "b", "group")
    assert list(index.get(table, "group")) == ["b"]


def test_a_record_replaced_under_its_id_is_found_only_as_it_is_now() -> None:
    st = Store()
    st.add_pending(Pending("p", ISS, "", "connect", {}, code="ABCD-EFGH-JK", sub=SUB))
    st.add_pending(Pending("p", ISS, "d-1", "clarify", {"sub": "other"}, sub="other"))
    assert st.pending_by_code("ABCD-EFGH-JK") is None    # no longer a connect
    assert st.pendings_of(ISS, SUB) == []                # no longer this person's
    assert st.pendings_of(ISS, "other") == [st.pending["p"]]
    assert st.pending_by_sdi(ISS, "d-1") is st.pending["p"]
    st.add_pending(Pending("p", ISS, "d-2", "clarify", {"sub": "other"}, sub="other"))
    assert st.pending_by_sdi(ISS, "d-1") is None         # now the question of another sdi
    assert st.pending_by_sdi(ISS, "d-2") is st.pending["p"]


def _clarified(timeout: int = 0) -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.cfg.clarification_timeout = timeout
    s256 = connected((ss, ps, clock), resources=("https://mail.example",))
    return ss, ps, clock, s256


def _request(ps: Any, clock: Any, s256: str) -> dict[str, Any]:
    return {"sdi": ps.nid("d"), "act": "auth_token", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token("https://mail.example", "mail.send",
                                                mission_s256=s256),
            "presented_token": "a.b.c"}


def _send(ss: Any, ps: Any, clock: Any, s256: str) -> Any:
    return ps.call(ss, "POST", "/decision", _request(ps, clock, s256))


def test_a_retry_after_a_question_timed_out_finds_the_new_question() -> None:
    # The question timed out unseen; the PS's retry of the request opens a new one under
    # the same sdi, and a further retry finds that one, not the one that is over.
    ss, ps, clock, s256 = _clarified(timeout=60)
    body = _request(ps, clock, s256)
    first = ps.call(ss, "POST", "/decision", body)
    assert first.status == 202
    clock.t += 61
    again = ps.call(ss, "POST", "/decision", body)
    assert again.status == 202 and again.headers["Location"] != first.headers["Location"]
    third = ps.call(ss, "POST", "/decision", body)
    assert third.status == 202 and third.headers["Location"] == again.headers["Location"]


def test_questions_that_are_over_do_not_count_against_the_cap(monkeypatch: Any) -> None:
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_OPEN_CLARIFICATIONS", 2)
    ss, ps, clock, s256 = _clarified()
    for _ in range(2):
        r = _send(ss, ps, clock, s256)
        assert r.status == 202
        assert ps.call(ss, "DELETE", r.headers["Location"], None).status == 204  # withdrawn
    assert _send(ss, ps, clock, s256).json()["decision"] == "clarify"


def test_questions_timed_out_do_not_count_against_the_cap(monkeypatch: Any) -> None:
    import aauth_supervision_server.service as service
    monkeypatch.setattr(service, "MAX_OPEN_CLARIFICATIONS", 2)
    ss, ps, clock, s256 = _clarified(timeout=60)
    for _ in range(2):
        assert _send(ss, ps, clock, s256).status == 202
    clock.t += 61
    assert _send(ss, ps, clock, s256).json()["decision"] == "clarify"


def test_open_records_come_in_the_order_they_were_recorded() -> None:
    # The order open acts are composed in decides where a token's window ends, so it must
    # not depend on the process (a set's order follows the string hash seed).
    st = Store()
    for sdi in ("d-c", "d-a", "d-b"):
        _allow(st, sdi, SUB, 0)
    assert st.open_records(ISS, SUB) == [Store.k(ISS, s) for s in ("d-c", "d-a", "d-b")]


def test_a_record_back_in_the_index_keeps_its_place(tmp_path: Any) -> None:
    # A key dropped from the open index and recorded again keeps the place it has in the
    # table, which a restart reads: the order does not change across a restart.
    st = Store(str(tmp_path / "ss.json"))
    _allow(st, "d-1", SUB, 0)
    _allow(st, "d-2", SUB, 0)
    st._open.drop((ISS, SUB), Store.k(ISS, "d-1"))      # its window was over
    st.record_decision(Store.k(ISS, "d-1"), st.decisions[Store.k(ISS, "d-1")])
    st.save()
    again = Store(str(tmp_path / "ss.json"))
    assert st.open_records(ISS, SUB) == again.open_records(ISS, SUB)
