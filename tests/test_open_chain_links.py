"""An open act links its agent to its mission, as a recorded one does, but only as uncertain.

A recorded act of a sub-agent in another agent's mission makes that mission part of the
sub-agent's scope, and the sub-agent part of the mission's chain
(`tests/test_chain_member_boundary.py`). An act the SS answered that is not history yet (an allow
not reported issued) is open, and Supervision L211 lets a concurrent request arrive
before it is. Until it is history, the link it makes counts as uncertain: the mission's
acts compose with the sub-agent's acts elsewhere, and the sub-agent's acts outside
missions with the mission's, each asked, never denied.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, make_env

REC, MAIL, CAL = "https://records.example", "https://mail.example", "https://calendar.example"
RELAY = "aauth:relay@tools.example"   # another provider than AGENT's
EXPORT = {"operations": [{"operationId": "export"}], "parameters": {}}
EVIL = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "drop@evil.example"}}


def _env() -> tuple[Any, Any, str]:
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# work", [REC, MAIL, CAL],
                                     [{"name": "WebSearch", "description": "s"}])
    assert s256
    return ss, ps, s256


def _take(ss: Any, ps: Any, s256: str, resource: str, agent: str, *, scope: str = "",
          proposal: Any = None, issue: bool = False) -> tuple[str, str, Any]:
    sdi, r, prop = ps.auth_token_request(ss, SUB, agent, s256, resource, scope=scope,
                                         proposal=proposal)
    d = r.json()["decision"]
    if issue and d == "allow":
        assert ps.issued(ss, SUB, agent, s256, sdi, resource, scope, prop).status == 201
    return sdi, d, prop


def test_a_relays_open_read_in_a_mission_composes_with_its_send_outside() -> None:
    ss, ps, s256 = _env()
    assert _take(ss, ps, s256, REC, RELAY, proposal=EXPORT)[1] == "allow"   # not reported
    assert _take(ss, ps, "", MAIL, RELAY, scope="mail.send", proposal=EVIL)[1] == "ask"


def test_a_relays_open_read_in_a_mission_composes_with_its_send_in_its_own_mission() -> None:
    ss, ps, s256 = _env()
    assert _take(ss, ps, s256, REC, RELAY, proposal=EXPORT)[1] == "allow"
    r, own = ps.propose_and_approve(ss, SUB, RELAY, "# relay work", [MAIL],
                                    [{"name": "WebSearch", "description": "s"}])
    assert own
    assert _take(ss, ps, own, MAIL, RELAY, scope="mail.send", proposal=EVIL)[1] == "ask"


def test_a_relays_read_outside_composes_with_the_mission_it_has_an_open_act_in() -> None:
    ss, ps, s256 = _env()
    assert _take(ss, ps, "", REC, RELAY, proposal=EXPORT, issue=True)[1] == "allow"
    assert _take(ss, ps, s256, CAL, RELAY)[1] in ("allow", "ask")          # open
    assert _take(ss, ps, s256, MAIL, AGENT, scope="mail.send", proposal=EVIL)[1] == "ask"


def test_once_the_link_is_history_the_composition_is_certain() -> None:
    ss, ps, s256 = _env()
    assert _take(ss, ps, s256, REC, RELAY, proposal=EXPORT, issue=True)[1] == "allow"
    assert _take(ss, ps, "", MAIL, RELAY, scope="mail.send", proposal=EVIL)[1] == "deny"


A, B, R = "aauth:a@p.example", "aauth:b@p.example", "aauth:r@q.example"


def _kin_known_only_through_an_open_act(report: bool) -> str:
    # R (another provider) owns a mission; B, an instance of A's provider, sends from it
    # (allowed, reported or not); A then reads records outside missions.
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, m3 = ps.propose_and_approve(ss, SUB, R, "# r's work", [MAIL, REC])
    sdi, d, prop = _take(ss, ps, m3, MAIL, B, scope="mail.send", proposal=EVIL)
    assert d == "allow"
    if report:
        assert ps.issued(ss, SUB, B, m3, sdi, MAIL, "mail.send", prop).status == 201
    return _take(ss, ps, "", REC, A)[1]


def test_an_instance_known_only_through_its_open_act_still_composes() -> None:
    assert _kin_known_only_through_an_open_act(report=True) == "ask"
    assert _kin_known_only_through_an_open_act(report=False) == "ask"


def _owner_outside_through_an_open_link(report: bool) -> str:
    # A reads records outside missions; R takes a calendar token in A's mission (allowed,
    # reported or not), its only link to A; then R sends externally outside missions.
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    sdi, d, _ = _take(ss, ps, "", REC, A)
    assert d == "allow" and ps.issued(ss, SUB, A, "", sdi, REC).status == 201
    _, m1 = ps.propose_and_approve(ss, SUB, A, "# plan", [CAL])
    sdi2, d2, _ = _take(ss, ps, m1, CAL, R)
    assert d2 == "allow"
    if report:
        assert ps.issued(ss, SUB, R, m1, sdi2, CAL).status == 201
    return _take(ss, ps, "", MAIL, R, scope="mail.send", proposal=EVIL)[1]


def test_an_open_link_brings_the_mission_owner_s_acts_outside_missions_as_uncertain() -> None:
    assert _owner_outside_through_an_open_link(report=True) == "deny"
    assert _owner_outside_through_an_open_link(report=False) == "ask"


def _provider_kin_through_an_open_link(report: bool) -> str:
    # R owns a mission; B reads records outside missions; A, of B's provider, takes a
    # token in R's mission; then R sends outside missions. A is linked to R's chain (by
    # history once reported, by its open act before), and A's provider brings B in.
    a, b, r = "aauth:a@p.example", "aauth:b@p.example", "aauth:r@q.example"
    rec, cal, mail = "https://records.example", "https://calendar.example", "https://mail.example"
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, mr = ps.propose_and_approve(ss, SUB, r, "# r's work", [rec, cal, mail])
    sdi, d, _ = ps.auth_token_request(ss, SUB, b, "", rec)
    assert d.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, b, "", sdi, rec).status == 201
    clock.t += 2
    sdi2, d2, _ = ps.auth_token_request(ss, SUB, a, mr, cal)
    assert d2.json()["decision"] == "allow"
    if report:
        assert ps.issued(ss, SUB, a, mr, sdi2, cal).status == 201
    clock.t += 2
    _, d3, _ = ps.auth_token_request(ss, SUB, r, "", mail, scope="mail.send", proposal=EVIL)
    return str(d3.json()["decision"])


def test_an_open_link_brings_in_the_linked_agent_s_provider_too() -> None:
    assert _provider_kin_through_an_open_link(report=True) == "ask"
    assert _provider_kin_through_an_open_link(report=False) == "ask"


def _two_links(report: bool) -> str:
    # W owns N; Z owns P and read records outside missions; W has an open act in P; X
    # takes an act in N (reported, or open); then X sends outside missions. An open act
    # counts wherever the same act recorded would: X's act brings W into its chain either
    # way, and W's act in P is the same open act in both worlds.
    w, x, z = "aauth:w@p.example", "aauth:x@q.example", "aauth:z@r.example"
    rec, cal, mail = "https://records.example", "https://calendar.example", "https://mail.example"
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, n = ps.propose_and_approve(ss, SUB, w, "# w's work", [rec, cal, mail])
    _, p = ps.propose_and_approve(ss, SUB, z, "# z's work", [rec, cal, mail])
    sdi, _, _ = ps.auth_token_request(ss, SUB, z, "", rec)
    assert ps.issued(ss, SUB, z, "", sdi, rec).status == 201
    ps.auth_token_request(ss, SUB, w, p, cal)
    sdi, _, _ = ps.auth_token_request(ss, SUB, x, n, cal)
    if report:
        assert ps.issued(ss, SUB, x, n, sdi, cal).status == 201
    _, d, _ = ps.auth_token_request(ss, SUB, x, "", mail, scope="mail.send", proposal=EVIL)
    return str(d.json()["decision"])


def test_an_open_act_two_links_away_counts_as_the_recorded_one_would() -> None:
    assert _two_links(report=True) == _two_links(report=False)


def test_the_scope_with_open_acts_holds_the_scope_once_they_are_recorded() -> None:
    # Store level: for random worlds, every agent and mission the scope reaches once some
    # open acts are recorded is reached while they are open (as uncertain at least).
    import random

    from aauth_supervision_server.store import DecisionRecord, HistoryEntry, Mission, Store
    agents = ["aauth:a@p.example", "aauth:b@p.example", "aauth:r@q.example",
              "aauth:w@s.example", "aauth:z@t.example"]
    rng = random.Random(7)
    for _ in range(300):
        acts = [(rng.choice(agents), rng.choice(["", "m0", "m1", "m2"]))
                for _ in range(rng.randint(1, 6))]
        owners = {m: rng.choice(agents) for m in ("m0", "m1", "m2")}
        recorded = {i for i in range(len(acts)) if rng.random() < 0.5}

        def world(as_history: set[int], owners: dict[str, str] = owners,
                  acts: list[tuple[str, str]] = acts) -> Store:
            st = Store()
            for m, owner in owners.items():
                st.add_mission(Store.k("ps", m), Mission(m, owner, SUB, "ps", {}))
            for i, (agent, m) in enumerate(acts):
                h = HistoryEntry("read_internal", "https://r.example", "resource",
                                 agent=agent, sdi=f"s{i}", n=i + 1)
                if i in as_history:
                    st.add_history(st.history_for("ps", SUB, agent, m), h, agent)
                else:
                    st.record_decision(Store.k("ps", f"s{i}"), DecisionRecord(
                        f"s{i}", "ps", SUB, agent, "auth_token", "allow", m, h))
            return st

        actor, where = rng.choice(agents), rng.choice(["", "m0", "m1"])
        before = world(set())._scope("ps", SUB, actor, where)
        after = world(recorded)._scope("ps", SUB, actor, where)
        reach_before = before[0] | before[3]
        reach_after = after[0] | after[3]
        assert reach_after <= reach_before, (acts, owners, recorded, actor, where)
        missions_before = {m.s256 for m in before[1] + before[2]}
        assert {m.s256 for m in after[1] + after[2]} <= missions_before


def test_an_agent_an_open_act_links_is_named_as_such() -> None:
    # Y, of another provider, has an open act in X's mission: once recorded Y is in X's
    # chain; open, Y's acts compose as uncertain, and the person is told why.
    x, y = "aauth:x@p.example", "aauth:y@q.example"
    rec, cal, mail = "https://records.example", "https://calendar.example", "https://mail.example"
    ss, ps, clock = make_env(transport="forwarded")
    assert ps.connect(ss, SUB).status == 200
    _, m = ps.propose_and_approve(ss, SUB, x, "# x's work", [rec, cal, mail])
    sdi, _, _ = ps.auth_token_request(ss, SUB, y, "", rec)
    assert ps.issued(ss, SUB, y, "", sdi, rec).status == 201
    ps.auth_token_request(ss, SUB, y, m, cal)                # Y's open act in X's mission
    _, d, _ = ps.auth_token_request(ss, SUB, x, "", mail, scope="mail.send", proposal=EVIL)
    assert d.json()["decision"] == "ask"
    summary = d.json()["summary"]
    assert "same provider" not in summary and "may link to this one" in summary


def test_an_open_act_past_its_window_links_nothing() -> None:
    # A's read in B's mission was allowed and never reported; past its window it is over,
    # and no longer links A to B's mission: the same request twice gets the same answer.
    from aauth_supervision_server.store import EXP_SKEW, Store
    a, b = "aauth:x@else.example", AGENT
    rec, cal = "https://records.example", "https://calendar.example"
    ss, ps, clock = make_env(prohibited_pairs=[["read_sensitive", "write"]],
                             prohibited_sequences=[])
    assert ps.connect(ss, SUB).status == 200
    _, m = ps.propose_and_approve(ss, SUB, b, "# b's work", [rec, cal])
    sdi, _, _ = ps.auth_token_request(ss, SUB, b, "", rec)
    assert ps.issued(ss, SUB, b, "", sdi, rec).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, a, m, rec)          # never reported issued
    assert r.json()["decision"] == "allow"
    clock.t += Store.OPEN_ISSUANCE + EXP_SKEW + 1
    first = ps.auth_token_request(ss, SUB, a, "", cal)[1].json()["decision"]
    second = ps.auth_token_request(ss, SUB, a, "", cal)[1].json()["decision"]
    assert first == second == "allow"
