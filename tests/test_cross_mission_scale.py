"""Composition across missions stays exact and cheap however the history is split.

* The cost of a decision does not grow with the number of missions a history is split
  across: 4000 entries over 400 missions cost about what 4000 entries in one mission do.
  The decision runs under the store lock, so every other request waits on it.
* The answer is the one the straightforward computation gives: each mission composed with
  the act's own history (certain where the evidence is), plus all missions together, every
  act of a mission uncertain. A reference implementation of that computation is kept here
  and compared with the policy on seeded random histories.
"""
from __future__ import annotations

import dataclasses
import random
import statistics
import time
from typing import Any

import pytest
from conftest import AGENT, SUB

from aauth_supervision_server.policy import (
    Act,
    Policy,
    PolicyConfig,
    Rule,
    _firmness,
    _sequence_completable,
)
from aauth_supervision_server.store import (
    UNBOUNDED_EXP,
    HistoryEntry,
    Mission,
    Store,
    elsewhere_copy,
)

ISS = "https://ps.example"
NOW = 1_790_600_000.0


def _unc(h: HistoryEntry) -> bool:
    return h.detail.startswith("uncertain")


def _reference_in(p: Policy, cls: str, uncertain: bool, history: list[HistoryEntry],
                  now: float) -> list[tuple[list[str], bool | None]]:
    out: list[tuple[list[str], bool | None]] = []
    for a, b in p.cfg.prohibited_pairs:
        for other, me in ((a, b), (b, a)):
            if cls == me:
                hits = [h for h in history if h.action_class == other]
                if hits:
                    out.append(([other, me], uncertain or all(_unc(h) for h in hits)))
    for seq in p.cfg.prohibited_sequences:
        if cls not in seq:
            continue
        for certain_only in (True, False):
            pool = [h for h in history if not (certain_only and _unc(h))]
            found = _sequence_completable(seq, cls, pool, now, certain_only)
            if found is False and certain_only and not uncertain and _sequence_completable(
                    seq, cls, pool, now, True, floated=True) is not False:
                found = None  # certain acts the stamps leave open: asked, never covered
            if found is None:
                out.append((list(seq), None))
                break
            if found:
                out.append((list(seq), uncertain or not certain_only))
                break
    return out


def _reference(p: Policy, cls: str, uncertain: bool, history: list[HistoryEntry],
               now: float) -> list[tuple[list[str], bool | None]]:
    """Each mission with the act's own history, then all missions together, every act of
    a mission uncertain; the firmest answer for each composition."""
    scopes = sorted({h.scope for h in history if h.scope})
    if not scopes:
        return _reference_in(p, cls, uncertain, history, now)
    found: dict[tuple[str, ...], bool | None] = {}
    pools = [[h for h in history if h.scope in ("", sc)] for sc in scopes]
    pools.append([elsewhere_copy(h, h.scope) if h.scope and not h.open else h for h in history])
    for pool in pools:
        for comp, unc in _reference_in(p, cls, uncertain, pool, now):
            found[tuple(comp)] = min(found.get(tuple(comp), True), unc, key=_firmness)
    order = [tuple(x) for pr in p.cfg.prohibited_pairs for x in (pr, pr[::-1])] + [
        tuple(q) for q in p.cfg.prohibited_sequences]
    return [(list(k), v) for k, v in sorted(found.items(), key=lambda kv: order.index(kv[0]))]


POLICY = Policy(PolicyConfig(severity=["unclassified", "A", "B", "C", "D"],
                             prohibited_pairs=[("A", "D")],
                             prohibited_sequences=[("A", "B", "C"), ("B", "B", "D"),
                                                   ("C", "A", "D", "B")]))


def _entry(rng: random.Random, inside: bool) -> HistoryEntry:
    scope = rng.choice(["", "", "m1", "m2", "m3"])
    tail = rng.choice(["rule x", "audit record", "replayed"])
    detail = ("uncertain: " if rng.random() < 0.3 else "") + tail
    exp = rng.choice([None, UNBOUNDED_EXP, int(NOW) - rng.randint(1, 500),
                      int(NOW) + rng.randint(1, 500)])
    h = HistoryEntry(rng.choice("ABCD"), "https://r.example", "configured",
                     at=int(NOW) - rng.randint(0, 900), detail=detail, token_exp=exp,
                     borrowed=bool(scope), scope=scope)
    if scope and inside:  # inside a mission, another mission's acts arrive uncertain
        h = elsewhere_copy(dataclasses.replace(h, scope=""), scope)
    elif not scope and rng.random() < 0.15:  # an open act
        h = dataclasses.replace(h, open=rng.choice(["own", "other"]), borrowed=True,
                                detail="uncertain: open")
    return h


@pytest.mark.parametrize("inside", [True, False])
def test_the_policy_gives_the_reference_answer(inside: bool) -> None:
    rng = random.Random(20261015 + inside)
    for _ in range(2500):
        hist = [_entry(rng, inside) for _ in range(rng.randint(0, 9))]
        cls, unc = rng.choice("ABCD"), rng.random() < 0.2
        got = POLICY._compositions(cls, unc, hist, NOW)
        assert got == _reference(POLICY, cls, unc, hist, NOW), (cls, unc, hist)


# ------------------------------------------------------------------ cost

MIX = [("A", "https://a.example"), ("B", "https://b.example"), ("C", "https://c.example"),
       ("W", "https://w.example")]
SCALE = Policy(PolicyConfig(severity=["unclassified", "A", "B", "C", "D", "W"],
                            rules=[Rule(resource=r, cls=c) for c, r in MIX + [
                                ("D", "https://d.example")]],
                            prohibited_pairs=[("A", "D")],
                            prohibited_sequences=[("A", "B", "C"), ("B", "W", "D")],
                            allow_unlisted_resources=True))


def _store(missions: int, total: int) -> tuple[Store, str]:
    rng = random.Random(missions)
    st = Store()
    last = ""
    for i in range(missions):
        last = f"m{i:04d}"
        m = Mission(last, AGENT, SUB, ISS, {})
        st.missions[Store.k(ISS, last)] = m
        for j in range(total // missions):
            cls, res = rng.choice(MIX)
            at = int(NOW) - (missions - i) * 86400 + j * 60
            st.add_history(m.history, HistoryEntry(cls, res, "configured", at=at,
                                                   detail=f"rule {cls}",
                                                   token_exp=at + 3600), AGENT)
    return st, last


def _cost(st: Store, mission: str, resource: str) -> float:
    act = Act("auth_token", ISS, SUB, AGENT, mission, resource=resource)
    m = st.missions.get(Store.k(ISS, mission)) if mission else None
    times = []
    for _ in range(5):
        t = time.perf_counter()
        SCALE.decide(act, m, st.composition_history(ISS, SUB, AGENT, mission, now=NOW),
                     [], NOW)
        times.append(time.perf_counter() - t)
    return statistics.median(times)


@pytest.mark.parametrize("where", ["inside", "outside"])
def test_the_cost_does_not_grow_with_the_number_of_missions(where: str) -> None:
    one, one_last = _store(1, 4000)
    many, many_last = _store(400, 4000)
    for res in ("https://d.example", "https://c.example"):
        base = _cost(one, one_last if where == "inside" else "", res)
        split = _cost(many, many_last if where == "inside" else "", res)
        assert split <= 3 * base + 0.05, (res, base, split)


def test_entries_are_copied_with_every_field() -> None:
    # The fast copy the store uses for borrowed entries keeps every field it does not set.
    h = HistoryEntry("A", "https://a.example", "resource", sdi="d", at=5, amount=3,
                     detail="rule A", amount_known=False, unit="USD/2", allocated=7, jti="j",
                     consumed=2, token_exp=9, n=4, agent="ag")
    c = elsewhere_copy(h, "m1")
    assert dataclasses.asdict(c) == dataclasses.asdict(h) | {
        "borrowed": True, "scope": "m1", "open": "mission",
        "detail": "uncertain: in another mission: rule A"}
    assert c is not h and h.scope == "" and h.open == ""


def _split(outside: int, missions: int, mode: str) -> tuple[Any, Any]:
    # An agent's acts outside missions leave read_sensitive, write, send_internal short of
    # certain ("may": an uncertain read before a write; "unsettled": a read reported in
    # the write's second), and each of its missions holds one certain act: of another
    # class, or ("-w") a write that ended long before.
    from conftest import AGENT, SUB, policy_cfg

    from aauth_supervision_server.policy import Act, Policy
    from aauth_supervision_server.store import HistoryEntry, Mission, Store
    iss, t = "https://ps.example", 1_790_000_000
    rec, hr, cal, mail = ("https://records.example", "https://hr.example",
                          "https://calendar.example", "https://mail.example")
    st = Store()
    out = st.history_for(iss, SUB, AGENT, "")

    def add(hist: list[HistoryEntry], h: HistoryEntry) -> None:
        st.add_history(hist, h, AGENT)

    for i in range(missions):
        ms = Mission(f"m{i:05d}", AGENT, SUB, iss, {})
        st.add_mission(Store.k(iss, ms.s256), ms)
        tt = t - 10_000 + i
        add(ms.history, HistoryEntry("write" if mode.endswith("-w") else "read_internal",
                                     cal if mode.endswith("-w") else mail, "configured",
                                     at=tt, iat=tt, token_exp=tt + 30, detail="rule"))
    if mode.startswith("unsettled"):
        add(out, HistoryEntry("write", cal, "configured", at=t, iat=t, token_exp=t + 30,
                              detail="rule write"))
        add(out, HistoryEntry("read_sensitive", rec, "configured", at=t + 200, iat=t,
                              token_exp=t + 3600, detail="rule", after_n=1))
    else:
        add(out, HistoryEntry("read_sensitive", hr, "configured", at=t, iat=t,
                              token_exp=t + 3600, detail="uncertain: data needed"))
        add(out, HistoryEntry("write", cal, "configured", at=t + 1, iat=t + 1,
                              token_exp=t + 31, detail="rule write"))
    for k in range(outside):
        tt = t + 300 + k
        add(out, HistoryEntry("read_internal", mail, "configured", at=tt, iat=tt,
                              token_exp=tt + 30, detail="rule"))
    act = Act("auth_token", iss, SUB, AGENT, "", resource=mail, scope="mail.send",
              operations=["send_email"], parameters={"to": "y@corp.example"},
              parameters_provenance="resource")
    now = float(t + 300 + outside + 7200)
    p = Policy(policy_cfg())
    return p, (act, st.composition_history(iss, SUB, AGENT, "", now=now), now)


@pytest.mark.parametrize("mode", ["may", "may-w", "unsettled", "unsettled-w"])
def test_acts_outside_missions_cost_a_bounded_amount_more_with_many_missions(
        mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # The same acts outside missions, with no missions and with 200 of them: the missions'
    # own passes run only where a mission could add a step, and stop at a budget, so a
    # decision costs a bounded amount more, not missions times acts outside.
    # Cost is counted in entries composed, the unit of that budget, so the bound is the
    # same on any machine and under coverage: about ten times the decision's own work
    # here, against two hundred times with no budget.
    import aauth_supervision_server.policy as policy_mod
    real = policy_mod._sequence_completable
    work = [0]

    def counted(seq: Any, cls: Any, history: Any, *a: Any, **k: Any) -> Any:
        work[0] += len(history)
        return real(seq, cls, history, *a, **k)
    monkeypatch.setattr(policy_mod, "_sequence_completable", counted)

    def cost(missions: int) -> tuple[int, str]:
        p, (act, hist, now) = _split(2000, missions, mode)
        work[0] = 0
        d = p.decide(act, None, hist, [], now)
        return work[0], d.decision

    base, d0 = cost(0)
    many, d1 = cost(200)
    assert d0 == d1 == "ask"
    assert many <= 20 * base, (base, many)


def test_many_one_act_missions_cost_a_bounded_number_of_searches(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # 3,000 missions, each with one certain read after the agent's write outside them
    # ended: none can make the "may" outside missions certain, so the passes run on. Each
    # pass costs its searches whatever its size, and the budget counts that too.
    from conftest import AGENT, SUB, policy_cfg

    import aauth_supervision_server.policy as policy_mod
    from aauth_supervision_server.policy import Act, Policy
    from aauth_supervision_server.store import HistoryEntry, Mission, Store
    iss, t = "https://ps.example", 1_790_000_000
    st = Store()
    out = st.history_for(iss, SUB, AGENT, "")
    st.add_history(out, HistoryEntry("read_sensitive", "https://hr.example", "configured",
                                     at=t, iat=t, token_exp=t + 3600,
                                     detail="uncertain: data needed"), AGENT)
    st.add_history(out, HistoryEntry("write", "https://calendar.example", "configured",
                                     at=t + 1, iat=t + 1, token_exp=t + 31, detail="rule"),
                   AGENT)
    for i in range(3000):
        ms = Mission(f"m{i:05d}", AGENT, SUB, iss, {})
        st.add_mission(Store.k(iss, ms.s256), ms)
        st.add_history(ms.history, HistoryEntry(
            "read_sensitive", "https://records.example", "configured", at=t + 200 + i,
            iat=t + 200 + i, token_exp=t + 230 + i, detail="rule"), AGENT)
    calls = [0]
    real = policy_mod._sequence_completable

    def counted(*a: Any, **k: Any) -> Any:
        calls[0] += 1
        return real(*a, **k)
    monkeypatch.setattr(policy_mod, "_sequence_completable", counted)
    act = Act("auth_token", iss, SUB, AGENT, "", resource="https://mail.example",
              scope="mail.send", operations=["send_email"],
              parameters={"to": "y@corp.example"}, parameters_provenance="resource")
    now = float(t + 10_000)
    d = Policy(policy_cfg()).decide(act, None, st.composition_history(iss, SUB, AGENT, "",
                                                                      now=now), [], now)
    assert d.decision == "ask"
    assert calls[0] < 1000, calls[0]


def test_a_composition_left_by_the_missions_pass_budget_is_told_so() -> None:
    # Past the missions' pass budget, the person is told the supervisor stopped short of
    # settling it, not only that the order is not settled.
    p, (act, hist, now) = _split(2000, 200, "may-w")
    d = p.decide(act, None, hist, [], now)
    assert d.decision == "ask"
    assert "settling it would take more work than the supervisor allows for one decision" in d.summary
