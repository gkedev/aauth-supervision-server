"""The work a decision does under the store lock does not grow with every mission.

A mission's own pass can only make certain a composition the pass over all missions
already found: a pool with fewer acts completes nothing the full pool does not. So the
per-mission passes run only for compositions found and not yet certain, and stop once
all of them are.
"""
from __future__ import annotations

from typing import Any

from aauth_supervision_server.policy import Policy, PolicyConfig, Rule
from aauth_supervision_server.store import HistoryEntry, elsewhere_copy

POLICY = Policy(PolicyConfig(
    severity=["unclassified", "read", "read_sensitive", "write", "send"],
    rules=[Rule(cls=c, resource=f"https://{c}.example") for c in ("read", "read_sensitive",
                                                                  "write", "send")],
    prohibited_pairs=[["read_sensitive", "send"]],
    prohibited_sequences=[["read_sensitive", "write", "send"]]))


def _counted(monkeypatch: Any) -> list[int]:
    calls: list[int] = []
    real = POLICY._compositions_in

    def counting(cls: str, uncertain: bool, history: list[HistoryEntry],
                 now: float, lead: float = 0.0) -> list[tuple[list[str], bool | None]]:
        calls.append(len(history))
        return real(cls, uncertain, history, now, lead)
    monkeypatch.setattr(POLICY, "_compositions_in", counting)
    return calls


def _hist(outside: list[str], missions: list[list[str]]) -> list[HistoryEntry]:
    out = [HistoryEntry(c, f"https://{c}.example", "resource", detail="rule", n=i + 1)
           for i, c in enumerate(outside)]
    for m, classes in enumerate(missions):
        out += [HistoryEntry(c, f"https://{c}.example", "resource", detail="rule",
                             borrowed=True, scope=f"m{m}", n=1000 + m * 10 + j)
                for j, c in enumerate(classes)]
    return out


def test_nothing_found_over_all_missions_needs_no_mission_pass(monkeypatch: Any) -> None:
    calls = _counted(monkeypatch)
    hist = _hist(["read"] * 50, [["write"]] * 40)
    assert POLICY._compositions("send", False, hist, 0.0) == []
    assert len(calls) == 1


def test_a_composition_found_certain_needs_no_mission_pass(monkeypatch: Any) -> None:
    calls = _counted(monkeypatch)
    hist = _hist(["read_sensitive", "write"], [["read"]] * 40)
    assert POLICY._compositions("send", False, hist, 0.0) == [
        (["read_sensitive", "send"], False), (["read_sensitive", "write", "send"], False)]
    assert len(calls) == 1


def test_mission_passes_stop_once_everything_found_is_certain(monkeypatch: Any) -> None:
    calls = _counted(monkeypatch)
    # The read is outside missions; the write is in the first mission of forty: the
    # sequence is uncertain over all missions, and certain with the first one.
    hist = _hist(["read_sensitive"], [["write"]] + [["read"]] * 39)
    assert POLICY._compositions("send", False, hist, 0.0) == [
        (["read_sensitive", "send"], False), (["read_sensitive", "write", "send"], False)]
    assert len(calls) == 2


def test_a_composition_no_mission_makes_certain_stays_uncertain(monkeypatch: Any) -> None:
    calls = _counted(monkeypatch)
    # Inside a mission, another mission's acts are uncertain copies: they never upgrade.
    hist = [elsewhere_copy(h, h.scope) for h in _hist([], [["read_sensitive"]] * 5)]
    assert POLICY._compositions("send", False, hist, 0.0) == [(["read_sensitive", "send"], True)]
    assert len(calls) == 1


def test_a_composition_left_unsettled_over_all_missions_is_settled_by_a_mission_pass(
        monkeypatch: Any) -> None:
    # The search over all missions together runs out of budget (unsettled, asked); the
    # mission's own pass, over fewer acts, settles it as certain, which is what stands.
    import aauth_supervision_server.policy as policy
    real = policy._sequence_completable

    def short_of_budget(seq: Any, cls: str, history: list[HistoryEntry], now: float,
                        certain_only: bool = False, floated: bool = False,
                        lead: float = 0.0) -> Any:
        if any(policy._uncertain(h) for h in history):
            return None
        return real(seq, cls, history, now, certain_only, floated=floated, lead=lead)
    monkeypatch.setattr(policy, "_sequence_completable", short_of_budget)
    hist = _hist(["read_sensitive"], [["write"], ["read"]])
    assert POLICY._compositions("send", False, hist, 0.0) == [
        (["read_sensitive", "send"], False), (["read_sensitive", "write", "send"], False)]
