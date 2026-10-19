"""The sequence search on long honest histories: fast, and never out of budget by accident.

A search that runs out of its step budget is read as a possible violation and put to the
person, so an honest history that exhausts it is a false `ask`. Two shapes can: one-off
grants (each ends at its own position, so none is interchangeable with another) and
expired tokens of a repeated step when the step after the act being decided has no live
token. Finding the end of every expired token's window must not scan every later entry,
or a long history would cost its length squared on every decision, under the store lock.
"""
from __future__ import annotations

import random
import time
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aauth_supervision_server import policy as policy_mod
from aauth_supervision_server.policy import Act, Policy, PolicyConfig, Rule
from aauth_supervision_server.store import Alias, HistoryEntry

NOW = 10_000_000.0
ISS, SUB, AGENT = "https://ps.example", "s", "aauth:a@agent.example"


def res(c: str) -> str:
    return f"https://{c.lower()}.example"


def pol(seq: tuple[str, ...]) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "A", "B", "R", "S", "V", "W"],
                               rules=[Rule(resource=res(c), cls=c) for c in "ABRSVW"],
                               prohibited_sequences=[seq]))


def decide(seq: tuple[str, ...], cls: str, hist: list[HistoryEntry]) -> Any:
    act = Act("auth_token", ISS, SUB, AGENT, "", resource=res(cls),
              parameters_provenance="resource")
    return pol(seq).decide(act, None, hist, [], now=NOW)


def grant(c: str, at: int) -> HistoryEntry:
    return HistoryEntry(c, res(c), "resource", at=at, detail="rule")


def token(c: str, at: int, exp: int) -> HistoryEntry:
    return HistoryEntry(c, res(c), "resource", at=at, detail="rule", token_exp=exp)


def test_a_long_history_of_expired_tokens_is_decided_quickly() -> None:
    hist = [token("A", at=i, exp=i + 1) for i in range(4000)]
    t0 = time.perf_counter()
    d = decide(("A", "B"), "B", hist)
    assert time.perf_counter() - t0 < 2.0
    assert d.decision == "deny"


@pytest.mark.parametrize(("seq", "m"), [(("W", "W", "A", "B"), 200),
                                        (("W", "W", "W", "A", "B"), 60)])
def test_one_off_grants_of_a_repeated_step_do_not_exhaust_the_search(
        seq: tuple[str, ...], m: int) -> None:
    # B happened once, before everything else: it can never follow A.
    hist = [grant("B", 0)] + [grant("W", i + 1) for i in range(m)]
    assert policy_mod._sequence_completable(seq, "A", hist, NOW) is False
    assert decide(seq, "A", hist).decision == "allow"


def test_expired_tokens_of_a_repeated_step_with_no_live_last_step_do_not_exhaust() -> None:
    # Forty reads whose tokens have expired, one send long ago: another read cannot be
    # followed by a send, so it is not put to the person.
    seq = ("R",) * 5 + ("S",)
    hist = [token("S", at=0, exp=1)] + [token("R", at=10 * i, exp=10 * i + 15)
                                        for i in range(1, 41)]
    assert policy_mod._sequence_completable(seq, "R", hist, NOW) is False
    assert decide(seq, "R", hist).decision == "allow"


def test_an_order_that_cannot_hold_is_settled_without_running_out() -> None:
    # Every V ended before any W started, so no W, W, V order exists.
    seq = ("W", "W", "V", "A")
    hist = [grant("V", i) for i in range(5)] + [token("W", at=10 * i, exp=10 * i + 15)
                                                for i in range(1, 201)]
    assert policy_mod._sequence_completable(seq, "A", hist, NOW) is False


# ------------------------------------------------------------------ the pruned search agrees
# A plain search (only the equal-end rule), with no step
# budget: wherever it finishes, the pruned search must give the same answer.

def _reference(seq: tuple[str, ...], cls: str, history: list[HistoryEntry], now: float) -> bool:
    import math
    n = len(history)
    windows: list[tuple[str, float, float]] = []
    for i, h in enumerate(history):
        if h.token_exp is None:
            windows.append((h.action_class, float(i), float(i)))
        elif h.token_exp + policy_mod.EXP_SKEW > now:
            windows.append((h.action_class, float(i), math.inf))
        else:
            last = i
            for j in range(i + 1, n):
                if history[j].at <= h.token_exp + policy_mod.EXP_SKEW:
                    last = j
            windows.append((h.action_class, float(i), last + 0.5 if last > i else float(i)))
    windows.append((cls, float(n), float(n)))
    used = [False] * len(windows)

    def place(step: int, t: float) -> bool:
        if step == len(seq):
            return used[n]
        if not used[n] and cls not in seq[step:]:
            return False
        tried: set[float] = set()
        for k, (c, lo, hi) in enumerate(windows):
            if used[k] or c != seq[step] or hi in tried:
                continue
            tried.add(hi)
            at = max(t, lo)
            if at > hi:
                continue
            used[k] = True
            r = place(step + 1, at)
            used[k] = False
            if r:
                return True
        return False

    return place(0, -math.inf)


@st.composite
def _case(draw: Any) -> tuple[tuple[str, ...], str, list[HistoryEntry]]:
    classes = ["A", "B", "W"]
    seq = tuple(draw(st.lists(st.sampled_from(classes), min_size=2, max_size=5)))
    cls = draw(st.sampled_from(classes))
    hist = []
    at = 0
    for _ in range(draw(st.integers(0, 9))):
        at += draw(st.integers(0, 3))  # report times repeat and need not be spread out
        c = draw(st.sampled_from(classes))
        kind = draw(st.sampled_from(["grant", "live", "expired", "expired"]))
        if kind == "grant":
            hist.append(grant(c, at))
        elif kind == "live":
            hist.append(token(c, at, int(NOW) + 60))
        else:
            hist.append(token(c, at, at + draw(st.integers(0, 12))))
    return seq, cls, hist


@settings(max_examples=3000, deadline=None, derandomize=True)
@given(_case())
def test_the_pruned_search_agrees_with_the_plain_one(case: Any) -> None:
    seq, cls, hist = case
    assert policy_mod._sequence_completable(seq, cls, hist, NOW) == _reference(
        seq, cls, hist, NOW), case


def test_unsorted_report_times_are_read_as_the_plain_search_reads_them() -> None:
    # A replayed or audited entry carries the PS's `iat`, so report times need not rise.
    rng = random.Random(7)
    for _ in range(300):
        hist = [token(rng.choice("ABW"), at=rng.randint(0, 30), exp=rng.randint(0, 40))
                for _ in range(rng.randint(1, 8))]
        seq = tuple(rng.choice("ABW") for _ in range(rng.randint(2, 4)))
        cls = rng.choice("ABW")
        assert policy_mod._sequence_completable(seq, cls, hist, NOW) == _reference(
            seq, cls, hist, NOW), (seq, cls, hist)


# ------------------------------------------------------------------ every window shape
# Audit records and replayed tokens can start at the head of the history, so windows are
# not in start order by position. Against an exhaustive enumeration of assignments
# over the same windows (no pruning at all), the search must agree.

def _windows(cls: str, history: list[HistoryEntry], now: float) -> list[tuple[str, float, float]]:
    """The uncertain pass's windows, as `_sequence_completable` documents them, computed
    the plain way: a replayed token floats unless its stamp is after every entry before it
    and before every pinned entry after it; a floating token starts before every entry and,
    expired, ends just after the last pinned entry (not an audit record) stamped while it
    was live; an audited action may have taken place before every entry too."""
    import math
    n = len(history)
    audit = [h.detail.endswith("audit record") for h in history]
    floating = [not a and (h.unplaced or h.detail.endswith("replayed"))
                for a, h in zip(audit, history, strict=True)]
    for i, h in enumerate(history):
        if floating[i] and h.detail.endswith("replayed") and all(
                history[j].at < h.at for j in range(i) if not floating[j]) and all(
                history[j].at > h.at for j in range(i + 1, n)
                if not (h2 := history[j]).unplaced and not h2.detail.endswith("replayed")
                or audit[j]):
            floating[i] = False
    out = []
    for i, h in enumerate(history):
        if audit[i]:
            out.append((h.action_class, -0.5, float(i)))
            continue
        end = None if h.token_exp is None else h.token_exp + policy_mod.EXP_SKEW
        if not floating[i]:
            if end is None:
                hi = float(i)
            elif end > now:
                hi = math.inf
            else:
                last = max([j for j in range(i + 1, n) if history[j].at <= end], default=i)
                hi = last + 0.5 if last > i else float(i)
            out.append((h.action_class, float(i), hi))
            continue
        if end is None:
            hi = float(i)
        elif end > now:
            hi = math.inf
        else:
            ends = [j for j in range(n) if not floating[j] and not audit[j]
                    and history[j].at <= end]
            hi = max(max(ends) + 0.5 if ends else -0.5, -0.5)
        out.append((h.action_class, -0.5, hi))
    out.append((cls, float(n), float(n)))
    return out


def _exhaustive(seq: tuple[str, ...], cls: str, history: list[HistoryEntry], now: float) -> bool:
    from itertools import permutations
    w = _windows(cls, history, now)
    mine = len(w) - 1
    for pick in permutations(range(len(w)), len(seq)):
        if mine not in pick or any(w[k][0] != c for k, c in zip(pick, seq, strict=True)):
            continue
        t = float("-inf")
        for k in pick:
            t = max(t, w[k][1])
            if t > w[k][2]:
                break
        else:
            return True
    return False


@st.composite
def _mixed(draw: Any) -> tuple[tuple[str, ...], str, list[HistoryEntry]]:
    classes = ["A", "B", "W"]
    seq = tuple(draw(st.lists(st.sampled_from(classes), min_size=2, max_size=4)))
    cls = draw(st.sampled_from(classes))
    hist = []
    at = 0
    for _ in range(draw(st.integers(0, 6))):
        at += draw(st.integers(0, 3))
        c = draw(st.sampled_from(classes))
        kind = draw(st.sampled_from(["grant", "live", "expired", "audit", "replayed",
                                     "replayed-expired"]))
        if kind == "grant":
            hist.append(grant(c, at))
        elif kind == "live":
            hist.append(token(c, at, int(NOW) + 60))
        elif kind == "expired":
            hist.append(token(c, at, at + draw(st.integers(0, 12))))
        elif kind == "audit":
            hist.append(HistoryEntry(c, res(c), "agent", at=at, detail="audit record"))
        else:
            exp = int(NOW) + 60 if kind == "replayed" else at + draw(st.integers(0, 12))
            hist.append(HistoryEntry(c, res(c), "resource", at=at, detail="replayed",
                                     token_exp=exp))
    return seq, cls, hist


@settings(max_examples=3000, deadline=None, derandomize=True)
@given(_mixed())
def test_the_search_agrees_with_exhaustive_enumeration_on_every_window_shape(case: Any) -> None:
    seq, cls, hist = case
    assert policy_mod._sequence_completable(seq, cls, hist, NOW) == _exhaustive(
        seq, cls, hist, NOW), case


def test_among_equal_ends_the_earliest_start_is_tried_whatever_its_position() -> None:
    # A replayed live token, stamped before the acts it arrives after (so it floats),
    # starts at the head of history although it comes after a live token that starts
    # later. Only the earlier start can precede the grant at position 0, so the search
    # must try windows in start order, not in position order.
    hist = [grant("W", 1), token("A", 2, int(NOW) + 60),
            HistoryEntry("A", res("A"), "resource", at=0, detail="replayed",
                         token_exp=int(NOW) + 60)]
    assert policy_mod._sequence_completable(("A", "W", "B"), "B", hist, NOW) is True


def test_one_off_acts_of_a_step_are_not_tried_in_every_combination() -> None:
    # W at 0, V at 1, then 200 more W: two distinct W leave V behind, but each pruning
    # that ignores distinctness (counts, the relaxed earliest moments) lets it through.
    # Trying every pair of W would run the search out of budget and ask the person.
    hist = [grant("W", 0), grant("V", 1)] + [grant("W", i) for i in range(2, 202)]
    assert policy_mod._sequence_completable(("W", "W", "V", "A"), "A", hist, NOW) is False


def test_steps_after_the_decided_act_need_live_tokens_of_their_own() -> None:
    # Two L steps follow the act being decided; only one L token is live (the other L was
    # a one-off grant, long before). Two hundred expired W tokens, each ending at its own
    # moment, would otherwise be tried in every pair before that shows.
    hist = [grant("L", 0), token("L", at=1, exp=int(NOW) + 60)] + [
        token("W", at=10 * i, exp=10 * i + 15) for i in range(1, 201)]
    assert policy_mod._sequence_completable(("W", "W", "A", "L", "L"), "A", hist, NOW) is False


def test_more_steps_of_a_class_than_its_acts_before_a_one_off_step_is_settled() -> None:
    # Five W must precede V, a single moment, and only four W start before it; twelve
    # more W end at moments of their own, so none is interchangeable.
    hist = [token("W", i, 40 + i) for i in range(4)] + [grant("V", 4)]
    hist += [token("W", j, 40 + j) for j in range(5, 17)]
    hist += [token("A", i, i) for i in range(17, 60)]
    assert policy_mod._sequence_completable(("W",) * 5 + ("V", "A"), "A", hist,
                                            NOW) is False


def test_an_order_that_cannot_hold_is_settled_before_any_search_step(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # With no search step to spend, an order the counts and moments rule out is still
    # `False`, not `None`: it is settled before the search, so it is never put to the
    # person as unsettled. The same history with four W, an order that holds, shows that
    # the budget leaves no step: only a search can settle that one.
    monkeypatch.setattr(policy_mod, "_SEQUENCE_SEARCH_BUDGET", 0)
    hist = [token("W", i, 40 + i) for i in range(4)] + [grant("V", 4)]
    hist += [token("W", j, 40 + j) for j in range(5, 17)]
    hist += [token("A", i, i) for i in range(17, 60)]
    assert policy_mod._sequence_completable(("W",) * 5 + ("V", "A"), "A", hist, NOW) is False
    assert policy_mod._sequence_completable(("W",) * 4 + ("V", "A"), "A", hist, NOW) is None
    # Every V ends before any W starts: no order holds even if acts could repeat.
    hist = [grant("V", i) for i in range(5)] + [token("W", at=10 * i, exp=10 * i + 15)
                                                for i in range(1, 201)]
    assert policy_mod._sequence_completable(("W", "W", "V", "A"), "A", hist, NOW) is False


def test_a_search_out_of_budget_is_asked_and_no_answer_covers_it(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # A certain completion the search cannot settle in its budget is not "uncertain
    # evidence": the person is asked, plainly, and an answer given about an uncertain
    # ask of the same composition does not let it through.
    from aauth_supervision_server.store import Reach
    monkeypatch.setattr(policy_mod, "_SEQUENCE_SEARCH_BUDGET", 1)
    seq = ("W", "W", "A")
    hist = [token("W", 0, int(NOW) + 60), token("W", 1, int(NOW) + 60)]
    act = Act("auth_token", ISS, SUB, AGENT, "m", resource=res("A"),
              parameters_provenance="resource")
    p = pol(seq)
    d = p.decide(act, None, hist, [], now=NOW)
    assert d.decision == "ask" and "cannot tell whether" in d.summary
    reach = [Reach("mission", ISS, SUB, AGENT, d.kind, "m", list(seq))]
    assert p.decide(act, None, hist, reach, now=NOW).decision == "ask"


def test_a_search_that_tries_every_candidate_and_fails_is_settled_false() -> None:
    """A fixed history, so the search's exhausted branch is exercised without a random draw.
    a b b a with the act being decided a `b`: the two b's must be the audit record (any
    moment up to 1) and the decided act (4), so the first `a` lands by 1 and the last at
    4 or later, and only the live token a0 can do either: it cannot do both."""
    from aauth_supervision_server.policy import _sequence_completable
    from aauth_supervision_server.store import UNBOUNDED_EXP
    hist = [HistoryEntry("a", "r", "configured", at=0, token_exp=UNBOUNDED_EXP),
            HistoryEntry("b", "r", "configured", at=1, detail="audit record"),
            HistoryEntry("a", "r", "configured", at=2, token_exp=1),
            HistoryEntry("a", "r", "configured", at=3, token_exp=4)]
    assert _sequence_completable(("a", "b", "b", "a"), "b", hist, now=10_000.0) is False
    hist[0].token_exp = None  # a0 now lands at 0 only: still no last a
    assert _sequence_completable(("a", "b", "b", "a"), "b", hist, now=10_000.0) is False
    hist.append(HistoryEntry("a", "r", "configured", at=4, token_exp=UNBOUNDED_EXP))
    assert _sequence_completable(("a", "b", "b", "a"), "b", hist, now=10_000.0) is True


# ------------------------------------------------------------------ acts with two classes
# An act the agent's data raised may take a step as its class or as its `blind` class,
# never both (it is one act), and in the certain pass only as a class it is certain of.

def _aliased_exhaustive(seq: tuple[str, ...], cls: str, history: list[HistoryEntry],
                        now: float, certain_only: bool) -> bool:
    from itertools import permutations
    w = _windows(cls, history, now)
    if certain_only:
        # For certain, an audited action came before every pinned act (one that does not
        # float) recorded before it and stamped in its second or later: which came first
        # in that second is not settled.
        pinned = [not (h.unplaced or h.detail.endswith("replayed"))
                  or h.detail.endswith("audit record") for h in history]
        for i, h in enumerate(history):
            if h.detail.endswith("audit record"):
                before = [j for j in range(i) if pinned[j] and history[j].at >= h.at]
                if before:
                    c, lo, hi = w[i]
                    w[i] = (c, lo, min(hi, min(before) - 0.5))
    kinds = [{c for c, unc in [(h.action_class, h.detail.startswith("uncertain"))] + [
                  (a.cls, not a.certain or h.detail.startswith("uncertain")) for a in h.blind]
              if not (certain_only and unc)} for h in history] + [{cls}]
    mine = len(w) - 1
    for pick in permutations(range(len(w)), len(seq)):
        if mine not in pick or any(c not in kinds[k] for k, c in zip(pick, seq, strict=True)):
            continue
        t = float("-inf")
        for k in pick:
            t = max(t, w[k][1])
            if t > w[k][2]:
                break
        else:
            return True
    return False


@st.composite
def _aliased(draw: Any) -> tuple[tuple[str, ...], str, list[HistoryEntry], bool]:
    classes = ["A", "B", "W"]
    seq = tuple(draw(st.lists(st.sampled_from(classes), min_size=2, max_size=4)))
    cls = draw(st.sampled_from(classes))
    hist = []
    at = 0
    for _ in range(draw(st.integers(0, 6))):
        at += draw(st.integers(0, 3))
        c = draw(st.sampled_from(classes))
        blind = draw(st.sampled_from(["", *[x for x in classes if x != c]]))
        detail = draw(st.sampled_from(["rule", "uncertain: rule"]))
        kind = draw(st.sampled_from(["grant", "live", "expired", "audit"]))
        exp = {"grant": None, "live": int(NOW) + 60, "audit": None,
               "expired": at + draw(st.integers(0, 12))}[kind]
        hist.append(HistoryEntry(c, res(c), "agent", at=at, token_exp=exp,
                                 blind=[Alias(blind, draw(st.booleans()))] if blind else [],
                                 detail="audit record" if kind == "audit" else detail))
    return seq, cls, hist, draw(st.booleans())


@settings(max_examples=3000, deadline=None, derandomize=True)
@given(_aliased())
def test_the_search_agrees_with_exhaustive_enumeration_on_aliased_acts(case: Any) -> None:
    seq, cls, hist, certain_only = case
    pool = [h for h in hist if not certain_only or not h.detail.startswith("uncertain")]
    assert policy_mod._sequence_completable(seq, cls, pool, NOW, certain_only) == (
        _aliased_exhaustive(seq, cls, pool, NOW, certain_only)), case
