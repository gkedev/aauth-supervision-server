"""A prohibited sequence against tokens that outlive their decision.

The SS decides an act when a token is issued, not when it is used, and an auth token can
be presented until its `exp`. So "send, then read" in issuance order can still be
"read, then send" in effect: the agent holds the send token, gets the read token, reads,
then sends. These tests pin that the SS checks a sequence whichever of its steps the act
is, using each issued token's `exp` from `auth_token.issued`.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server import policy as policy_mod
from aauth_supervision_server.policy import Policy, PolicyConfig
from aauth_supervision_server.store import UNBOUNDED_EXP, HistoryEntry

NOW = 1_000.0
SEQ2 = [("read", "send")]
SEQ3 = [("read", "write", "send")]


def pol(seqs: list[tuple[str, ...]]) -> Policy:
    return Policy(PolicyConfig(severity=["unclassified", "read", "write", "send"],
                               prohibited_sequences=seqs))


def grant(cls: str, at: int = 0, uncertain: bool = False) -> HistoryEntry:
    return HistoryEntry(cls, "r", "resource", at=at,
                        detail="uncertain: x" if uncertain else "rule")


def token(cls: str, exp: int, at: int = 0) -> HistoryEntry:
    return HistoryEntry(cls, "r", "resource", at=at, detail="rule", token_exp=exp)


def comp(p: Policy, cls: str, history: list[HistoryEntry], *,
         uncertain: bool = False) -> tuple[list[str], bool]:
    return p._composition(cls, uncertain, "r", history, NOW)


# ------------------------------------------------------------------ live tokens of a later step


def test_a_live_later_step_token_makes_an_earlier_step_a_violation() -> None:
    p = pol(SEQ2)
    assert comp(p, "read", [token("send", exp=int(NOW) + 60)]) == (["read", "send"], False)


S = policy_mod.EXP_SKEW


def test_an_expired_later_step_token_does_not() -> None:
    """Protocol L2317: a resource judges `exp` "by the verifier's own clock" and the draft
    "defines no tolerance for clock skew on `exp`", so a resource whose clock is behind
    still accepts a token this SS has seen expire. The SS treats a token as usable for
    EXP_SKEW (the 60 s signature window, L2246) past its `exp`, and not after."""
    p = pol(SEQ2)
    assert comp(p, "read", [token("send", exp=int(NOW) - S - 1)]) == ([], False)
    assert comp(p, "read", [token("send", exp=int(NOW) - S)]) == ([], False)  # exclusive
    assert comp(p, "read", [token("send", exp=int(NOW) - S + 1)]) == (["read", "send"], False)
    assert comp(p, "read", [token("send", exp=int(NOW))]) == (["read", "send"], False)


def test_a_token_with_no_reported_exp_never_expires() -> None:
    p = pol(SEQ2)
    assert comp(p, "read", [token("send", exp=UNBOUNDED_EXP)]) == (["read", "send"], False)


def test_a_grant_for_a_later_step_happened_once_and_is_over() -> None:
    p = pol(SEQ2)
    assert comp(p, "read", [grant("send")]) == ([], False)


def test_a_three_step_sequence_completes_through_a_live_middle_token() -> None:
    # write token issued before the read, still live: write can land after the read.
    p = pol(SEQ3)
    hist = [token("write", exp=int(NOW) + 60), grant("read")]
    assert comp(p, "send", hist) == (["read", "write", "send"], False)
    # The same history with only grants is the harmless order.
    assert comp(p, "send", [grant("write"), grant("read")]) == ([], False)


def test_an_expired_token_reaches_only_the_acts_reported_before_its_exp() -> None:
    p = pol(SEQ3)
    # write token exp=50, usable to 50 + S by a resource behind the SS (L2317): a read
    # reported before that can precede a use of it; one reported after cannot.
    assert comp(p, "send", [token("write", exp=50, at=10), grant("read", at=40 + S)]) == (
        ["read", "write", "send"], False)
    assert comp(p, "send", [token("write", exp=50, at=10), grant("read", at=60 + S)]) == (
        [], False)


def test_the_act_being_decided_as_a_middle_step() -> None:
    p = pol(SEQ3)
    live_send = token("send", exp=int(NOW) + 60)
    assert comp(p, "write", [grant("read"), live_send]) == (["read", "write", "send"], False)
    assert comp(p, "write", [grant("read"), grant("send")]) == ([], False)
    # A grant cannot run before the read it follows.
    assert comp(p, "write", [live_send]) == ([], False)


def test_the_search_backtracks_when_the_first_token_it_tries_is_needed_later() -> None:
    # send, read, send with a live send token (0) and a one-off send (1): only "1 then
    # read then 0" works, so trying 0 first must be undone.
    p = pol([("send", "read", "send")])
    hist = [token("send", exp=int(NOW) + 60), grant("send")]
    assert comp(p, "read", hist) == (["send", "read", "send"], False)


def test_an_act_reported_exactly_at_a_tokens_exp_may_precede_its_use() -> None:
    # Report times are whole seconds; the boundary is `exp` plus the skew allowance
    # (L2317). An act reported in that very second may have come just before the token's
    # end or just after: the composition is found, but not as certain (it is asked).
    p = pol(SEQ3)
    assert comp(p, "send", [token("write", exp=50, at=10), grant("read", at=50 + S)]) == (
        ["read", "write", "send"], True)
    assert comp(p, "send", [token("write", exp=50, at=10), grant("read", at=49 + S)]) == (
        ["read", "write", "send"], False)
    assert comp(p, "send", [token("write", exp=50, at=10), grant("read", at=51 + S)]) == (
        [], False)


def test_one_token_never_takes_two_steps() -> None:
    p = pol([("send", "read", "send")])
    assert comp(p, "read", [token("send", exp=int(NOW) + 60)]) == ([], False)
    assert comp(p, "read", [token("send", exp=int(NOW) + 60),
                            token("send", exp=int(NOW) + 60)]) == (
        ["send", "read", "send"], False)


def test_at_the_last_step_the_recorded_order_decides() -> None:
    p = pol(SEQ3)
    assert comp(p, "send", [grant("read"), grant("write")]) == (["read", "write", "send"], False)
    assert comp(p, "send", [grant("write"), grant("read")]) == ([], False)


def test_the_decided_token_is_placed_at_its_own_position() -> None:
    # Everything in history started before it, so its own later use adds no order:
    # "read, then send" with the send being decided is the forward order.
    p = pol(SEQ2)
    assert comp(p, "send", [token("read", exp=int(NOW) + 60)]) == (["read", "send"], False)
    assert comp(p, "read", [grant("read")]) == ([], False)


def test_uncertainty_is_kept_and_a_certain_completion_wins() -> None:
    p = pol(SEQ2)
    live = token("send", exp=int(NOW) + 60)
    assert comp(p, "read", [live], uncertain=True) == (["read", "send"], True)
    unc = HistoryEntry("send", "r", "resource", detail="uncertain: x",
                       token_exp=int(NOW) + 60)
    assert comp(p, "read", [unc]) == (["read", "send"], True)
    assert comp(p, "read", [unc, live]) == (["read", "send"], False)


def test_a_search_that_runs_out_of_budget_counts_as_possible_and_uncertain(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_mod, "_SEQUENCE_SEARCH_BUDGET", 2)
    p = pol([("read", "write", "write", "write", "send")])
    hist = [token("write", exp=int(NOW) + 60) for _ in range(4)] + [
        token("send", exp=int(NOW) + 60)]
    assert comp(p, "read", hist) == (["read", "write", "write", "write", "send"], True)


def test_many_live_tokens_stay_cheap() -> None:
    # 200 live tokens of a step the sequence does not complete: the search must not
    # explode (it is bounded either way; this pins that the common case is fast).
    import time
    p = pol(SEQ3)
    hist = [token("write", exp=int(NOW) + 60) for _ in range(200)]
    t0 = time.perf_counter()
    assert comp(p, "read", hist) == ([], False)
    assert time.perf_counter() - t0 < 2.0


# ------------------------------------------------------------------ end to end


def test_token_exp_reads_only_a_positive_number() -> None:
    from aauth_supervision_server.service import _token_exp
    assert _token_exp({"exp": 1}) == 1
    assert _token_exp({"exp": 1_790_000_000}) == 1_790_000_000
    # A NumericDate may have a fraction (RFC 7519 Section 2): `exp` rounds up and `iat`
    # down, so a token is never read as expiring earlier than it does.
    assert _token_exp({"exp": 1.5}) == 2
    assert _token_exp({"exp": 100.0, "iat": 99.5}) == 100
    assert _token_exp({"exp": 100.5, "iat": 100.9}) == UNBOUNDED_EXP  # expired when issued
    assert _token_exp({"exp": 100.0, "iat": 100.5}) == UNBOUNDED_EXP
    for bad in ({}, {"exp": None}, {"exp": 0}, {"exp": -5}, {"exp": True}, {"exp": "100"},
                {"exp": 0.0}, {"exp": -0.5}, {"exp": float("nan")}, {"exp": float("inf")}):
        assert _token_exp(bad) == UNBOUNDED_EXP, bad


def test_e2e_an_issuance_without_exp_keeps_the_token_live() -> None:
    ss, ps, clock, s256 = _env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "allow"
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi,
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": ps.nid("at"),
            "aud": CHAT, "issuer": ps.issuer, "mission_s256": s256}
    assert ps.call(ss, "POST", "/event", body).status == 201
    entry = ss.store.history_for(ps.issuer, SUB, AGENT, s256)[-1]
    assert entry.token_exp == UNBOUNDED_EXP
    clock.t += 20 * 86400                           # weeks later, the mission still live
    assert _token(ss, ps, s256, DOCS) == "allow"   # a fresh write token
    assert _token(ss, ps, s256, REC) == "deny"     # the send token never expired
REC, DOCS, CHAT = "https://records.example", "https://docs.example", "https://chat.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": DOCS, "class": "write"},
         {"resource": CHAT, "class": "send_internal"}]


def _env() -> tuple[Any, Any, Any, str]:
    # The shipped example's own sequence: read_sensitive -> write -> send_internal.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[])
    s256 = connected((ss, ps, clock), resources=(REC, DOCS, CHAT))
    return ss, ps, clock, s256


def _token(ss: Any, ps: Any, s256: str, resource: str) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource)
    d = r.json()
    if d.get("decision") == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
    return str(d.get("decision"))


def test_e2e_tokens_taken_in_reverse_order_cannot_compose_the_sequence() -> None:
    ss, ps, _, s256 = _env()
    assert _token(ss, ps, s256, CHAT) == "allow"   # send token, live for an hour
    assert _token(ss, ps, s256, DOCS) == "allow"   # write token, nothing read yet
    assert _token(ss, ps, s256, REC) == "deny"     # read now could be followed by both


def test_e2e_once_the_later_tokens_expire_the_read_is_harmless() -> None:
    ss, ps, clock, s256 = _env()
    assert _token(ss, ps, s256, CHAT) == "allow"
    assert _token(ss, ps, s256, DOCS) == "allow"
    clock.t += 3601                                 # both tokens past their exp
    assert _token(ss, ps, s256, REC) == "deny"      # a resource behind may still take them
    clock.t += S                                    # and past the skew allowance (L2317)
    assert _token(ss, ps, s256, REC) == "allow"


def test_e2e_the_forward_order_is_still_denied_at_the_last_step() -> None:
    ss, ps, _, s256 = _env()
    assert _token(ss, ps, s256, REC) == "allow"
    assert _token(ss, ps, s256, DOCS) == "allow"
    assert _token(ss, ps, s256, CHAT) == "deny"


# ------------------------------------------------------------------ differential oracle

from itertools import product  # noqa: E402

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


def _moments(i: int, h: HistoryEntry, hist: list[HistoryEntry], now: float) -> list[float]:
    """Every moment, on a grid, at which entry `i`'s effect can land: a grant at its own
    position; a token from its position to the last later report at or before its exp,
    and after the act being decided too while its exp is ahead of `now`."""
    n = len(hist)
    if h.token_exp is None:
        return [float(i)]
    out = [float(i), i + 0.5]
    for j in range(i + 1, n):
        if hist[j].at <= h.token_exp + policy_mod.EXP_SKEW:
            out += [float(j), j + 0.5]
    if h.token_exp + policy_mod.EXP_SKEW > now:
        out += [float(j) for j in range(i, n + 2)] + [n + 0.5, n + 1.5]
    return sorted(set(out))


def _oracle(seq: tuple[str, ...], cls: str, hist: list[HistoryEntry]) -> bool:
    """Brute force: try every placement of every act, sort the effects into a log, and
    ask whether the log contains `seq` as a subsequence that uses the decided act. The
    decided act may land anywhere after every history entry started (its own token's
    later uses are tried too), which the search under test does not model directly."""
    n = len(hist)
    choices = [_moments(i, h, hist, NOW) for i, h in enumerate(hist)]
    mine = [float(n), n + 0.5, n + 1.0, n + 1.5]
    acts = [h.action_class for h in hist] + [cls]
    for times in product(*choices, mine):
        order = sorted(range(n + 1), key=lambda k: times[k])
        # Equal moments may land in either order: try each order within a tie group.
        groups: list[list[int]] = []
        for k in order:
            if groups and times[groups[-1][0]] == times[k]:
                groups[-1].append(k)
            else:
                groups.append([k])
        if _subseq_any(seq, acts, groups, n):
            return True
    return False


def _subseq_any(seq: tuple[str, ...], acts: list[str], groups: list[list[int]],
                me: int) -> bool:
    from itertools import permutations
    for perm in product(*(permutations(g) for g in groups)):
        log = [k for g in perm for k in g]
        for idx in _embeddings(seq, [acts[k] for k in log]):
            if me in (log[i] for i in idx):
                return True
    return False


def _embeddings(seq: tuple[str, ...], log: list[str]) -> Any:
    def rec(s: int, start: int, acc: list[int]) -> Any:
        if s == len(seq):
            yield list(acc)
            return
        for i in range(start, len(log)):
            if log[i] == seq[s]:
                acc.append(i)
                yield from rec(s + 1, i + 1, acc)
                acc.pop()
    yield from rec(0, 0, [])


CLASSES = ["read", "write", "send"]


@st.composite
def _case(draw: Any) -> tuple[tuple[str, ...], str, list[HistoryEntry]]:
    seq = tuple(draw(st.lists(st.sampled_from(CLASSES), min_size=2, max_size=3)))
    cls = draw(st.sampled_from(CLASSES))
    hist = []
    for i in range(draw(st.integers(0, 3))):
        c = draw(st.sampled_from(CLASSES))
        at = i * 10
        kind = draw(st.sampled_from(["grant", "live", "expired"]))
        if kind == "grant":
            hist.append(grant(c, at=at))
        elif kind == "live":
            hist.append(token(c, exp=int(NOW) + 60, at=at))
        else:
            hist.append(token(c, exp=at + draw(st.sampled_from([0, 5, 10, 15, 25])), at=at))
    return seq, cls, hist


@settings(max_examples=1500, deadline=None, derandomize=True)
@given(_case())
def test_search_agrees_with_the_brute_force_effect_log(case: Any) -> None:
    seq, cls, hist = case
    got = policy_mod._sequence_completable(seq, cls, hist, NOW)
    assert got is not None
    assert got == (cls in seq and _oracle(seq, cls, hist)), (seq, cls, hist)


# ------------------------------------------------------------------ repeated steps
# A sequence that repeats a step, with many live tokens of that step, must not run the
# search out of budget and put an honest mission to the person.

REPEAT = ("read", "read", "read", "read", "read", "send")


def test_repeated_steps_with_no_act_for_the_last_step_are_not_a_violation() -> None:
    p = pol([REPEAT])
    hist = [token("read", exp=int(NOW) + 60) for _ in range(40)]
    assert comp(p, "read", hist) == ([], False)


def test_enough_acts_of_every_step_but_no_order_is_settled_without_running_out() -> None:
    # The send happened once, before any read: the counts allow the sequence, the order
    # does not. Forty interchangeable live reads must cost one branch per step, not a
    # permutation (which would exhaust the budget and be put to the person).
    p = pol([REPEAT])
    hist = [grant("send")] + [token("read", exp=int(NOW) + 60) for _ in range(40)]
    assert comp(p, "read", hist) == ([], False)


def test_repeated_steps_that_can_complete_are_found_with_certainty() -> None:
    p = pol([REPEAT])
    hist = [token("read", exp=int(NOW) + 60) for _ in range(40)] + [
        token("send", exp=int(NOW) + 60)]
    assert comp(p, "read", hist) == (list(REPEAT), False)
    # Four reads are not five, whatever else is live.
    assert comp(p, "read", [token("read", exp=int(NOW) + 60) for _ in range(3)] + [
        token("send", exp=int(NOW) + 60)]) == ([], False)


def test_e2e_an_honest_mission_with_many_live_tokens_is_not_put_to_the_person() -> None:
    ss, ps, _, s256 = _env()
    ss.policy.cfg.prohibited_sequences = [("read_sensitive",) * 5 + ("send_internal",)]
    assert [_token(ss, ps, s256, REC) for _ in range(15)] == ["allow"] * 15


@settings(max_examples=400, deadline=None, derandomize=True)
@given(st.lists(st.sampled_from(["read", "send"]), min_size=2, max_size=5),
       st.sampled_from(["read", "send"]),
       st.lists(st.tuples(st.sampled_from(["read", "send"]),
                          st.sampled_from(["grant", "live", "expired"])), max_size=4))
def test_search_agrees_with_the_brute_force_on_repeated_steps(
        seq: list[str], cls: str, raw: list[tuple[str, str]]) -> None:
    hist = []
    for i, (c, kind) in enumerate(raw):
        at = i * 10
        hist.append(grant(c, at=at) if kind == "grant" else
                    token(c, exp=int(NOW) + 60 if kind == "live" else at + 15, at=at))
    got = policy_mod._sequence_completable(tuple(seq), cls, hist, NOW)
    assert got == (cls in seq and _oracle(tuple(seq), cls, hist)), (seq, cls, hist)
