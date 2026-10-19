"""An act whose class the agent's data raised composes as that class or as the class the
other rules give it (its blind class): one act, either class, never both at once.

The blind class is an alias of the same act in the composition search, so one act cannot
take two steps of a sequence. It is as certain as the act and its own classification
both are: an act already uncertain (another agent's, another mission's, one not settled
yet) is uncertain under either class. A "may" names what could complete it, and never
nothing.
"""
from __future__ import annotations

import math
from typing import Any

from aauth_supervision_server.policy import (
    Act,
    Classification,
    Policy,
    PolicyConfig,
    Rule,
    _doubts,
    _sequence_completable,
)
from aauth_supervision_server.store import Alias, HistoryEntry, Mission

R = "https://r.example"
SEV = ["unclassified", "read", "send_internal", "write", "read_sensitive"]


def _pol(**kw: Any) -> Policy:
    kw.setdefault("severity", SEV)
    kw.setdefault("prohibited_pairs", [])
    kw.setdefault("prohibited_sequences", [["read_sensitive", "write", "send_internal"]])
    kw.setdefault("composition_on_certain", "deny")
    return Policy(PolicyConfig(**kw))


def _note(detail: str = "rule write", blind_certain: bool = True, **kw: Any) -> HistoryEntry:
    """A Note the agent's data made `write`; the other rules make it `send_internal`."""
    return HistoryEntry("write", R, "agent", detail=detail,
                        blind=[Alias("send_internal", blind_certain)], **kw)


def test_one_act_does_not_take_two_steps_as_its_class_and_its_blind_class() -> None:
    p = _pol()
    live = _note(token_exp=10 ** 10)
    c = Classification("read_sensitive", "resource", False)
    assert p._compositions_of(c, [live], 0) == []
    # With another act for the other step, it completes, as either class.
    other = HistoryEntry("send_internal", R, "resource", detail="rule", token_exp=10 ** 10)
    assert p._compositions_of(c, [live, other], 0) == [
        (["read_sensitive", "write", "send_internal"], False)]


def test_the_search_tries_an_aliased_act_under_each_of_its_classes() -> None:
    seq = ("read_sensitive", "write", "send_internal")
    live = 10 ** 10
    # Two live acts, each a write that may be a send: one takes each step, whichever way.
    hist = [_note(token_exp=live), _note(token_exp=live)]
    assert _sequence_completable(seq, "read_sensitive", hist, 0) is True
    assert _sequence_completable(seq, "read_sensitive", hist[:1], 0) is False
    # The act being decided is placed once, as the class it is searched as.
    assert _sequence_completable(seq, "send_internal", [
        HistoryEntry("read_sensitive", R, "resource", detail="rule"), _note()], 0) is True


def test_an_alias_is_tried_even_where_another_act_of_its_step_ends_at_the_same_moment() -> None:
    # Two live writes; only the second may also be a send. The search must not take the
    # aliased one for the write step and stop: the plain one takes it instead.
    seq = ("read_sensitive", "write", "send_internal")
    live = 10 ** 10
    plain = HistoryEntry("write", R, "resource", detail="rule", token_exp=live)
    assert _sequence_completable(seq, "read_sensitive", [_note(token_exp=live), plain],
                                 0) is True
    assert _sequence_completable(seq, "read_sensitive", [plain, _note(token_exp=live)],
                                 0) is True


def test_an_uncertain_act_is_uncertain_under_its_blind_class_too() -> None:
    p = _pol(prohibited_pairs=[["send_internal", "read_sensitive"]], prohibited_sequences=[])
    c = Classification("read_sensitive", "resource", False)
    for detail in ("uncertain: of another agent: rule write",
                   "uncertain: allow not yet settled: rule write"):
        assert p._compositions_of(c, [_note(detail)], 0) == [
            (["send_internal", "read_sensitive"], True)], detail
    assert p._compositions_of(c, [_note(blind_certain=False)], 0) == [
        (["send_internal", "read_sensitive"], True)]
    assert p._compositions_of(c, [_note()], 0) == [(["send_internal", "read_sensitive"], False)]


def test_a_certain_pass_takes_an_act_only_as_a_certain_class() -> None:
    # The write is certain, its blind send is not: a sequence needing the send from it is
    # uncertain, though the act is in the certain pass as a write.
    p = _pol(prohibited_sequences=[["read_sensitive", "send_internal"]])
    c = Classification("read_sensitive", "resource", False)
    hist = [_note(blind_certain=False, token_exp=10 ** 10)]
    assert p._compositions_of(c, hist, 0) == [(["read_sensitive", "send_internal"], True)]


def _decide(history: list[HistoryEntry], **kw: Any) -> Any:
    p = _pol(rules=[Rule(cls="read_sensitive", resource=R)], **kw)
    m = Mission("m", "a", "s", "i", blob={"approved_resources": [R]})
    return p.decide(Act("auth_token", "i", "s", "a", mission_s256="m", resource=R,
                        parameters_provenance="resource"), m, history, [], now=0)


def test_another_agent_s_act_composing_by_its_blind_class_is_asked_not_denied() -> None:
    d = _decide([_note("uncertain: of another agent: rule write", open="agent")],
                prohibited_pairs=[["send_internal", "read_sensitive"]], prohibited_sequences=[])
    assert d.decision == "ask", d
    assert "Without the details the agent gave, an earlier act may have another class." in d.summary
    assert "another agent from the same provider" in d.summary


def test_a_may_names_what_could_complete_it_when_both_classes_are_steps() -> None:
    c = Classification("write", "agent", False, blind=[Alias("send_internal", False)])
    comp = ["read_sensitive", "write", "send_internal"]
    assert _doubts(comp, c, []) == [
        "Without the details the agent gave, this act may have another class."]
    # Certain under the other rules, the blind class is no doubt.
    c.blind[0].certain = True
    assert _doubts(comp, c, []) == []
    # An earlier act's blind class: a doubt only where it is uncertain.
    assert _doubts(comp, Classification("read_sensitive", "resource", False),
                   [_note(blind_certain=True)]) == []
    assert _doubts(comp, Classification("read_sensitive", "resource", False),
                   [_note(blind_certain=False)]) == [
        "Without the details the agent gave, an earlier act may have another class."]
    assert _doubts(["read_sensitive", "send_internal"],
                   Classification("read_sensitive", "resource", False),
                   [_note("uncertain: of another agent: rule write", open="agent")]) == [
        "Without the details the agent gave, an earlier act may have another class.",
        "One of the acts is by another agent from the same provider."]


def test_the_may_is_worded_as_what_it_rests_on() -> None:
    text = Policy._comp_summary([["a", "b"]], True, ["x", "y"])
    assert text == ("Together with other acts, this act may complete a combination the policy "
                    "forbids: `a`, then `b`. The supervisor can neither confirm nor rule it "
                    "out, as it cannot confirm every act that could complete it. x y")


def test_a_live_plain_act_takes_its_step() -> None:
    seq = ("read_sensitive", "write")
    hist = [HistoryEntry("write", R, "resource", detail="rule", token_exp=math.inf)]
    assert _sequence_completable(seq, "read_sensitive", hist, 0) is True
