"""After a routing change the SS cannot know where a replayed token stood.

Supervision L619 has the PS replay each active mission's log in order, then each
outstanding token: a token taken outside any mission arrives after mission entries it may
have preceded. Recorded order is then not the order of the acts, so a replayed token is
taken to have been usable from the start of the history up to its `exp`, never only from
where the replay put it.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS

REC, CHAT = "https://records.example", "https://chat.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": "*", "tool": "WriteDoc", "class": "write"},
         {"resource": CHAT, "class": "send_internal"}]
SEQ = [["read_sensitive", "write", "send_internal"]]


@pytest.mark.req("SUP-P12")
def test_a_token_replayed_after_the_mission_log_still_precedes_it() -> None:
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(REC, CHAT),
                     tools=[{"name": "WriteDoc", "description": "x"}])
    clock.t += 10
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)    # outside any mission
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t += 10
    audit = {"event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
             "agent": AGENT, "mission_s256": s256, "action": "WriteDoc"}
    assert ps.call(ss, "POST", "/event", audit).status == 201     # a write, in the mission
    log = list(ps.sent)
    clock.t += 10
    assert ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)[1].json()["decision"] == "deny"

    # Routing change, replayed in the order L619 gives: the mission, its log, then the
    # outstanding tokens.
    fetcher = StaticFetcher()
    ps.install(fetcher)
    key = SigningKey.generate("ss2")
    ss2 = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                         trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                            Policy(ss.policy.cfg), JwksUriResolver(fetcher), key, clock=clock)
    ps.ss_jwk = key.public_jwk()
    assert ps.connect(ss2, SUB).status == 200

    def replay(pick: Any) -> None:
        for path, body, _ in log:
            if pick(path, body):
                assert ps.call(ss2, "POST", path, body).status == 201

    replay(lambda p, b: p.startswith("/mission/") and b.get("action") == "approved")
    replay(lambda p, b: p == "/event" and b.get("mission_s256") == s256)
    replay(lambda p, b: p == "/event" and b.get("event") == "auth_token.issued"
           and not b.get("mission_s256"))
    assert ps.auth_token_request(ss2, SUB, AGENT, s256, CHAT)[1].json()["decision"] == "deny"


def test_a_person_token_replayed_after_the_mission_log_still_precedes_it() -> None:
    # A person token reported with no decision on record (here, replayed): where it stood
    # is not known either, so it may have been usable from the start of the history.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[], serves_on_identity=[REC])
    s256 = connected((ss, ps, clock), resources=(CHAT,),
                     tools=[{"name": "WriteDoc", "description": "x"}])
    clock.t += 10
    token = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": "d-pt",
             "iat": int(clock()), "sub": SUB, "agent": AGENT, "aud": REC, "jti": "pt-1",
             "exp": int(clock()) + 3600}
    assert ps.call(ss, "POST", "/event", token).status == 201     # outside any mission
    clock.t += 10
    audit = {"event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
             "agent": AGENT, "mission_s256": s256, "action": "WriteDoc"}
    assert ps.call(ss, "POST", "/event", audit).status == 201
    log = list(ps.sent)
    clock.t += 10
    assert ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)[1].json()["decision"] == "ask"

    fetcher = StaticFetcher()
    ps.install(fetcher)
    key = SigningKey.generate("ss2")
    ss2 = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                         trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                            Policy(ss.policy.cfg), JwksUriResolver(fetcher), key, clock=clock)
    ps.ss_jwk = key.public_jwk()
    assert ps.connect(ss2, SUB).status == 200
    for pick in (lambda p, b: p.startswith("/mission/") and b.get("action") == "approved",
                 lambda p, b: p == "/event" and b.get("mission_s256") == s256,
                 lambda p, b: p == "/event" and b.get("event") == "person_token.issued"):
        for path, body, _ in log:
            if pick(path, body):
                assert ps.call(ss2, "POST", path, body).status == 201
    assert ps.auth_token_request(ss2, SUB, AGENT, s256, CHAT)[1].json()["decision"] == "ask"


@pytest.mark.parametrize("copy", ["kin", "elsewhere"])
def test_a_copy_of_an_unplaced_person_token_is_still_unplaced(copy: str) -> None:
    # A person token reported with no decision may have been usable from the start of the
    # history: so may its copy into another agent's or another mission's composition.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry, elsewhere_copy, kin_copy
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    token = HistoryEntry("read_sensitive", REC, "configured", at=30, n=2, token_exp=10**9,
                         detail="uncertain: person token", unplaced=True)
    write = HistoryEntry("write", "WriteDoc", "agent", at=20, n=1, detail="audit record")
    copied = kin_copy(token, "aauth:other@agent.example") if copy == "kin" \
        else elsewhere_copy(token, "m-other")
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    assert p.decide(act, None, [write, copied], [], now=40).decision == "ask"


def _seq_env() -> tuple[Any, Any, Any]:
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[], serves_on_identity=[REC],
                             allow_unlisted_resources=True)
    assert ps.connect(ss, SUB).status == 200
    return ss, ps, clock


def _proposal(ss: Any, ps: Any, clock: Any) -> str:
    r = ps.call(ss, "POST", "/mission", {
        "sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# work",
        "resources": [REC, CHAT], "tools": [{"name": "WriteDoc", "description": "x"}]})
    assert r.json()["decision"] == "allow"
    return str(ps.sent[-1][1]["sdi"])


def _token(ss: Any, ps: Any, clock: Any, sdi: str, jti: str, life: int = 3600) -> None:
    assert ps.call(ss, "POST", "/event", {
        "event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "aud": REC, "jti": jti,
        "exp": int(clock()) + life}).status == 201


def _write(ss: Any, ps: Any, clock: Any, s256: str = "") -> None:
    b = {"event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
         "agent": AGENT, "action": "WriteDoc"}
    if s256:
        b["mission_s256"] = s256
    assert ps.call(ss, "POST", "/event", b).status == 201


def _approve(ss: Any, ps: Any, clock: Any, sdi: str, iat: int | None = None) -> str:
    import hashlib
    import json

    from aauth_supervision_server.jwk import b64u
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "# work",
            "approved_tools": [{"name": "WriteDoc", "description": "x"}],
            "approved_resources": [REC, CHAT]}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    assert ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "sdi": sdi,
        "iat": int(clock()) if iat is None else iat, "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)}).status == 201
    return s256


def test_a_token_held_before_its_approval_may_precede_later_acts() -> None:
    # Reported before `approved`, it exists from its report: a write after it, then a send,
    # complete read, write, send; held or once the approval books it.
    for approve in (False, True):
        ss, ps, clock = _seq_env()
        sdi = _proposal(ss, ps, clock)
        _token(ss, ps, clock, sdi, "pt-1")
        clock.t += 5
        _write(ss, ps, clock)
        clock.t += 5
        where = _approve(ss, ps, clock, sdi) if approve else ""
        _, r, _ = ps.auth_token_request(ss, SUB, AGENT, where, CHAT)
        assert r.json()["decision"] == "ask", approve


def test_two_tokens_held_for_one_resource_are_both_kept() -> None:
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    _token(ss, ps, clock, sdi, "pt-long", life=3600)
    _token(ss, ps, clock, sdi, "pt-short", life=100)
    held = sorted(rec.entry.jti for rec in ss.store.decisions.values()
                  if rec.decision == "reported" and rec.entry is not None)
    assert held == ["pt-long", "pt-short"]


def test_an_approval_in_the_second_of_a_later_act_floats() -> None:
    # Replayed after an act of the same second (Supervision L619): where it stood is not
    # known, so its token may precede that act.
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    _write(ss, ps, clock)
    s256 = _approve(ss, ps, clock, sdi)                # the same second as the write
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.resource == REC)
    assert h.unplaced


def test_two_held_reports_without_a_jti_keep_the_wider_window() -> None:
    # Two reports for one resource that name no `jti` cannot be told apart: the held token
    # keeps the earliest moment and the latest `exp` of the two, never a shorter window.
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    _token(ss, ps, clock, sdi, "", life=3600)
    clock.t += 2
    _token(ss, ps, clock, sdi, "", life=100)
    (h,) = (rec.entry for rec in ss.store.decisions.values()
            if rec.decision == "reported" and rec.entry is not None)
    # (`at` on the SS's clock: the first report's stamp, and two seconds for whole
    # seconds)
    assert h.at == int(clock()) - 2 + 2 and h.token_exp == int(clock()) - 2 + 3600


def _decide_after_replay(history: list[Any], now: float) -> str:
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    return p.decide(act, None, history, [], now=now).decision


def test_a_replayed_log_in_order_is_judged_as_it_was_recorded() -> None:
    # A mission's log replayed in order (Supervision L619): a write token that expired,
    # then a read 190 s later. Their stamps agree with the order they arrive in, so they
    # stand where they arrive, as at the old SS: the read cannot precede the write.
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "https://calendar.example", "configured", at=10, n=1,
                         token_exp=40, detail="replayed", unplaced=True)
    read = HistoryEntry("read_sensitive", REC, "configured", at=200, n=2, token_exp=10**9,
                        detail="replayed", unplaced=True)
    assert _decide_after_replay([write, read], now=220) == "allow"


def test_a_replayed_token_stamped_after_a_write_stands_after_it() -> None:
    # Stamped after the write's report and arriving after it, the token took place after
    # the write: read, write, send cannot complete.
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "WriteDoc", "agent", at=20, n=1, detail="audit record")
    read = HistoryEntry("read_sensitive", REC, "configured", at=30, n=2, token_exp=10**9,
                        detail="replayed", unplaced=True)
    assert _decide_after_replay([write, read], now=40) == "allow"


def test_a_replayed_token_stamped_before_a_write_still_completes_for_certain() -> None:
    # Supervision L619 replays outside tokens after the mission logs: one stamped before
    # the write was taken before it, and it is live: the sequence completes, certainly.
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "WriteDoc", "agent", at=20, n=1, detail="audit record")
    read = HistoryEntry("read_sensitive", REC, "configured", at=10, n=2, token_exp=10**9,
                        detail="replayed", unplaced=True)
    assert _decide_after_replay([write, read], now=40) == "deny"


def test_an_approval_reported_late_floats_whatever_held_token_it_takes() -> None:
    # Reported after a later act (a retry), the approval's token may precede that act:
    # merged with a token held since, reported after the act, it floats all the same.
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    t_a = int(clock())
    clock.t += 1
    _write(ss, ps, clock)
    clock.t += 2
    _token(ss, ps, clock, sdi, "pt-2")
    clock.t += 2
    s256 = _approve(ss, ps, clock, sdi, iat=t_a)
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.resource == REC)
    assert h.jti == "pt-2" and h.unplaced
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_a_replayed_token_live_past_a_later_act_still_completes_for_certain() -> None:
    # Expired by now, but still live when a read stamped after it was reported: wherever
    # it was taken, it could be used after that read, so read, write, send completes for
    # certain (a "may" answer does not cover it).
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "https://calendar.example", "configured", at=100, n=1,
                         token_exp=200, detail="replayed", unplaced=True)
    read = HistoryEntry("read_sensitive", REC, "configured", at=150, n=2, token_exp=10**9,
                        detail="rule")
    assert _decide_after_replay([write, read], now=300) == "deny"


def test_a_replayed_token_live_when_an_earlier_reported_act_happened_completes() -> None:
    # Stamped before a read that arrived first, and live when the read happened: the
    # read, then the write on it, then the send, for certain.
    from aauth_supervision_server.store import HistoryEntry
    read = HistoryEntry("read_sensitive", REC, "configured", at=120, n=1, token_exp=10**9,
                        detail="rule")
    write = HistoryEntry("write", "https://calendar.example", "configured", at=100, n=2,
                         token_exp=150, detail="replayed", unplaced=True)
    assert _decide_after_replay([read, write], now=300) == "deny"


def test_an_approval_stamped_far_ahead_of_the_clock_floats() -> None:
    # Past the margin ahead of this SS's clock, the approval's stamp places nothing: a
    # write recorded before it, stamped earlier, may have followed it (a PS clock that
    # stepped back), so the approval's token may precede the write.
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    t = int(clock())
    clock.t += 5
    _write(ss, ps, clock)
    clock.t += 5
    s256 = _approve(ss, ps, clock, sdi, iat=t + 120)
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.resource == REC)
    assert h.unplaced
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_an_approval_s_token_is_usable_from_the_start_of_the_history() -> None:
    # Where a token an approval issued stood is not worked out from when the approval was
    # reported. Whenever that is, the token may have been usable from the start of the
    # history: more asks, never an order assumed.
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    _write(ss, ps, clock)
    clock.t += 30
    s256 = _approve(ss, ps, clock, sdi)                # reported well after the write
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.resource == REC)
    assert h.unplaced
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_a_held_token_merged_at_approval_is_usable_from_the_start_too() -> None:
    ss, ps, clock = _seq_env()
    sdi = _proposal(ss, ps, clock)
    _write(ss, ps, clock)
    clock.t += 10
    _token(ss, ps, clock, sdi, "pt-1")                 # reported after the write
    clock.t += 10
    s256 = _approve(ss, ps, clock, sdi)
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.resource == REC)
    assert h.jti == "pt-1" and h.unplaced


def test_a_replayed_token_stamped_before_a_write_is_certain_beside_other_replayed_ones(
) -> None:
    # Two outstanding tokens replayed after the log (Supervision L619): the other one's
    # stamp says nothing of where the first stood among the log's entries.
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "WriteDoc", "agent", at=20, n=1, detail="audit record")
    read = HistoryEntry("read_sensitive", REC, "configured", at=10, n=2, token_exp=10**9,
                        detail="replayed", unplaced=True)
    other = HistoryEntry("read", "https://other.example", "configured", at=5, n=3,
                         token_exp=10**9, detail="replayed", unplaced=True)
    assert _decide_after_replay([write, read, other], now=40) == "deny"
    assert _decide_after_replay([write, other, read], now=40) == "deny"


def test_a_replayed_token_stamped_before_a_long_log_is_certain() -> None:
    # However many entries the log has, a token stamped before all of them preceded each.
    from aauth_supervision_server.store import HistoryEntry
    write = HistoryEntry("write", "WriteDoc", "agent", at=20, n=1, detail="audit record")
    log = [HistoryEntry("read", "https://other.example", "configured", at=30 + k, n=2 + k,
                        detail="rule") for k in range(300)]
    read = HistoryEntry("read_sensitive", REC, "configured", at=10, n=400, token_exp=10**9,
                        detail="replayed", unplaced=True)
    assert _decide_after_replay([write, *log, read], now=400) == "deny"


def test_an_expired_floating_token_s_window_does_not_depend_on_where_it_landed() -> None:
    # Dead before every entry pinned at its position, it can only have been used before
    # all of them, wherever it was appended: it cannot follow a later write.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], high_impact=[],
                          prohibited_sequences=[["write", "read_sensitive", "send_internal"]]))
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    token = HistoryEntry("read_sensitive", REC, "configured", at=2, n=0, token_exp=32,
                         detail="uncertain: person token", unplaced=True)
    write = HistoryEntry("write", "WriteDoc", "agent", at=3800, n=0,
                         token_exp=4611686018427387904, detail="rule")
    for hist in ([token, write], [write, token]):
        assert p.decide(act, None, hist, [], now=3900).decision == "allow"


def test_a_completion_the_stamps_cannot_settle_is_not_covered_by_a_may_answer() -> None:
    # A mission's log replayed (Supervision L619): a read token and a write token stamped
    # in the same second, the write expired before the replay. Their stamps do not order
    # them, so whether the send would complete read, write, send is not known either way.
    # An answer about a completion that only "may" happen does not cover it: it is asked
    # again.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry, Reach
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    read = HistoryEntry("read_sensitive", REC, "configured", at=20, n=1, token_exp=10**9,
                        detail="replayed", unplaced=True)
    write = HistoryEntry("write", "https://calendar.example", "configured", at=20, n=2,
                         token_exp=50, detail="replayed", unplaced=True)    # the same second
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    may = Reach("always", "ps", SUB, AGENT, f"send_internal|{CHAT}",
                composition_override=list(SEQ[0]))
    d = p.decide(act, None, [read, write], [may], now=210)
    assert d.decision == "ask", d.trace
    # The person is told why: the order is not known, not that the search gave up.
    assert "cannot tell whether" in d.summary and "step budget" not in d.summary
    assert "order" in d.summary


@pytest.mark.parametrize(("gap", "want"), [(1, "deny"), (0, "ask")])
def test_an_issuance_reported_after_a_later_act_may_precede_it(gap: int, want: str) -> None:
    # The report of a token issued at tA arrives after a write stamped tA + gap (a retry
    # out of the order Supervision L211 asks for). It floats: stamped a second before the
    # write it surely preceded it, as delivered in order (a deny, which no answer about a
    # "may" covers); in the same second, the order is not settled (asked).
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    t_a = int(clock())
    clock.t += gap
    _write(ss, ps, clock)                              # reported first
    clock.t += 4
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t_a, "sub": SUB,
        "agent": AGENT, "jti": "at-late", "aud": REC, "scope": None, "exp": t_a + 3600,
        "issuer": ps.issuer}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want


def test_an_issuance_reported_with_nothing_recorded_since_its_decision_stands_there() -> None:
    # Reported in order, nothing recorded since its decision: it stands where it is
    # reported, whatever its stamp says against stamps of other clocks (an SS stamp, a PS
    # clock behind it).
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    _write(ss, ps, clock)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi,
        "iat": int(clock()) - 30, "sub": SUB, "agent": AGENT, "jti": "at-skew", "aud": REC,
        "scope": None, "exp": int(clock()) + 3600, "issuer": ps.issuer}).status == 201
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.jti == "at-skew")
    assert not h.unplaced and h.after_n == 0


def test_a_mission_log_replayed_in_order_completes_as_it_did_before() -> None:
    # The old SS, which recorded them in this order, denies: so does the new one.
    from aauth_supervision_server.store import HistoryEntry
    read = HistoryEntry("read_sensitive", REC, "configured", at=10, n=1, token_exp=10**9,
                        detail="replayed", unplaced=True)
    write = HistoryEntry("write", "https://calendar.example", "configured", at=20, n=2,
                         token_exp=50, detail="replayed", unplaced=True)
    assert _decide_after_replay([read, write], now=210) == "deny"


def test_an_approval_s_token_cannot_precede_acts_recorded_before_its_proposal() -> None:
    # The token is issued at approval, after the SS answered the proposal: an act the SS
    # recorded before that answer took place before the token existed.
    ss, ps, clock = _seq_env()
    _write(ss, ps, clock)
    clock.t += 10
    sdi = _proposal(ss, ps, clock)
    clock.t += 10
    s256 = _approve(ss, ps, clock, sdi)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "allow"


def test_an_allowed_token_not_yet_reported_counts_from_its_decision() -> None:
    # Allowed, its issuance not reported yet when a later act is: delivered out of the
    # order Supervision L211 asks for, the token may have been used before that act.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t += 1
    _write(ss, ps, clock)
    clock.t += 1
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "ask"


def test_a_floating_token_cannot_precede_entries_recorded_before_its_floor() -> None:
    # `after_n`: entries numbered below it were recorded before the answer the token
    # follows, so took place before it; without a floor it may precede any of them.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    for floor, want in ((2, "allow"), (0, "ask")):
        write = HistoryEntry("write", "WriteDoc", "agent", at=10, n=1, detail="audit record")
        read = HistoryEntry("read_sensitive", REC, "configured", at=5, n=3, token_exp=10**9,
                            detail="uncertain: person token", unplaced=True, after_n=floor)
        assert p.decide(act, None, [write, read], [], now=40).decision == want, floor


def test_an_audited_act_may_precede_a_token_that_died_before_every_pinned_entry() -> None:
    # An audited action may have taken place before every entry, as may a floating token
    # that expired before every entry pinned at its place: the audit can come first.
    from aauth_supervision_server.store import HistoryEntry
    read = HistoryEntry("read_sensitive", "ExportRecords", "agent", at=160, n=1,
                        detail="audit record")
    write = HistoryEntry("write", "https://calendar.example", "configured", at=80, n=2,
                         token_exp=100, detail="replayed", unplaced=True)
    assert _decide_after_replay([read, write], now=400) == "ask"


def test_an_unsettled_composition_offers_this_act_only() -> None:
    # No answer covers a composition the order does not settle, so none but this act's is
    # offered.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry, Mission
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[], allow_unlisted_resources=True))
    read = HistoryEntry("read_sensitive", REC, "configured", at=20, n=1, token_exp=10**9,
                        detail="replayed", unplaced=True)
    write = HistoryEntry("write", "https://calendar.example", "configured", at=20, n=2,
                         token_exp=50, detail="replayed", unplaced=True)
    m = Mission("m1", AGENT, SUB, "ps", {"approved_resources": [CHAT]})
    act = Act("auth_token", "ps", SUB, AGENT, "m1", resource=CHAT)
    d = p.decide(act, m, [read, write], [], now=210)
    assert d.decision == "ask" and "cannot tell whether" in d.summary
    assert [o["value"] for o in d.apply_options] == ["once"]


def test_a_late_issuance_of_a_0_1_x_decision_floats() -> None:
    # A 0.1.x decision record holds no position (0: not known): a
    # report stamped before an act recorded since floats all the same, and its stamp puts
    # it before the write, as delivery in order would.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    from aauth_supervision_server.store import Store
    ss.store.decisions[Store.k(ps.issuer, sdi)].recorded_n = 0   # as loaded from 0.1.x
    t_a = int(clock())
    clock.t += 5
    _write(ss, ps, clock)
    clock.t += 4
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t_a + 1,
        "sub": SUB, "agent": AGENT, "jti": "at-old", "aud": REC, "scope": None,
        "exp": t_a + 3600, "issuer": ps.issuer}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny"


def test_an_expired_token_reported_late_does_not_follow_acts_it_never_reached() -> None:
    # A write token expired long before a read existed, its issuance reported after the
    # read: it floats from its own stamps, so read, write, send cannot complete.
    cal = "https://calendar.example"
    ss, ps, clock = make_env(rules=[*RULES, {"resource": cal, "class": "write"}],
                             prohibited_pairs=[], prohibited_sequences=SEQ, high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi_w, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", cal)
    assert r.json()["decision"] == "allow"
    t0 = int(clock())
    clock.t += 199
    sdi_r, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi_r, REC).status == 201
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi_w, "iat": t0,
        "sub": SUB, "agent": AGENT, "jti": "w-late", "aud": cal, "scope": None,
        "exp": t0 + 20, "issuer": ps.issuer}).status == 201
    clock.t += 10
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "allow"


def test_an_answer_reported_after_a_later_act_floors_its_token_at_the_ask() -> None:
    # The person allows at t0 + 5 and the agent writes at t0 + 7, but `decision.resolved`
    # arrives after the write (out of L211's order): the token, issued at the answer, may
    # precede the write, before and after its issuance is reported.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(CHAT,),
                     tools=[{"name": "WriteDoc", "description": "x"}])
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "ask"
    t0 = int(clock())
    clock.t += 7
    _write(ss, ps, clock, s256)
    clock.t += 2
    assert ps.call(ss, "POST", "/event", {
        "event": "decision.resolved", "id": ps.nid("e"), "sdi": sdi, "iat": t0 + 5,
        "sub": SUB, "agent": AGENT, "answer": "allow", "mission_s256": s256}).status == 201
    clock.t += 300
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t0 + 5,
        "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "r-late", "aud": REC,
        "scope": None, "exp": t0 + 3600, "issuer": ps.issuer}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] != "allow"


def test_an_expired_floating_token_reaches_a_floored_token_issued_while_it_lived() -> None:
    # A write token whose place is not known, live from 0 to 120 (with the margin), and a
    # read floored after the entries recorded before its answer (stamped 10, while the
    # write lived): the write may follow the read.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    other = HistoryEntry("read", "https://mail.example", "configured", at=5, n=1,
                         token_exp=10**9, detail="replayed", unplaced=True)
    write = HistoryEntry("write", "https://calendar.example", "configured", at=0, n=2,
                         token_exp=60, detail="replayed", unplaced=True)
    read = HistoryEntry("read_sensitive", REC, "configured", at=10, n=0, token_exp=10**9,
                        detail="uncertain: allow not yet settled: rule", unplaced=True,
                        after_n=3, open="own", borrowed=True)
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    assert p.decide(act, None, [other, write, read], [], now=300).decision == "ask"


def _late_env() -> tuple[Any, Any, Any, str]:
    rules = [*RULES, {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(CHAT,),
                     tools=[{"name": "WriteDoc", "description": "x"}])
    return ss, ps, clock, s256


def test_a_permission_answer_reported_late_floats_its_grant() -> None:
    # The person allows ExportRecords at t0 + 10, the agent writes at t0 + 20, and the
    # answer arrives after the write (out of L211's order): the grant, stamped first,
    # surely came first, as delivered in order.
    ss, ps, clock, s256 = _late_env()
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {
        "sdi": sdi, "act": "permission", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "ExportRecords"})
    assert r.json()["decision"] == "ask"
    t0 = int(clock())
    clock.t += 20
    _write(ss, ps, clock, s256)
    clock.t += 5
    assert ps.call(ss, "POST", "/event", {
        "event": "decision.resolved", "id": ps.nid("e"), "sdi": sdi, "iat": t0 + 10,
        "sub": SUB, "agent": AGENT, "answer": "allow", "mission_s256": s256}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "deny"


def test_a_late_report_is_placed_by_the_ps_stamps_whatever_the_ss_clock() -> None:
    # The PS's clock runs 30 s behind the SS's: the read's issuance (PS stamp t - 30),
    # reported after a write the PS stamped t - 20, surely came before it.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    t = int(clock())
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": t - 20, "sub": SUB,
        "agent": AGENT, "action": "WriteDoc"}).status == 201
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t - 30,
        "sub": SUB, "agent": AGENT, "jti": "lag", "aud": REC, "scope": None,
        "exp": t + 3600, "issuer": ps.issuer}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny"


def test_a_report_in_the_same_second_as_an_act_before_it_is_asked_each_time() -> None:
    # The write and the read's issuance stamped in one second, the issuance reported
    # after the write: which came first is not settled, and if the read did, the send
    # completes on certain evidence. So it is asked, this act only, and asked again.
    ss, ps, clock, s256 = _late_env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow").status == 201
    clock.t += 5
    _write(ss, ps, clock, s256)
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "tie", "aud": REC,
        "scope": None, "exp": int(clock()) + 3600, "issuer": ps.issuer}).status == 201
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.jti == "tie")
    assert h.after_n and not h.unplaced
    sdi2, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    d = r.json()
    assert d["decision"] == "ask" and "does not settle" in d["summary"]
    assert [o["value"] for o in d["apply_options"]] == ["once"]
    assert ps.resolved(ss, SUB, AGENT, s256, sdi2, "allow", apply="once").status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_an_audit_reported_late_is_not_taken_for_certain_after_acts_stamped_later() -> None:
    # The write took place at t + 40 and was reported at t + 175, after a read issued at
    # t + 46: the write came first, so read, write, send is not denied. The uncertain
    # pass keeps an audit's whole span before its report, so it is asked.
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    clock.t += 46
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t += 129
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": t + 40, "sub": SUB,
        "agent": AGENT, "action": "WriteDoc"}).status == 201
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "ask"


def test_floored_acts_cost_no_more_than_the_same_history_without_floors() -> None:
    # A token whose place is not known reaches the floors of floored acts stamped while
    # it lived; finding the latest one is a search, not a scan per token.
    import time as _time

    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)

    def history(floored: bool) -> list[HistoryEntry]:
        out = []
        for k in range(4000):
            if k % 2:
                out.append(HistoryEntry("read_sensitive", REC, "configured", at=10 * k, n=k + 1,
                                        token_exp=10 * k + 5, detail="uncertain: person token",
                                        unplaced=True, after_n=k if floored else 0))
            else:
                out.append(HistoryEntry("write", f"https://w{k}.example", "configured",
                                        at=10 * k, n=k + 1, token_exp=10 * k + 5,
                                        detail="rule"))
        return out

    def cost(hist: list[HistoryEntry]) -> float:
        # The best of five runs: a busy machine only ever adds time.
        best = float("inf")
        for _ in range(5):
            t = _time.perf_counter()
            p.decide(act, None, hist, [], now=10**6)
            best = min(best, _time.perf_counter() - t)
        return best

    base, floored = cost(history(False)), cost(history(True))
    assert floored <= 3 * base + 0.05, (base, floored)


def test_a_may_answer_does_not_cover_a_report_in_the_second_of_a_later_act() -> None:
    # The read's token, decided before the agent's audited write and reported after it in
    # the same second (`after_n`, not `unplaced`): if the read came first, the send
    # completes on certain evidence. An answer the person gave about a "may" does not
    # cover that: the send is asked, and no answer covers it.
    from conftest import policy_cfg

    from aauth_supervision_server.policy import Act
    from aauth_supervision_server.store import HistoryEntry, Reach
    p = Policy(policy_cfg(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                          high_impact=[]))
    write = HistoryEntry("write", "WriteDoc", "agent", at=100, n=1, iat=100,
                         detail="audit record")
    read = HistoryEntry("read_sensitive", REC, "configured", at=105, n=2, iat=100,
                        token_exp=4000, detail="rule", after_n=1)
    act = Act("auth_token", "ps", SUB, AGENT, "", resource=CHAT)
    may = Reach("always", "ps", SUB, AGENT, f"send_internal|{CHAT}",
                composition_override=list(SEQ[0]))
    d = p.decide(act, None, [write, read], [may], now=300)
    assert d.decision == "ask", d.trace
    assert "does not settle" in d.summary
    assert [o["value"] for o in d.apply_options] == ["once"]


CAL = "https://calendar.example"


def _short_write(ss: Any, ps: Any, life: int, s256: str = "") -> None:
    # A write token issued at once, `life` seconds of it by the PS's clock.
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "allow"
    now = int(ps.clock())
    b = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": now, "sub": SUB,
         "agent": AGENT, "jti": ps.nid("at"), "aud": CAL, "scope": None, "exp": now + life,
         "issuer": ps.issuer}
    if s256:
        b["mission_s256"] = s256
    assert ps.call(ss, "POST", "/event", b).status == 201


@pytest.mark.parametrize(("lag", "want"), [(0, "deny"), (30, "allow")])
def test_a_ps_clock_behind_does_not_make_a_token_surely_live_longer(lag: int,
                                                                   want: str) -> None:
    # A write token with 60 s of life issued at 0, a read issued at 110, a send at 200,
    # the PS's clock `lag` s behind the SS's. The resource ends the token at its `exp` by
    # its own clock: 60 - lag on the SS's. In step (with the 60 s margin) the token was
    # live at the read, and the send would complete; 30 s behind, it had ended (the PS's
    # signatures show the lag), so the send is allowed, not denied.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t - lag
    assert ps.connect(ss, SUB).status == 200
    _short_write(ss, ps, 60)
    clock.t += 110
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t += 90
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want


@pytest.mark.parametrize(("delivered", "want"), [(100, "deny"), (300, "allow")])
def test_a_grant_on_a_retried_request_takes_place_when_it_is_granted(delivered: int,
                                                                    want: str) -> None:
    # A write token with 60 s of life issued at 0. The agent asks for a permission at 100
    # (the request's `iat`); delivered then, the grant came while the token was live and
    # the send would complete. Lost and retried at 300 with `iat` unchanged (Supervision
    # L198), it is granted at 300, after the token ended: nothing completes.
    rules = [*RULES, {"resource": CAL, "class": "write"},
             {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    _short_write(ss, ps, 60)
    clock.t = t + delivered
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": t + 100, "sub": SUB, "agent": AGENT,
        "action": "ExportRecords"})
    assert r.json()["decision"] == "allow"
    clock.t = t + 400
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want


@pytest.mark.parametrize(("lag", "want"), [(0, "deny"), (30, "allow")])
def test_a_ps_clock_behind_does_not_stretch_a_token_past_a_late_answer(lag: int,
                                                                      want: str) -> None:
    # As above, but the read is asked at 10 and the person allows it at 110: the SS
    # decided it long before its issuance, so only the report's arrival bounds when it
    # was issued on the SS's clock.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t - lag
    s256 = connected((ss, ps, clock), resources=(CHAT, CAL))
    t = clock.t
    _short_write(ss, ps, 60, s256)
    clock.t = t + 10
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "ask"
    clock.t = t + 110
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow").status == 201
    assert ps.issued(ss, SUB, AGENT, s256, sdi, REC).status == 201
    clock.t = t + 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == want


@pytest.mark.parametrize(("lag", "want"), [(0, "deny"), (30, "allow")])
def test_a_ps_clock_behind_does_not_stretch_a_token_past_a_late_grant(lag: int,
                                                                     want: str) -> None:
    # The same with a permission the person grants at 110: the grant took place by the
    # answer's arrival, whatever the PS's stamp on it says.
    rules = [*RULES, {"resource": CAL, "class": "write"},
             {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t - lag
    s256 = connected((ss, ps, clock), resources=(CHAT, CAL))
    t = clock.t
    _short_write(ss, ps, 60, s256)
    clock.t = t + 10
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {
        "sdi": sdi, "act": "permission", "iat": int(ps.clock()), "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "ExportRecords"})
    assert r.json()["decision"] == "ask"
    clock.t = t + 110
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow").status == 201
    clock.t = t + 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == want


@pytest.mark.parametrize(("lag", "want"), [(0, "ask"), (30, "ask")])
def test_a_replayed_log_with_the_ps_clock_behind_does_not_stretch_a_token(lag: int,
                                                                          want: str) -> None:
    # A write token with 100 s of life by the PS's clock, and a read issued 165 - lag s
    # later on the SS's: after the token's end and the 60 s margin. A routing change
    # replays the log in order. The new SS does not know the PS's clock at the acts (its
    # clock at the replay says nothing of it): it does not take the token as surely live
    # at the read (with the PS 30 s behind, the stamps alone would), nor rule it out within
    # the signature window, so it asks.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t - lag
    s256 = connected((ss, ps, clock), resources=(REC, CHAT, CAL))
    t = clock.t
    _short_write(ss, ps, 100, s256)
    clock.t = t + 165 - lag
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, REC).status == 201
    clock.t = t + 200
    fetcher = StaticFetcher()
    ps.install(fetcher)
    key = SigningKey.generate("ss2")
    ss2 = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                         trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                            Policy(ss.policy.cfg), JwksUriResolver(fetcher), key, clock=clock)
    ps.ss_jwk = key.public_jwk()
    ps.replay_to(ss2, SUB, AGENT)
    _, r, _ = ps.auth_token_request(ss2, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == want


@pytest.mark.parametrize(("write_at", "want"), [(1, "allow"), (2, "ask")])
def test_an_unrelated_act_in_a_report_s_second_does_not_unsettle_what_the_stamps_settle(
        write_at: int, want: str) -> None:
    # The read's token is decided at t, the agent writes at t + write_at (audited), and the
    # token is issued at t + 2, its report after an act of an agent of another provider
    # stamped in that second. Every act recorded since the decision before that one was
    # stamped earlier, so it came first: a write at t + 1 came before the read, and the
    # send completes nothing. A write at t + 2 shares the read's second: not settled.
    other = "aauth:z@other.example"
    ss, ps, clock = make_env(rules=RULES, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = t + write_at
    _write(ss, ps, clock)
    clock.t = t + 2
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": t + 2, "sub": SUB,
        "agent": other, "action": "WebSearch"}).status == 201
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t = t + 10
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want


def test_a_write_queued_behind_a_retried_permission_request_is_not_unsettled() -> None:
    # The agent asks for ExportRecords at t (the request's `iat`); the first delivery
    # fails, and the agent's write at t + 20 is audited and queued behind the request
    # (Supervision L211). The retry is granted at t + 40, then the audit arrives. The
    # write, stamped before the grant, came first: no certain completion, nor one the
    # stamps leave open (at most a "may", which the person can answer).
    rules = [*RULES, {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(CHAT,),
                     tools=[{"name": "WriteDoc", "description": "x"},
                            {"name": "ExportRecords", "description": "x"}])
    t = int(clock())
    clock.t = t + 40
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": t, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "ExportRecords"})
    assert r.json()["decision"] == "allow"
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": t + 20, "sub": SUB,
        "agent": AGENT, "action": "WriteDoc", "mission_s256": s256}).status == 201
    clock.t = t + 60
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    d = r.json()
    assert d["decision"] in ("allow", "ask"), d
    assert "cannot tell whether" not in d.get("summary", ""), d


@pytest.mark.parametrize("lead", [0, 31, 55])
def test_a_ps_clock_ahead_does_not_shorten_a_token_s_margin(lead: int) -> None:
    # A write token allowed at t, issued with the hour the SS caps its `exp` at (the SS's
    # clock), and a read issued at that end plus 30 s: within the 60 s margin, so the
    # write may follow the read and the send would complete, on certain acts. The PS's
    # clock `lead` s ahead of the SS's changes none of that.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t + lead
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    clock.t = t + 3630
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t = t + 3700
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny"


def test_a_report_in_the_seconds_past_a_token_s_end_is_asked_with_its_life_in_doubt() -> None:
    # A write token with 60 s of life, and a read issued a second past its end and the 60 s
    # margin, the PS's clock on time. Whole-second stamps and transit leave a few seconds
    # in doubt: the token may still have been live at the read, so the send is asked, this
    # act only, and the person is told what is not settled.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    _short_write(ss, ps, 60)
    clock.t = t + 121
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t = t + 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    d = r.json()
    assert d["decision"] == "ask" and "still live" in d["summary"]
    assert [o["value"] for o in d["apply_options"]] == ["once"]


def test_a_token_reported_after_an_act_it_ended_before_completes_for_certain() -> None:
    # A read token issued at t that ends at t + 58 (t + 118 with the margin), a write
    # issued at t + 120, and the read's issuance reported after the write, out of the
    # order L211 asks for. Its stamp and its end both put its whole life before the
    # write, wherever it stood: read, write, send completes for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    t = int(clock())
    clock.t += 120
    _short_write(ss, ps, 3600)
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t, "sub": SUB,
        "agent": AGENT, "jti": "short", "aud": REC, "scope": None, "exp": t + 58,
        "issuer": ps.issuer}).status == 201
    clock.t += 100
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny"


def test_a_token_spent_when_issued_and_reported_late_completes_nothing_for_certain() -> None:
    # The read is allowed at t with `exp` capped at t + 3600, and issued at t + 3700 under
    # that cap: spent when issued (L508). Reported after a write issued since, it was
    # live at no moment, so read, write, send cannot complete through it for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow" and r.json()["exp"] == int(clock()) + 3600
    t = int(clock())
    clock.t += 3710
    _short_write(ss, ps, 3600)
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t + 3700,
        "sub": SUB, "agent": AGENT, "jti": "spent", "aud": REC, "scope": None,
        "exp": t + 3600, "issuer": ps.issuer}).status == 201
    clock.t += 100
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] != "deny"


@pytest.mark.parametrize(("transit", "want"), [(0, "deny"), (8, "ask")])
def test_a_slow_report_from_a_ps_clock_ahead_is_placed_by_the_ps_s_lead(transit: int,
                                                                      want: str) -> None:
    # The PS's clock 10 s ahead. A write token allowed at t, with the hour the SS caps its
    # `exp` at; a read issued 3 s before that end and the 60 s margin, its report reaching
    # the SS `transit` s after it was signed. The PS's other signatures show its lead, so
    # the read is placed by it, within the token's life, however slow this one report:
    # surely (a deny) when the report is prompt, as may be (an ask) when it is late.
    lead = 10
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t + lead
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    clock.t = t + 3657
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t += transit
    ps.clock = lambda: clock.t + lead - transit  # signed when issued, read on arrival
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    ps.clock = lambda: clock.t + lead
    clock.t = t + 3700
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want


def _new_ss(ss: Any, ps: Any, clock: Any) -> Any:
    # A routing change: a new SS for the same PS, with the same policy, empty.
    fetcher = StaticFetcher()
    ps.install(fetcher)
    key = SigningKey.generate("ss2")
    new = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                         trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                            Policy(ss.policy.cfg), JwksUriResolver(fetcher), key, clock=clock)
    ps.ss_jwk = key.public_jwk()
    return new


@pytest.mark.parametrize(("live", "replayed", "at"), [(20, 0, 3655), (0, 20, 3670)])
def test_a_replay_does_not_place_acts_by_the_ps_s_clock_at_the_replay(live: int,
                                                                      replayed: int,
                                                                      at: int) -> None:
    # A write token allowed at t with the hour the SS caps its `exp` at, a read at t + `at`,
    # the PS's clock `live` s ahead then and `replayed` s ahead when it replays the log to
    # a new SS. Its clock at the replay says nothing of its clock at the acts: at 3655 the
    # write may follow the read (no allow), at 3670 it cannot (no deny); either is asked.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(REC, CHAT, CAL))
    ps.clock = lambda: clock.t + live
    t = clock.t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, CAL).status == 201
    clock.t = t + at
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, REC).status == 201
    clock.t = t + 3800
    ps.clock = lambda: clock.t + replayed
    new = _new_ss(ss, ps, clock)
    ps.replay_to(new, SUB, AGENT)
    _, r, _ = ps.auth_token_request(new, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_an_approval_s_person_token_lives_to_the_exp_the_ps_writes_on_it() -> None:
    # Records serve on a person token alone, and a write followed by a read and a send is
    # prohibited. The PS's clock 30 s ahead: the person token it issues at the approval
    # carries `exp` an hour from its own stamp, which the resource reads; a write at
    # t + 3680 may be followed by a use of it, unreported, so the send is asked.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[],
                             prohibited_sequences=[["write", "read_sensitive", "send_internal"]],
                             high_impact=[], serves_on_identity=[REC])
    ps.clock = lambda: clock.t + 30
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# plan", [REC, CHAT, CAL],
                                     [{"name": "WriteDoc", "description": "x"}])
    assert s256, r.body
    clock.t = t + 3680
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, CAL).status == 201
    clock.t = t + 3800
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_a_write_queued_behind_a_grant_in_its_second_is_not_certain() -> None:
    # The agent asks for ExportRecords at t and writes in that second; the request is
    # granted on delivery in the same second (its `created`), the write's audit queued
    # behind it. Which came first is not settled: the send is asked, not denied.
    rules = [*RULES, {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(CHAT,),
                     tools=[{"name": "WriteDoc", "description": "x"},
                            {"name": "ExportRecords", "description": "x"}])
    t = int(clock()) + 1
    clock.t = t + 0.4
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": t, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "ExportRecords"})
    assert r.json()["decision"] == "allow"
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": t, "sub": SUB,
        "agent": AGENT, "action": "WriteDoc", "mission_s256": s256}).status == 201
    clock.t = t + 60
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] == "ask"


def test_a_stamp_after_its_report_s_signature_is_read_as_that_signature() -> None:
    # A PS that stamps on a clock 30 s ahead of the one it signs with: a read stamped 30 s
    # after its own report's signature took place by that signature. Within the write
    # token's life (with the SS's 60 s margin), so the send would complete: denied.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    clock.t = t + 3657
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    now = int(clock())
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": now + 30,
        "sub": SUB, "agent": AGENT, "jti": "two-clocks", "aud": REC, "scope": None,
        "exp": now + 3600, "issuer": ps.issuer}).status == 201
    clock.t = t + 3700
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny"


def test_an_act_in_a_token_s_last_second_is_not_placed_after_it() -> None:
    # Fractional clocks: the PS's 1.15 s ahead; a read issued a tenth of a second before
    # the write token's end and the 60 s margin, its report signed 0.9 s later and read
    # by the SS 4.8 s after that. Whole-second stamps must not move it past the end.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    lead = 1.15
    ps.clock = lambda: clock.t + lead
    assert ps.connect(ss, SUB).status == 200
    t = float(int(clock()))
    clock.t = t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201   # exp: the cap, t + 3600
    act = t + 3660 - 0.1
    clock.t = act - 5
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    ps.clock = lambda: act + 0.9 + lead          # signed 0.9 s after the act
    clock.t = act + 0.9 + 4.8                    # read by the SS 4.8 s later
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi,
        "iat": int(act + lead), "sub": SUB, "agent": AGENT, "jti": "last-second",
        "aud": REC, "scope": None, "exp": int(act + lead) + 3600,
        "issuer": ps.issuer}).status == 201
    ps.clock = lambda: clock.t + lead
    clock.t = t + 3700
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] != "allow"


def test_a_grant_is_placed_no_earlier_than_a_report_recorded_before_it() -> None:
    # A read's issuance reported at 100.25, then a permission the SS grants at 100.5: where
    # each took place at the latest (`at`) keeps the order they were recorded in, so the
    # later act cannot say a token was live where the earlier one does not.
    rules = [*RULES, {"resource": "*", "tool": "ExportRecords", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = float(int(clock()))
    clock.t = t + 95
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = t + 100.25
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    clock.t = t + 100.5
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "action": "ExportRecords"})
    assert r.json()["decision"] == "allow"
    report, grant = ss.store.history_for(ps.issuer, SUB, AGENT, "")[-2:]
    assert grant.at >= report.at


@pytest.mark.parametrize("transit", [0, 6])
def test_a_ps_whose_every_report_is_slow_is_covered_by_the_transit_allowance(
        transit: int) -> None:
    # The PS's clock 30 s ahead, and every request it sends for the person reaching the
    # SS `transit` s after its signature (a relay): its signatures show its lead short by
    # that much. With a transit allowance that covers it, a read 2 s before the write
    # token's end and the 60 s margin is still placed within the token's life: the send
    # is not allowed.
    lead = 30
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ss.cfg.transit_allowance = 8
    ps.clock = lambda: clock.t - transit + lead   # each request handled `transit` s later

    def at(true: float) -> None:
        clock.t = true + transit

    t = clock.t
    at(t)
    assert ps.connect(ss, SUB).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    exp_cap = int(clock()) + 3600              # the SS's cap, from its decision
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    at(exp_cap + 60 - 2)
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    at(exp_cap + 200)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] != "allow"


def test_a_reconnect_does_not_drop_how_far_ahead_the_ps_ran() -> None:
    # The PS's clock 30 s ahead: a read issued 2 s before the write token's end and the
    # 60 s margin. Its clock then moves back, and the person disconnects and connects
    # again. The read was stamped on the clock as it was, so it is still placed by that
    # lead: within the token's life, the send is not allowed.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    ps.clock = lambda: clock.t + 30
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    clock.t = t + 3658
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, REC).status == 201
    ps.clock = lambda: clock.t
    clock.t = t + 3700
    assert ps.call(ss, "POST", "/connect", {"action": "disconnect", "id": ps.nid("c"),
                                            "iat": int(ps.clock()), "sub": SUB}).status == 200
    assert ps.connect(ss, SUB).status == 200
    clock.t = t + 3800
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] != "allow"


def test_a_ps_that_stamps_on_another_clock_is_read_by_its_stamps_too() -> None:
    # The PS stamps on a clock 30 s ahead of the one it signs with. A read 10 s before
    # the write token's end and the 60 s margin, its report signed 40 s later (an
    # outbox): its stamp is below its signature, so nothing in it shows the stamping
    # clock's lead, but the PS's prompt requests do, and the read is placed by it: within
    # the token's life, the send is not allowed.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = clock.t
    assert ps.call(ss, "POST", "/decision", {      # a prompt request stamped on that clock
        "sdi": ps.nid("d"), "act": "permission", "iat": int(clock()) + 30, "sub": SUB,
        "agent": AGENT, "action": "WebSearch"}).status == 200
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", sdi, CAL).status == 201
    act = t + 3650
    clock.t = act
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = act + 40
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(act) + 30,
        "sub": SUB, "agent": AGENT, "jti": "two-clocks-late", "aud": REC, "scope": None,
        "exp": int(act) + 30 + 3600, "issuer": ps.issuer}).status == 201
    clock.t = t + 3800
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] != "allow"


def test_a_replayed_send_with_an_assumed_class_composes_as_the_class_it_would_have() -> None:
    # A sensitive read, then a mail.send token for an internal recipient, then a routing
    # change: the replayed issuance carries no proposal, so the new SS assumes the send
    # external (`if_unknown`), yet it may be the internal send it was. Live when a write is
    # decided, it may take the last step of read, write, send: the write is asked.
    ss, ps, clock = make_env(transport="forwarded")
    mail, cal = "https://mail.example", "https://calendar.example"
    s256 = connected((ss, ps, clock), resources=(REC, mail, cal))
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, REC, "", prop).status == 201
    clock.t += 5
    send = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "a@corp.example"}}
    sdi, r, prop = ps.auth_token_request(ss, SUB, AGENT, s256, mail, scope="mail.send",
                                         proposal=send)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, s256, sdi, mail, "mail.send", prop).status == 201
    clock.t += 5
    new = _new_ss(ss, ps, clock)
    ps.replay_to(new, SUB, AGENT)
    _, r, _ = ps.auth_token_request(new, SUB, AGENT, s256, cal)
    d = r.json()
    assert d["decision"] == "ask", d
    assert "`read_sensitive`, then `write`, then `send_internal`" in d["summary"]


def test_a_replayed_token_stamped_ahead_of_its_signature_is_placed_by_its_stamp() -> None:
    # The PS stamps on a host 45 s ahead of the clock it signs with (both within the
    # window). A write token whose end the resource reads at t + 175.5, a read issued at
    # t + 170.2, then a routing change at t + 175: the replay is signed before the read's
    # stamp, yet the read is placed anywhere the window allows around that stamp, so it may
    # precede the write's end, and the send at t + 200 is not allowed.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    s256 = connected((ss, ps, clock), resources=(REC, CHAT, CAL))
    t = clock.t

    def issued(sdi: str, aud: str, at: float, life: int) -> None:
        clock.t = t + at
        stamp = int(clock.t) + 45
        assert ps.call(ss, "POST", "/event", {
            "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": stamp,
            "sub": SUB, "agent": AGENT, "jti": ps.nid("at"), "aud": aud, "scope": None,
            "exp": stamp + life, "issuer": ps.issuer, "mission_s256": s256}).status == 201

    clock.t = t + 10
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "allow"
    issued(sdi, CAL, 10.5, 60)
    clock.t = t + 170
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "allow"
    issued(sdi, REC, 170.2, 3600)
    clock.t = t + 175
    new = _new_ss(ss, ps, clock)
    ps.replay_to(new, SUB, AGENT)
    clock.t = t + 200
    _, r, _ = ps.auth_token_request(new, SUB, AGENT, s256, CHAT)
    assert r.json()["decision"] != "allow", r.json()


@pytest.mark.parametrize("audit_at", [None, 5, 201])
def test_a_late_audit_record_never_places_a_token_after_acts_it_ended_before(
        audit_at: int | None) -> None:
    # A write token allowed at t + 15 with an `exp` of t + 20, its issuance reported at
    # t + 202, after a read issued at t + 200 (out of the order L211 asks for); an audit
    # of a local tool stamped `audit_at` and reported at t + 201. The write ended by t + 80
    # with the margin, long before the read, so read, write, send cannot happen in order.
    # An audit record stands where it was reported, not where it was taken: it never
    # moves the write after the read.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    clock.t += 15
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t += 185
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", rsdi, REC).status == 201
    clock.t += 1
    if audit_at is not None:
        assert ps.call(ss, "POST", "/event", {
            "event": "audit.recorded", "id": ps.nid("e"), "iat": t + audit_at, "sub": SUB,
            "agent": AGENT, "action": "ReadFile"}).status == 201
    clock.t += 1
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": t + 15,
        "sub": SUB, "agent": AGENT, "jti": "late", "aud": CAL, "scope": None, "exp": t + 20,
        "issuer": ps.issuer}).status == 201
    clock.t += 10
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "allow"


def _search(ss: Any, ps: Any, clock: Any) -> None:
    # A permission for a tool no rule classes, granted where it is asked: an act stamped
    # at its request, of no class any prohibited sequence names.
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "action": "WebSearch"})
    assert r.json()["decision"] == "allow"


def _late_issuance(ss: Any, ps: Any, sdi: str, aud: str, iat: int, exp: int) -> None:
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": iat, "sub": SUB,
        "agent": AGENT, "jti": ps.nid("at"), "aud": aud, "scope": None, "exp": exp,
        "issuer": ps.issuer}).status == 201


def _read_file(ss: Any, ps: Any, iat: int) -> None:
    assert ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": iat, "sub": SUB,
        "agent": AGENT, "action": "ReadFile"}).status == 201


@pytest.mark.parametrize("audit_at", [None, 5, 12, 100])
def test_a_late_audit_record_does_not_unsettle_what_the_stamps_settle(
        audit_at: int | None) -> None:
    # A read token issued at t + 10 and still live; a write token allowed at t + 15 with an
    # `exp` of t + 20, its issuance reported at t + 202, after a search stamped t + 200 (out
    # of the order Supervision L211 asks for); an audit of a local tool stamped `audit_at`
    # and reported at t + 201. The write was live after the read and ended before the
    # search, wherever the audit stands: read, write, send completes for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    clock.t = t + 10
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", rsdi, REC).status == 201
    clock.t = t + 15
    wsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t = t + 200
    _search(ss, ps, clock)
    clock.t = t + 201
    if audit_at is not None:
        _read_file(ss, ps, t + audit_at)
    clock.t = t + 202
    _late_issuance(ss, ps, wsdi, CAL, t + 15, t + 20)
    (w,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.resource == CAL)
    assert w.unplaced
    clock.t = t + 212
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny", r.json()


def test_a_token_reported_late_precedes_an_audit_stamped_after_it_for_certain() -> None:
    # A write token allowed at t + 15 with an `exp` of t + 20, its issuance reported at
    # t + 202, after an audit of ReadFile (here a sensitive read) stamped t + 20 and
    # reported at once. An audit logs an action after it is performed (Protocol L1245),
    # at any moment up to its stamp, and the write was issued in an earlier second: write,
    # read, send completes for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"},
             {"resource": "*", "tool": "ReadFile", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], high_impact=[],
                             prohibited_sequences=[["write", "read_sensitive", "send_internal"]])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    clock.t = t + 15
    wsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t = t + 20
    _read_file(ss, ps, t + 20)
    clock.t = t + 202
    _late_issuance(ss, ps, wsdi, CAL, t + 15, t + 20)
    (w,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.resource == CAL)
    assert w.unplaced
    clock.t = t + 212
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny", r.json()


def test_a_token_reported_late_precedes_a_late_audit_stamped_after_it_for_certain() -> None:
    # A search at t; a write token allowed at t + 5, issued at t + 10 with an `exp` of
    # t + 20; an audit of ReadFile (here a sensitive read) stamped t + 15; a search at
    # t + 100; then the audit, and then the write's issuance, reported. The write was
    # issued in an earlier second than the audit's stamp, and between the same two
    # searches: write, read, send completes for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"},
             {"resource": "*", "tool": "ReadFile", "class": "read_sensitive"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], high_impact=[],
                             prohibited_sequences=[["write", "read_sensitive", "send_internal"]])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    _search(ss, ps, clock)
    clock.t = t + 5
    wsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t = t + 100
    _search(ss, ps, clock)
    clock.t = t + 101
    _read_file(ss, ps, t + 15)
    clock.t = t + 102
    _late_issuance(ss, ps, wsdi, CAL, t + 10, t + 20)
    (w,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.resource == CAL)
    assert w.unplaced
    clock.t = t + 200
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny", r.json()


def test_a_token_reported_late_does_not_reach_back_to_a_token_that_ended_before_it() -> None:
    # A write token issued at t with an `exp` of t + 50 (t + 110 with the margin), a search
    # at t + 100 while it was live, a read allowed at t + 150 and issued at t + 200 with an
    # `exp` of t + 220, its issuance reported after a search stamped t + 900. The read was
    # issued after the write had ended: read, write, send cannot complete for certain.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    _short_write(ss, ps, 50)
    clock.t = t + 100
    _search(ss, ps, clock)
    clock.t = t + 150
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = t + 900
    _search(ss, ps, clock)
    clock.t = t + 901
    _late_issuance(ss, ps, rsdi, REC, t + 200, t + 220)
    (rd,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.resource == REC)
    assert rd.unplaced
    clock.t = t + 1000
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    # Read loosely the read floats to just after the search at t + 100, where the write
    # may still have been live: asked, not denied.
    assert r.json()["decision"] == "ask", r.json()


@pytest.mark.parametrize(("seq", "want"), [(["read_sensitive", "write", "send_internal"], "ask"),
                                           (["write", "read_sensitive", "send_internal"], "deny")])
def test_two_tokens_reported_late_keep_the_order_of_their_stamps(seq: list[str],
                                                                 want: str) -> None:
    # A write token issued at t with an `exp` of t + 20 (t + 80 with the margin) and a read
    # issued at t + 150, both reported after a search stamped t + 500. The write ended
    # before the read was issued: write, then read, completes for certain; read, then
    # write, cannot complete for certain, but read loosely both float, so it is asked.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=[seq],
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    wsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t = t + 100
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = t + 500
    _search(ss, ps, clock)
    clock.t = t + 501
    _late_issuance(ss, ps, wsdi, CAL, t, t + 20)
    clock.t = t + 502
    _late_issuance(ss, ps, rsdi, REC, t + 150, t + 170)
    assert all(h.unplaced for h in ss.store.history_for(ps.issuer, SUB, AGENT, "")
               if h.resource in (CAL, REC))
    clock.t = t + 600
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want, r.json()


@pytest.mark.parametrize("audit_at", [None, 5, 201])
def test_a_late_audit_record_does_not_move_a_token_past_acts_it_outlived(
        audit_at: int | None) -> None:
    # A write token allowed at t + 15 with an `exp` of t + 250 (t + 310 with the margin),
    # its issuance reported at t + 202, after a read issued at t + 200; an audit of a local
    # tool stamped `audit_at` and reported at t + 201. The write was live when the read
    # was issued: read, write, send completes for certain, wherever the audit stands.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    clock.t = t + 15
    wsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CAL)
    assert r.json()["decision"] == "allow"
    clock.t = t + 200
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    assert ps.issued(ss, SUB, AGENT, "", rsdi, REC).status == 201
    clock.t = t + 201
    if audit_at is not None:
        _read_file(ss, ps, t + audit_at)
    clock.t = t + 202
    _late_issuance(ss, ps, wsdi, CAL, t + 15, t + 250)
    clock.t = t + 400
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "deny", r.json()


@pytest.mark.parametrize(("read_iat", "want"), [(30, "deny"), (78, "ask")])
def test_a_token_surely_live_when_a_late_token_was_issued_follows_it(read_iat: int,
                                                                      want: str) -> None:
    # A write token issued at t with an `exp` of t + 20 (t + 80 with the margin), a read
    # allowed at t + 10 and issued at `read_iat`, its issuance reported after a search
    # stamped t + 100. Issued at t + 30, the read came while the write was surely live:
    # read, write, send completes for certain. Issued at t + 78, the write may have ended.
    rules = [*RULES, {"resource": CAL, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())
    _short_write(ss, ps, 20)
    clock.t = t + 10
    rsdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    clock.t = t + 100
    _search(ss, ps, clock)
    clock.t = t + 101
    _late_issuance(ss, ps, rsdi, REC, t + read_iat, t + read_iat + 20)
    (rd,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, "") if h.resource == REC)
    assert rd.unplaced
    clock.t = t + 300
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == want, r.json()


@pytest.mark.parametrize("step", [0, 50])
def test_a_token_decided_after_an_act_was_reported_never_precedes_it_for_certain(
        step: int) -> None:
    # A write audited at t + 10; then the PS's clock steps back `step` s (within the
    # signature window). A read token allowed at t + 20, whose issuance (stamped by the
    # stepped clock) is reported at t + 26, after a ReadFile audited since. The read was
    # decided after the write was reported, so it came after it, whatever the stamps say:
    # read, write, send cannot complete, and the send is allowed.
    rules = [*RULES, {"resource": "*", "tool": "ReadFile", "class": "read"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], prohibited_sequences=SEQ,
                             high_impact=[])
    assert ps.connect(ss, SUB).status == 200
    t = int(clock())

    def audit(tool: str) -> None:
        assert ps.call(ss, "POST", "/event", {
            "event": "audit.recorded", "id": ps.nid("e"), "iat": int(ps.clock()),
            "sub": SUB, "agent": AGENT, "action": tool}).status == 201

    clock.t = t + 10
    audit("WriteDoc")
    ps.clock = lambda: clock.t - step
    clock.t = t + 20
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    assert r.json()["decision"] == "allow"
    issued = int(ps.clock()) + 1
    clock.t = t + 25
    audit("ReadFile")
    clock.t = t + 26
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": issued,
        "sub": SUB, "agent": AGENT, "jti": "rd", "aud": REC, "scope": None,
        "exp": issued + 3600, "issuer": ps.issuer}).status == 201
    clock.t = t + 30
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", CHAT)
    assert r.json()["decision"] == "allow", r.json()
