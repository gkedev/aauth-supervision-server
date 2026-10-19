"""`iat` as Supervision L198 gives it: "seconds since the epoch", any JSON number.

The draft says no more, so a PS may stamp `1790600000.9` or write `1.7906e9`. The SS takes
any finite number of at most 2^53 - 1 either way (I-JSON, RFC 7493 Section 2.2), as it takes
`exp`, a JWT NumericDate. It reads the stamp as the whole second it falls in,
wherever the stamp places or orders an act, and keeps it so: a request stamped
`1790600000.9` is decided, placed and ordered as one stamped `1790600000`. Three readings
see the number as sent: the idempotence fingerprint (L316: a retry keeps its `iat`, L198,
so one that differs below the second is another request), whether a reported `exp` came
before the act (a token expired when issued), and the end of a token the PS issues an
hour from its stamp at approval (rounded up, as `exp` is).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, ROOT, SUB, connected, make_env
from test_conformance_rows import TAKEN, _requests

from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message
from aauth_supervision_server.service import APPROVAL_DETAIL
from aauth_supervision_server.store import UNBOUNDED_EXP, Store

X = 1_790_600_000  # the test clock's start
HR, MAIL, REC = "https://hr.example", "https://mail.example", "https://records.example"
UNLISTED = "https://unlisted.example"
EXTERNAL_SEND = {"action": "SendEmail", "parameters": {"to": "drop@evil.example"}}
NUMBER = "member 'iat' must be a finite JSON number of at most 2**53 - 1 either way"


def _fractional(ps: Any, frac: float) -> None:
    """Every request the simulated PS sends from now on stamps `frac` past its whole
    second: the stamps an integer-stamping PS sends, with a fraction added."""
    build = ps.build

    def with_fraction(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if body is not None and isinstance(body.get("iat"), int) and frac:
            body = body | {"iat": body["iat"] + frac}
        return build(method, path, body)
    ps.build = with_fraction


def _raw(ss: Any, ps: Any, clock: Any, path: str, raw: bytes) -> Any:
    """A request whose body is sent as written, signed: a number JSON writes in a form
    `json.dumps` never produces (an exponent, NaN, Infinity) reaches the SS as such."""
    req = HttpRequest("POST", "ss.example", path,
                      {"content-type": "application/json", "content-digest": content_digest(raw)},
                      raw)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    h = sign_message(["@method", "@authority", "@path", "signature-key", "content-digest",
                      "content-type"], ps.key, sk, req, created=int(clock()))
    req.headers.update({k.lower(): v for k, v in h.items()})
    return ss.handle(req)


def _audit(ps: Any, iat: Any, mission: str = "") -> dict[str, Any]:
    body = {"event": "audit.recorded", "id": ps.nid("e"), "iat": iat, "sub": SUB,
            "agent": AGENT} | EXTERNAL_SEND
    return body | ({"mission_s256": mission} if mission else {})


def _audit_raw(ps: Any, written: bytes) -> bytes:
    head = json.dumps(_audit(ps, 0), separators=(",", ":")).encode()
    return head.replace(b'"iat":0', b'"iat":' + written)


def _entries(ss: Any) -> list[tuple[Any, ...]]:
    """Every act in the SS's history, with what places and orders it."""
    lists = [m.history for m in ss.store.missions.values()] + list(
        ss.store.agent_history.values())
    return sorted((h.n, h.action_class, h.resource, h.at, h.iat, h.wide, h.after_n, h.unplaced,
                   h.token_exp, h.detail, h.sdi) for hist in lists for h in hist)


# ------------------------------------------------------------------ taken everywhere


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("name", sorted(TAKEN))
def test_a_fractional_iat_is_taken_on_every_endpoint(name: str) -> None:
    # Supervision L198: "seconds since the epoch". A fraction is seconds too: the request
    # is taken as the same request stamped with a whole number is.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    path, body = _requests(ps, s256, X + 0.9)[name]
    r = ps.call(ss, "POST", path, body)
    assert r.status == TAKEN[name], (name, r.body)


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("written", [b"NaN", b"Infinity", b"-Infinity", b"1e400",
                                     b"9007199254740992", b"-9.007199254740992e15"])
def test_an_event_with_no_finite_time_is_refused_and_nothing_is_recorded(
        written: bytes) -> None:
    # Python's JSON reader takes NaN and Infinity, which are no JSON numbers (RFC 8259
    # Section 6), and reads 1e400 as Infinity. None is a time; nor is a number past the
    # integers every JSON parser holds exactly. The refusal says what is required, and the
    # event changes nothing (`tests/test_conformance.py` holds the same for a connect).
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    r = _raw(ss, ps, clock, "/event", _audit_raw(ps, written))
    assert (r.status, json.loads(r.body)["detail"]) == (400, NUMBER)
    assert ss.store.history_for(ps.issuer, SUB, AGENT, "") == []


@pytest.mark.parametrize("member", ["iat", "exp"])
def test_a_time_member_out_of_range_says_what_is_required(member: str) -> None:
    # `iat` and `exp` are both times: one rule, one refusal that says it.
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    body = {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-replayed",
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": "j", "aud": HR,
            "exp": int(clock()) + 60} | {member: 2 ** 53}
    r = ps.call(ss, "POST", "/event", body)
    assert (r.status, r.json()["detail"]) == (
        400, f"member {member!r} must be a finite JSON number of at most 2**53 - 1 either way")
    assert ss.store.history_for(ps.issuer, SUB, AGENT, "") == []


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("iat, read", [(2 ** 53 - 1, 2 ** 53 - 1), (-(2 ** 53 - 1), -(2 ** 53 - 1)),
                                       (float(2 ** 53 - 1), 2 ** 53 - 1), (X + 0.999, X),
                                       (-0.5, -1)])
def test_an_iat_at_the_edge_of_the_range_is_taken_and_kept_as_its_floor(iat: Any,
                                                                         read: int) -> None:
    # Read down to the second it falls in, never toward zero: -0.5 is in the second that
    # starts at -1.
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    assert ps.call(ss, "POST", "/event", _audit(ps, iat)).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    assert h.iat == read and type(h.iat) is int


# ------------------------------------------------------------------ read as its whole second


def _scenario(frac: float) -> tuple[list[Any], list[tuple[Any, ...]], dict[str, Any]]:
    """One person's acts across every endpoint and event that reads `iat`, each stamped
    `frac` past its whole second: the answers, the history, and what the SS kept."""
    ss, ps, clock = make_env(serves_on_identity=[REC])
    _fractional(ps, frac)
    answers: list[Any] = []

    def call(path: str, body: dict[str, Any]) -> Any:
        r = ps.call(ss, "POST", path, body)
        answers.append((path, r.status, r.json().get("decision") if r.status == 200 else None))
        return r

    s256 = connected((ss, ps, clock))
    clock.t += 1  # a permission, granted by the SS: the grant joins the history
    call("/decision", {"sdi": "d-perm", "act": "permission", "iat": int(clock()), "sub": SUB,
                       "agent": AGENT, "mission_s256": s256, "action": "WebSearch",
                       "parameters": {"q": "x"}})
    clock.t += 1  # an auth token, allowed then reported issued
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, HR)
    answers.append(r.json()["decision"])
    clock.t += 1
    assert ps.issued(ss, SUB, AGENT, s256, sdi, HR).status == 201
    clock.t += 1  # the agent's own record of an external send, stamped ahead of its report
    call("/event", _audit(ps, int(clock()) + 3, s256))
    clock.t += 1  # an ask, then the person's answer
    ask, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, UNLISTED)
    answers.append(r.json()["decision"])
    clock.t += 1
    assert ps.resolved(ss, SUB, AGENT, s256, ask, "allow").status == 201
    clock.t += 1  # an external send the SS does not allow, which the person grants
    call("/decision", {"sdi": "d-send", "act": "permission", "iat": int(clock()), "sub": SUB,
                       "agent": AGENT} | EXTERNAL_SEND)
    clock.t += 1
    assert ps.resolved(ss, SUB, AGENT, "", "d-send", "allow").status == 201
    clock.t += 1  # a token of a decision this SS never made (a replay)
    call("/event", {"event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-old",
                    "iat": int(clock()) - 400, "sub": SUB, "agent": AGENT, "jti": "j-old",
                    "aud": MAIL, "exp": int(clock()) + 600})
    clock.t += 1  # a person token reported with no decision
    call("/event", {"event": "person_token.issued", "id": ps.nid("e"), "iat": int(clock()),
                    "sub": SUB, "agent": AGENT, "jti": "p-1", "aud": REC,
                    "exp": int(clock()) + 3600})
    clock.t += 1
    call("/event", {"event": "agent.bound", "id": ps.nid("e"), "iat": int(clock()),
                    "sub": SUB, "agent": AGENT, "agent_iss": "https://agent.example",
                    "agent_sub": AGENT})
    clock.t += 1  # the read the history above bears on
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
    answers.append(r.json()["decision"])
    kept = {"decisions": {k: (v.decision, v.resolved_n, v.recorded_n)
                          for k, v in ss.store.decisions.items()},
            "agents": ss.store.agents, "leads": ss.store.leads}
    return answers, _entries(ss), kept


@pytest.mark.req("SUP-014")
def test_a_request_stamped_with_a_fraction_is_decided_as_its_whole_second() -> None:
    # A request at 1790600000.9 composes and orders as one at 1790600000: every act is
    # placed, ordered and kept as the same acts stamped with whole numbers are.
    answers, entries, kept = _scenario(0.9)
    assert (answers, entries, kept) == _scenario(0.0)
    assert all(type(e[4]) is int for e in entries)  # a stamp the SS keeps is an integer
    # Each kind of act was recorded: a grant at the SS's answer, an issued token, an audit
    # record, a grant at the person's answer, a replayed token, a person token reported.
    by_sdi = {e[10]: e for e in entries}
    assert {"d-perm", "d-send", "d-old"} <= set(by_sdi)
    assert by_sdi["d-old"][5]  # wide: a replay
    details = [e[9] for e in entries]
    assert "audit record" in details and "uncertain: person token" in details
    assert "resolved_allow" in {d for d, _, _ in kept["decisions"].values()}
    assert answers[-1] != "allow"  # the read the external sends bear on


@pytest.mark.req("SUP-014")
def test_a_stamp_kept_from_a_fraction_survives_a_restart(tmp_path: Path) -> None:
    snap = tmp_path / "ss.json"
    ss, ps, clock = make_env()
    ss.store = Store(str(snap))
    _fractional(ps, 0.75)
    s256 = connected((ss, ps, clock))
    assert ps.call(ss, "POST", "/event", _audit(ps, int(clock()), s256)).status == 201
    again = Store(str(snap))
    assert not again.load_error
    (h,) = again.missions[Store.k(ps.issuer, s256)].history
    assert h.iat == X and type(h.iat) is int


def test_an_answer_in_the_second_of_an_act_recorded_since_is_not_placed_after_it() -> None:
    # The act recorded since the ask was stamped 1790600005.2 and is kept as 1790600005.
    # The answer stamped 1790600005.9 is read as 1790600005 too: which came first is not
    # settled, so its token may follow the ask only. Read as sent, the answer would be
    # placed after an act that may have followed it (one stamped 1790600005.95 is kept as
    # 1790600005 all the same).
    for stamp, late in ((X + 5.9, True), (X + 6, False)):
        ss, ps, clock = make_env()
        s256 = connected((ss, ps, clock))
        ask, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, UNLISTED)
        assert r.json()["decision"] == "ask"
        clock.t += 5
        assert ps.call(ss, "POST", "/event", _audit(ps, X + 5.2, s256)).status == 201
        clock.t += 1
        assert ps.call(ss, "POST", "/event", {
            "event": "decision.resolved", "id": ps.nid("e"), "sdi": ask, "iat": stamp,
            "sub": SUB, "agent": AGENT, "mission_s256": s256, "answer": "allow"}).status == 201
        assert (ss.store.decisions[Store.k(ps.issuer, ask)].resolved_n == 0) is late, stamp


def test_the_ps_lead_reads_a_fractional_stamp() -> None:
    # A PS that stamps on a clock 20.7 s ahead of the one it signs with: its lead is read
    # from the stamp, as the whole second it is in, as an integer stamp 20 s ahead would
    # be. One past the signature window still moves nothing.
    ss, ps, clock = make_env()
    connected((ss, ps, clock), resources=(HR,))
    before = ss.store.lead_of(ps.issuer)
    assert before is not None and before < 20
    for stamp, lead in ((X + 3600.5, before), (X + 20.7, 20.0), (X + 10.5, 20.0)):
        assert ps.call(ss, "POST", "/event", _audit(ps, stamp)).status == 201
        assert ss.store.lead_of(ps.issuer) == lead, stamp


# ------------------------------------------------------------------ read as sent


@pytest.mark.req("SUP-014", "SUP-028")
def test_a_retry_keeps_its_fractional_iat_and_one_that_differs_below_the_second_is_refused(
        ) -> None:
    # L198: on a retried request `iat` "is unchanged". The identical request under its sdi
    # gets the same signed answer (L316); one whose `iat` differs, if only below the
    # second or in being written as an integer, is another request reusing the sdi.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    body = {"sdi": "d-r", "act": "permission", "iat": X + 0.9, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "action": "WebSearch", "parameters": {"q": "x"}}
    first = ps.call(ss, "POST", "/decision", body)
    assert first.status == 200 and first.json()["decision"] == "allow"
    clock.t += 10
    again = ps.call(ss, "POST", "/decision", body)
    assert (again.status, again.body, again.headers["Signature"]) == (
        200, first.body, first.headers["Signature"])
    for other in (X + 0.4, X, X + 1):
        r = ps.call(ss, "POST", "/decision", body | {"iat": other})
        assert (r.status, r.json()["detail"]) == (
            400, "sdi already used for a different request"), other


def test_a_replayed_token_whose_exp_came_before_its_fractional_stamp_never_expires() -> None:
    # Reported as expiring at .5 of the second it was issued in at .9: expired when issued,
    # so not what was issued (a lifetime sent as `exp`, or a slip). Read against the stamp
    # as sent; against its whole second it would be a token spent a moment later.
    ss, ps, clock = make_env()
    assert ps.connect(ss, SUB).status == 200
    assert ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-old", "iat": X + 0.9,
        "sub": SUB, "agent": AGENT, "jti": "j", "aud": HR, "exp": X + 0.5}).status == 201
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, "")
    assert (h.iat, h.token_exp) == (X, UNBOUNDED_EXP)


@pytest.mark.parametrize("frac, end", [(0.0, X + 3600), (0.9, X + 3601)])
def test_an_approval_token_ends_an_hour_from_the_stamp_rounded_up(frac: float,
                                                                   end: int) -> None:
    # The PS writes the hour from its approval's stamp on the token (Protocol L863): an
    # end is never read as earlier than the stamp allows, as `exp` is rounded up. The
    # stamp itself places the act, as its whole second.
    ss, ps, clock = make_env(serves_on_identity=[REC])
    assert ps.connect(ss, SUB).status == 200
    _fractional(ps, frac)
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# read the records", [REC])
    assert r.json()["decision"] == "allow"
    (h,) = ss.store.missions[Store.k(ps.issuer, s256)].history
    assert h.detail == APPROVAL_DETAIL
    assert (h.iat, h.at, h.token_exp) == (X, X, end)


# ------------------------------------------------------------------ a fractional stamp in a composition


def test_an_external_send_audited_with_a_fractional_iat_bears_on_the_read_after_it() -> None:
    # Under the example policy, reading sensitive records after an external send is a
    # composition it never allows. The agent's record of the send, stamped with a
    # fraction, must be taken: the PS does not retry `invalid_request` (L631), so a refusal
    # would let the read through as if the send had not happened.
    policy = json.loads((ROOT / "examples" / "policy.json").read_text())
    answers = []
    for audited in (False, True):
        ss, ps, clock = make_env(**policy)
        assert ps.connect(ss, SUB).status == 200
        if audited:
            assert ps.call(ss, "POST", "/event", _audit(ps, clock() + 0.25)).status == 201
        clock.t += 5
        _, r, _ = ps.auth_token_request(ss, SUB, AGENT, "", REC)
        answers.append(r.json()["decision"])
    assert answers[0] == "allow" and answers[1] in ("ask", "deny"), answers


@pytest.mark.req("SUP-028")
@pytest.mark.parametrize(("first", "again"), [(X, float(X)), (float(X), X), (X + 0.5, X + 0.5)])
def test_a_retry_writing_the_same_iat_in_another_form_is_the_same_request(
        first: Any, again: Any) -> None:
    # JSON has one number type (RFC 8259 Section 6): `1790600000` and `1790600000.0` are the
    # same `iat`, so a retry that writes it either way is the same request and gets the
    # same answer (L316); a PS whose writer changes the form between tries is not refused
    # for it. The answer is signed over the request it answers (`;req`), so its signature
    # is that of this retry's bytes.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    body = {"sdi": "d-f", "act": "permission", "iat": first, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "action": "WebSearch", "parameters": {"q": "x"}}
    one = ps.call(ss, "POST", "/decision", body)
    assert one.status == 200
    clock.t += 10
    two = ps.call(ss, "POST", "/decision", body | {"iat": again})
    assert (two.status, two.body) == (200, one.body)
