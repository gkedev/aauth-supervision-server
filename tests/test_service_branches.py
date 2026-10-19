"""The service paths no other suite reaches, each pinned to its observable effect.

Malformed bodies, unsigned operation, Accept-Signature fallbacks, policy answers with no
optional members, R3 decoding errors, late and repeated pending operations, the events
the SS only acknowledges. Among them:

* a non-UTF-8 R3 proposal is a 400, never a 500;
* the clarification `timeout` the SS states is enforced (SUP-P15);
* a DELETE after a clarification was answered leaves the answer, so the person's later
  `decision.resolved` still counts (SUP-P17).
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.errors import ProtocolError
from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message
from aauth_supervision_server.jwk import b64u
from aauth_supervision_server.policy import Decision, Policy
from aauth_supervision_server.service import ServerConfig, _check_member_types, _decode_jwt_claims
from aauth_supervision_server.store import HistoryEntry, Store, StoredResponse
from aauth_supervision_server.testing import ACCEPT_SIG, r3_bytes

MAIL = "https://mail.example"


def clarify_env(**over: Any) -> tuple[Any, Any, Any, str]:
    ss, ps, c = make_env(clarify_missing_justification=True, **over)
    return ss, ps, c, connected((ss, ps, c))


def ask_clarification(ss: Any, ps: Any, s256: str) -> tuple[str, str]:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202
    return sdi, r.headers["Location"]


def signed_raw(ps: Any, body: bytes, ctype: str, path: str = "/connect") -> HttpRequest:
    """A correctly signed request whose body the SS must still refuse."""
    req = HttpRequest("POST", ps.ss_authority, path,
                      {"accept-signature": ACCEPT_SIG, "content-type": ctype,
                       "content-digest": content_digest(body)}, body)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    h = sign_message(["@method", "@authority", "@path", "signature-key", "content-digest",
                      "content-type"], ps.key, sk, req, created=int(ps.clock()))
    req.headers.update({k.lower(): v for k, v in h.items()})
    return req


class Scripted(Policy):
    """The APC policy, except for answers a test scripts (a pluggable policy may give
    any well-formed Decision, including ones without the optional members)."""

    def __init__(self, base: Policy, proposal: Decision | None = None,
                 decision: Decision | None = None) -> None:
        super().__init__(base.cfg)
        self._proposal, self._decision = proposal, decision

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        return self._proposal or super().decide_proposal(body, now)

    def decide(self, *a: Any, **k: Any) -> Decision:
        return self._decision or super().decide(*a, **k)


# ------------------------------------------------------------ configuration, members


def test_server_config_requires_an_issuer() -> None:
    with pytest.raises(ValueError, match="^server config: issuer is required$"):
        ServerConfig.from_dict({})


@pytest.mark.parametrize("member,value,ok", [
    ("signature_window", 30, True), ("signature_window", True, False),
    ("signature_window", "30", False), ("signature_window", -1, False),
    ("open_registration", True, True), ("open_registration", 1, False),
    ("name", "SS", True), ("name", 5, False),
])
def test_server_config_member_types(member: str, value: Any, ok: bool) -> None:
    """A bool is not an int here (`True` is not a 1-second window), and a bool member
    takes a bool."""
    d = {"issuer": "https://ss.example", member: value}
    if ok:
        assert getattr(ServerConfig.from_dict(d), member) == value
    else:
        with pytest.raises(ValueError, match=f"^server config: {member} "):
            ServerConfig.from_dict(d)


def test_aud_is_a_string_or_an_array_of_strings() -> None:
    _check_member_types({"aud": "https://r.example"})
    _check_member_types({"aud": ["https://r.example", "https://s.example"]})
    for bad in (5, ["https://r.example", 5], {"a": 1}):
        with pytest.raises(ProtocolError) as e:
            _check_member_types({"aud": bad})
        assert e.value.detail == "member 'aud' has the wrong JSON type"


def test_a_forwarded_token_whose_payload_is_not_an_object() -> None:
    with pytest.raises(ProtocolError) as e:
        _decode_jwt_claims("x." + b64u(b"[1]") + ".y")
    assert e.value.detail == "forwarded token payload is not an object"


@pytest.mark.parametrize("payload", ["a=b", b64u(b"{"), b64u(b"\xff")])
def test_a_forwarded_token_whose_payload_is_not_json(payload: str) -> None:
    with pytest.raises(ProtocolError) as e:
        _decode_jwt_claims(f"x.{payload}.y")
    assert (e.value.status, e.value.detail) == (400, "forwarded token payload is not JSON")


@pytest.mark.parametrize("body,ctype,detail", [
    (b'{"action":"connect"}', "text/plain", "body must be application/json"),
    (b"{", "application/json", "body is not JSON"),
    (b"\xff\xfe", "application/json", "body must be UTF-8 JSON with no byte order mark"),
    (b"[1]", "application/json", "body is not a JSON object"),
])
def test_a_signed_body_that_is_not_a_json_object_is_refused(body: bytes, ctype: str,
                                                            detail: str) -> None:
    ss, ps, _ = make_env()
    r = ss.handle(signed_raw(ps, body, ctype))
    assert r.status == 400 and r.json() == {"error": "invalid_request", "detail": detail}


def test_a_json_media_type_with_parameters_is_json() -> None:
    ss, ps, _ = make_env()
    body = json.dumps({"action": "connect", "id": "c-1", "iat": 1, "sub": SUB}).encode()
    r = ss.handle(signed_raw(ps, body, "Application/JSON; charset=utf-8"))
    assert r.status == 200


# ------------------------------------------------------------ signing


def test_an_ss_without_a_key_answers_unsigned() -> None:
    ss, ps, _ = make_env(sign=False)
    r = ps.connect(ss, SUB)
    assert r.status == 200 and r.body
    assert not {"Signature", "Signature-Input", "Content-Digest"} & set(r.headers)


def test_accept_signature_label_is_used_even_without_a_component_list() -> None:
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB})
    req.headers["accept-signature"] = "mine=:YWJj:"  # a byte sequence, not an inner list
    r = ss.handle(req)
    assert r.headers["Signature-Input"].startswith(
        'mine=("@status" "content-type" "content-digest" "content-digest";req '
        '"@authority";req "@path";req)')


@pytest.mark.parametrize("accept", ["sig=(", ""])
def test_unusable_accept_signature_falls_back_to_the_default(accept: str) -> None:
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB})
    req.headers["accept-signature"] = accept
    r = ss.handle(req)
    assert r.status == 200
    assert r.headers["Signature-Input"].startswith(
        'sig=("@status" "content-type" "content-digest" "content-digest";req')


def test_a_requested_component_that_cannot_be_covered_keeps_the_request_binding() -> None:
    # RFC 9421 Section 5.2: a requested component that does not apply fails that request.
    # The answer is still signed (Supervision L320), and over the `;req` components L340
    # says it SHOULD cover: one bad component does not drop them all, so the signed
    # decision stays bound to the request it answers.
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB})
    req.headers["accept-signature"] = 'sig=("@status" "@unknown-derived";req)'
    r = ss.handle(req)
    assert r.status == 200
    assert r.headers["Signature-Input"].startswith(
        'sig=("@status" "content-type" "content-digest" "content-digest";req '
        '"@authority";req "@path";req);')


def test_a_stored_answer_without_a_body_is_redelivered_as_is() -> None:
    ss, ps, _ = make_env()
    req = ps.build("GET", "/pending/x")
    r = ss._replay(req, StoredResponse(204, {"X-Kept": "1"}, ""))
    assert r.status == 204 and r.headers == {"X-Kept": "1"} and r.body == b""


def test_only_a_200_with_a_body_is_signed_on_redelivery() -> None:
    """The same rule as every live answer: a non-200 is never a signed decision."""
    ss, ps, _ = make_env()
    req = ps.build("GET", "/pending/x")
    r = ss._replay(req, StoredResponse(403, {"Content-Type": "application/json"}, '{"a":1}'))
    assert r.status == 403 and "Signature" not in r.headers
    signed = ss._replay(req, StoredResponse(200, {"Content-Type": "application/json"}, "{}"))
    assert "Signature" in signed.headers


def test_pending_ids_carry_128_bits() -> None:
    """Pending URLs are capabilities scoped to the PS (L286): unguessable, 16 random bytes."""
    from aauth_supervision_server.jwk import b64u_decode

    ss, ps, _ = make_env(auto_connect=False)
    loc = ps.connect(ss, SUB).headers["Location"]
    assert len(b64u_decode(loc.rsplit("/", 1)[1])) == 16
    ss2, ps2, _, s256 = clarify_env()
    _, loc2 = ask_clarification(ss2, ps2, s256)
    assert len(b64u_decode(loc2.rsplit("/", 1)[1])) == 16


@pytest.mark.parametrize("entry,ok", [
    ({}, True), ({"auto_connect": True}, True), ({"tenants": ["t1"]}, True),
    ({"auto_connect": None}, False), ({"auto_connect": 1}, False),
    ({"tenants": "t1"}, False), ({"tenants": [1]}, False), ({"tenants": None}, False),
])
def test_trusted_ps_member_types(entry: dict[str, Any], ok: bool) -> None:
    d = {"issuer": "https://ss.example", "trusted_ps": {"https://ps.example": entry}}
    if ok:
        tp = ServerConfig.from_dict(d).trusted_ps["https://ps.example"]
        assert tp.auto_connect is entry.get("auto_connect", False)
        assert tp.tenants == entry.get("tenants", [])
    else:
        with pytest.raises(ValueError, match="has the wrong types$"):
            ServerConfig.from_dict(d)


# ------------------------------------------------------------ missions


def propose(ss: Any, ps: Any) -> Any:
    return ps.call(ss, "POST", "/mission", {
        "sdi": ps.nid("d"), "iat": 1, "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "x", "tools": [],
        "resources": [MAIL]})


def test_a_proposal_ask_without_a_refinement_carries_no_proposed() -> None:
    ss, ps, _ = make_env()
    ps.connect(ss, SUB)
    ss.policy = Scripted(ss.policy, proposal=Decision("ask", summary="Check with me."))
    assert propose(ss, ps).json() == {"sdi": ps.sent[-1][1]["sdi"], "decision": "ask",
                                      "summary": "Check with me.",
                                      "apply_options": [{"value": "once", "label": "This proposal only"}]}


def test_a_proposal_deny_without_a_reason_carries_no_reason() -> None:
    ss, ps, _ = make_env()
    ps.connect(ss, SUB)
    ss.policy = Scripted(ss.policy, proposal=Decision("deny"))
    assert propose(ss, ps).json() == {"sdi": ps.sent[-1][1]["sdi"], "decision": "deny"}


@pytest.mark.parametrize("mission", ["a=b", b64u(b"not json")])
def test_an_approved_mission_must_be_base64url_json(mission: str) -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    s256 = "A" * 43
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "iat": 1, "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": mission})
    assert r.status == 400 and r.json()["detail"] == "mission is not base64url JSON"


def test_a_second_approval_of_a_known_mission_does_not_reset_it() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    _, raw = ps._last_blob
    assert ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "terminated", "id": ps.nid("e"), "iat": 1, "sub": SUB, "agent": AGENT,
        "reason": "done"}).status == 201
    again = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "iat": 1, "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)})
    assert again.status == 201
    m = ss.store.missions[Store.k(ps.issuer, s256)]
    assert (m.state, m.reason) == ("terminated", "done")


def test_a_retried_mission_update_gets_the_same_signed_answer() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    body = {"action": "update", "sdi": ps.nid("d"), "iat": 1, "sub": SUB, "agent": AGENT,
            "description": "Also draft the summary"}
    first = ps.call(ss, "POST", f"/mission/{s256}", body)
    c.t += 5
    second = ps.call(ss, "POST", f"/mission/{s256}", body)
    assert first.status == second.status == 200
    assert (first.body, first.headers["Signature"]) == (second.body, second.headers["Signature"])
    assert ss.store.missions[Store.k(ps.issuer, s256)].updates == [
        "Also draft the summary"]


# ------------------------------------------------------------ R3 proposals


def r3_request(ps: Any, ss: Any, s256: str, member: Any, r3_s256: str = "") -> Any:
    return ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "mission_s256": s256,
        "resource_token": ps.resource_token(MAIL, "mail.send", r3_s256, s256),
        "presented_token": "a.b.c", "r3_proposal": member})


@pytest.mark.parametrize("member,detail", [
    ("a=b", "R3 proposal is not base64url"),
    (b64u(b"\xff\xfe\x00"), "R3 proposal is not JSON"),  # not UTF-8: a 400, never a 500
    (b64u(b"{"), "R3 proposal is not JSON"),
    (b64u(b"[1]"), "R3 proposal is not an object"),
])
def test_a_malformed_r3_proposal_is_a_400(member: Any, detail: str) -> None:
    ss, ps, c = make_env(transport="forwarded")
    s256 = connected((ss, ps, c))
    r = r3_request(ps, ss, s256, member)
    assert r.status == 400 and r.json() == {"error": "invalid_request", "detail": detail}


def test_r3_proposal_bytes_must_match_r3_s256() -> None:
    ss, ps, c = make_env(transport="forwarded")
    s256 = connected((ss, ps, c))
    _, digest = r3_bytes({"operations": []})
    r = r3_request(ps, ss, s256, b64u(b'{"operations":[1]}'), digest)
    assert r.status == 400 and r.json()["detail"] == "R3 proposal bytes do not match r3_s256"


# ------------------------------------------------------------ decisions


def test_a_deny_without_a_reason_carries_no_reason() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    ss.policy = Scripted(ss.policy, decision=Decision("deny"))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)
    assert r.json() == {"sdi": sdi, "decision": "deny"}


def test_an_ask_without_recommendation_or_options_carries_only_its_summary() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    ss.policy = Scripted(ss.policy, decision=Decision("ask", summary="Shall I?"))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)
    assert r.json() == {"sdi": sdi, "decision": "ask", "summary": "Shall I?"}


# ------------------------------------------------------------ clarification timeout


@pytest.mark.req("SUP-P15")
def test_clarification_times_out_at_the_stated_timeout() -> None:
    ss, ps, clock, s256 = clarify_env()
    sdi, loc = ask_clarification(ss, ps, s256)
    assert ps.call(ss, "GET", loc).json()["timeout"] == 120
    clock.t += 119
    assert ps.call(ss, "GET", loc).status == 202  # still before the deadline
    clock.t += 1
    late = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                     "clarification_response": "late"})
    assert late.status == 408 and late.json() == {
        "error": "expired", "detail": "the clarification was not answered in time"}
    # The 408 is a terminal response (Protocol L2414), so the URL is gone after it (L2840).
    assert ps.call(ss, "GET", loc).status == 410
    assert ps.call(ss, "DELETE", loc).status == 410
    assert ss.store.decisions[Store.k(ps.issuer, sdi)].decision == "expired"


@pytest.mark.req("SUP-P15")
def test_each_clarification_round_gets_the_full_timeout() -> None:
    ss, ps, clock, s256 = clarify_env()
    ss.policy = Scripted(ss.policy, decision=Decision("clarify", clarification="Why?"))
    _, loc = ask_clarification(ss, ps, s256)
    clock.t += 100
    again = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                      "clarification_response": "because"})
    assert again.status == 202  # Scripted asks again; clarify=False is not honoured by it
    clock.t += 100  # 200s after the first round, 100s after the second
    assert ps.call(ss, "GET", loc).status == 202


@pytest.mark.req("SUP-P15")
def test_an_answered_clarification_does_not_expire() -> None:
    ss, ps, clock, s256 = clarify_env()
    sdi, loc = ask_clarification(ss, ps, s256)
    a = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                  "clarification_response": "why"})
    clock.t += 10_000
    # Gone, not expired: the answer was the terminal response (Protocol L2840), and the
    # decision on file stays the answer.
    g = ps.call(ss, "GET", loc)
    assert g.status == 410
    assert ss.store.decisions[Store.k(ps.issuer, sdi)].decision == a.json()["decision"]


@pytest.mark.req("SUP-P15")
def test_a_zero_timeout_is_neither_stated_nor_enforced() -> None:
    ss, ps, clock, s256 = clarify_env()
    ss.cfg.clarification_timeout = 0
    _, loc = ask_clarification(ss, ps, s256)
    clock.t += 10_000
    g = ps.call(ss, "GET", loc)
    assert g.status == 202 and "timeout" not in g.json()


def test_a_snapshot_pending_without_a_deadline_never_expires() -> None:
    ss, ps, clock, s256 = clarify_env()
    _, loc = ask_clarification(ss, ps, s256)
    ss.store.pending[loc.rsplit("/", 1)[1]].deadline = 0.0  # as loaded from a snapshot that has no deadline
    clock.t += 10_000
    assert ps.call(ss, "GET", loc).status == 202


# ------------------------------------------------------------ withdrawal


@pytest.mark.req("SUP-P17")
def test_a_delete_after_the_answer_keeps_the_answer() -> None:
    ss, ps, _, s256 = clarify_env()
    sdi, loc = ask_clarification(ss, ps, s256)
    a = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                  "clarification_response": "to tell the team"})
    assert a.json()["decision"] == "ask"
    # Protocol L2840: the answer was the terminal response, so a late DELETE finds the URL
    # gone and changes nothing.
    assert ps.call(ss, "DELETE", loc).status == 410
    assert ps.call(ss, "GET", loc).status == 410
    rec = ss.store.decisions[Store.k(ps.issuer, sdi)]
    assert rec.decision == "ask"
    # The person's answer still counts: the late DELETE did not rewrite the record.
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", apply="mission").status == 201
    assert rec.decision == "resolved_allow"


@pytest.mark.req("SUP-P17", "REF-010")
def test_a_retry_after_withdrawal_is_decided_afresh() -> None:
    # The withdrawn question answered nothing: a retry of the request under its sdi is
    # decided again (here, asked again, at a new URL); the withdrawn URL stays gone.
    ss, ps, _, s256 = clarify_env()
    _, loc = ask_clarification(ss, ps, s256)
    body = ps.sent[-1][1]
    assert ps.call(ss, "DELETE", loc).status == 204
    again = ps.call(ss, "POST", "/decision", body)
    assert again.status == 202 and again.headers["Location"] != loc
    assert ps.call(ss, "GET", again.headers["Location"]).status == 202
    assert ps.call(ss, "GET", loc).status == 410


def test_a_delete_without_a_decision_record_still_withdraws() -> None:
    ss, ps, _, s256 = clarify_env()
    sdi, loc = ask_clarification(ss, ps, s256)
    del ss.store.decisions[Store.k(ps.issuer, sdi)]
    assert ps.call(ss, "DELETE", loc).status == 204
    assert ps.call(ss, "GET", loc).status == 410


def test_a_retry_whose_record_has_no_open_question_is_decided_afresh() -> None:
    ss, ps, _, s256 = clarify_env()
    sdi, loc = ask_clarification(ss, ps, s256)
    body = ps.sent[-1][1]
    ss.store.pending.clear()  # e.g. a snapshot restored without its pending table
    again = ps.call(ss, "POST", "/decision", body)
    assert again.status == 202 and again.headers["Location"] != loc


# ------------------------------------------------------------ updated request


@pytest.mark.req("SUP-P16")
def test_updated_request_with_the_extension_off_carries_only_core_members() -> None:
    ss, ps, _, s256 = clarify_env(transport="forwarded", r3_member=None)
    _, loc = ask_clarification(ss, ps, s256)
    raw, digest = r3_bytes({"operations": [{"operationId": "send_email"}],
                            "parameters": {"to": "a@corp.example"}})
    a = ps.call(ss, "POST", loc, {
        "action": "updated_request", "presented_token": "a.b.c", "r3_proposal": b64u(raw),
        "resource_token": ps.resource_token(MAIL, "mail.send", digest, s256)})
    pid = loc.rsplit("/", 1)[1]
    assert "r3_proposal" not in ss.store.pending[pid].request
    assert a.status == 200 and a.json()["decision"] == "ask"  # no resource evidence used


def test_updated_request_answers_only_a_resource_token_act() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    ss.policy = Scripted(ss.policy, decision=Decision("clarify", clarification="Why?"))
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "Bash"})
    assert r.status == 202
    a = ps.call(ss, "POST", r.headers["Location"], {
        "action": "updated_request", "presented_token": "a.b.c",
        "resource_token": ps.resource_token(MAIL)})
    assert a.status == 400
    assert a.json()["detail"] == "updated_request answers only a resource-token act"


# ------------------------------------------------------------ events


@pytest.mark.parametrize("ev,members", [
    ("person_token.issued", {"jti": "pt-1", "aud": MAIL}),
    ("interaction.requested", {"interaction": "https://ps.example/i"}),
])
def test_acknowledged_events_change_nothing_but_dedup(ev: str, members: dict[str, Any]) -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    before = json.dumps({"d": {k: str(v) for k, v in ss.store.decisions.items()},
                         "h": [str(h) for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)],
                         "r": [str(r) for r in ss.store.reach]}, sort_keys=True)
    body = {"event": ev, "id": "e-ack", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, **members}
    assert ps.call(ss, "POST", "/event", body).status == 201
    after = json.dumps({"d": {k: str(v) for k, v in ss.store.decisions.items()},
                        "h": [str(h) for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)],
                        "r": [str(r) for r in ss.store.reach]}, sort_keys=True)
    assert after == before
    assert Store.k(ps.issuer, "e-ack") in ss.store.events_seen


def test_a_resolved_permission_without_a_history_entry_commits_nothing() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    ss.policy = Scripted(ss.policy, decision=Decision("ask", summary="?"))
    sdi, r = permission(ps, ss, s256)
    assert r.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow").status == 201
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []


def test_a_permission_reported_issued_then_resolved_joins_history_once() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    ss.policy = Scripted(ss.policy, decision=Decision(
        "ask", summary="?", entry=HistoryEntry("write", "Bash", "agent")))
    sdi, _ = permission(ps, ss, s256)
    ps.issued(ss, SUB, AGENT, s256, sdi, MAIL)
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow")
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [(h.sdi, h.action_class) for h in hist] == [(sdi, "write")]


def permission(ps: Any, ss: Any, s256: str) -> tuple[str, Any]:
    sdi = ps.nid("d")
    return sdi, ps.call(ss, "POST", "/decision", {
        "sdi": sdi, "act": "permission", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "Bash"})


def test_an_issued_then_resolved_act_joins_history_once() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c), resources=("https://hr.example",))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://calendar.example")
    assert r.json()["decision"] == "ask"
    ps.issued(ss, SUB, AGENT, s256, sdi, "https://calendar.example")
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow")
    hist = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert [h.sdi for h in hist] == [sdi]


def offered(ss: Any, ps: Any, body: str | None) -> set[str]:
    ss2, ps2, c2 = make_env()
    s256 = connected((ss2, ps2, c2), resources=("https://hr.example",))
    sdi, r, _ = ps2.auth_token_request(ss2, SUB, AGENT, s256, "https://calendar.example")
    rec = ss2.store.decisions[Store.k(ps2.issuer, sdi)]
    if body is None:
        rec.response = None
    else:
        assert rec.response is not None
        rec.response.body = body
    return ss2._offered_reaches(rec)


def test_offered_reaches_read_only_well_formed_options() -> None:
    ss, ps, _ = make_env()
    assert offered(ss, ps, None) == {"once"}
    assert offered(ss, ps, "{not json") == {"once"}
    assert offered(ss, ps, "[1]") == {"once"}
    assert offered(ss, ps, json.dumps({"apply_options": [
        "always", {"value": 3}, {"label": "x"}, {"value": "mission"}]})) == {"once", "mission"}


@pytest.mark.req("REF-027")
@pytest.mark.parametrize("uri", ["http://ss.example/docs", "javascript:alert(1)", "docs",
                                 "https://", "https://[ss.example/docs"])
def test_documentation_uri_must_be_an_https_url(uri: str) -> None:
    # Protocol L1994: `documentation_uri` "URL with developer documentation. MUST use
    # `https`." The SS publishes it in its metadata as configured.
    with pytest.raises(ValueError, match="documentation_uri"):
        ServerConfig.from_dict({"issuer": "https://ss.example", "documentation_uri": uri})
    ok = ServerConfig.from_dict({"issuer": "https://ss.example",
                                 "documentation_uri": "https://ss.example/docs"})
    assert ok.documentation_uri == "https://ss.example/docs"


@pytest.mark.parametrize("tool", [{"description": "no name"}, "WebSearch", 5])
def test_a_proposal_tool_entry_without_a_name_is_not_a_tool_name(tool: Any) -> None:
    # Only a tool object's `name` is checked as a name; the entry itself is the policy's.
    ss, ps, clock = make_env()
    ps.connect(ss, SUB)
    r = ps.call(ss, "POST", "/mission", {"sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB,
                                         "agent": AGENT, "agent_token": ps.agent_token(AGENT),
                                         "description": "x", "resources": [], "tools": [tool]})
    assert r.status == 200
