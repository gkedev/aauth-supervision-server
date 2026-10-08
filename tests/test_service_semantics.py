"""Exact semantics of the Supervision Server's protocol layer, one behaviour per test.

The end-to-end and conformance suites prove the flows. These pin the details those
flows pass through without asserting: member type checks, routing edges, Accept-Signature
handling, retry caching, clarification rounds, what each event does to the state, and
the defensive 500. Each test names the behaviour it protects.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.errors import ProtocolError
from aauth_supervision_server.httpsig import verify_response
from aauth_supervision_server.jwk import b64u, key_from_jwk
from aauth_supervision_server.service import _decode_jwt_claims, _operations
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import r3_bytes

MAIL = "https://mail.example"
CAL = "https://calendar.example"
INTERNAL = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "a@corp.example"}}
PAY_RULES = [{"resource": "*", "tool": "Pay", "param_gt": {"amount": 100}, "class": "payment"},
             {"resource": "*", "tool": "Pay", "class": "read"},
             {"resource": "*", "tool": "Export", "result_contains_any": ["pii"],
              "class": "read_sensitive"},
             {"resource": "*", "tool": "Export", "class": "read"}]


def with_rules(extra: list[dict[str, Any]]) -> list[dict[str, Any]]:
    base = json.loads((__import__("conftest").ROOT / "examples" / "policy.json").read_text())
    return base["rules"] + extra


def history(ss: Any, ps: Any, s256: str) -> list[Any]:
    return ss.store.history_for(ps.issuer, SUB, AGENT, s256)


def event(ps: Any, ss: Any, ev: str, s256: str = "", **members: Any) -> Any:
    body = {"event": ev, "id": ps.nid("e"), "iat": int(ps.clock()), "sub": SUB, "agent": AGENT,
            **members}
    if s256:
        body["mission_s256"] = s256
    return ps.call(ss, "POST", "/event", body)


def permission(ps: Any, ss: Any, s256: str, action: str, **members: Any) -> tuple[str, Any]:
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", "/decision", {"sdi": sdi, "act": "permission", "iat": int(ps.clock()),
                                          "sub": SUB, "agent": AGENT, "mission_s256": s256,
                                          "action": action, **members})
    return sdi, r


# ------------------------------------------------------------- member types


def test_a_null_member_does_not_end_the_type_check() -> None:
    ss, ps, c = make_env()
    r = ps.call(ss, "POST", "/connect", {"justification": None, "tenant": 5, "action": "connect",
                                         "id": "c-1", "iat": 1, "sub": SUB})
    assert r.status == 400 and r.json()["detail"] == "member 'tenant' has the wrong JSON type"


def test_an_extension_member_does_not_end_the_type_check() -> None:
    ss, ps, c = make_env()
    r = ps.call(ss, "POST", "/connect", {"x-extension": 1, "tenant": 5, "action": "connect",
                                         "id": "c-1", "iat": 1, "sub": SUB})
    assert r.status == 400 and r.json()["detail"] == "member 'tenant' has the wrong JSON type"


def test_forwarded_token_shape() -> None:
    for bad in ("abc", "a.b", "a.b.c.d"):
        with pytest.raises(ProtocolError) as e:
            _decode_jwt_claims(bad)
        assert e.value.detail == "forwarded token is not a JWT"
    tok = "x." + b64u(b'{"iss":"https://r.example"}') + ".y"
    assert _decode_jwt_claims(tok) == {"iss": "https://r.example"}


def test_operations_take_the_first_named_key_per_entry() -> None:
    prop = {"operations": [{"tool": "t", "name": "n"}, {"name": "n2", "method": "m2"}, "bad",
                           {"other": 1}]}
    assert _operations(prop) == ["t", "m2"]
    assert _operations({"operations": "x"}) == []


# ------------------------------------------------------------------ routing


def test_an_unexpected_failure_is_a_500_without_detail_leak() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))

    class Boom:
        r3_member = None
        ask_on_mission_update = False

        def __getattr__(self, name: str) -> Any:
            raise RuntimeError("secret internals")

    ss.policy = Boom()  # type: ignore[assignment]
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)
    assert r.status == 500
    assert r.json() == {"error": "server_error", "detail": "RuntimeError"}


def test_mission_url_with_an_extra_segment_is_not_the_mission() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    s256, raw = ps._last_blob
    r = ps.call(ss, "POST", f"/mission/{s256}/x", {
        "action": "approved", "id": ps.nid("e"), "iat": 1, "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)})
    assert r.status == 400 and r.json()["detail"] == "s256 differs from the mission URL"


def test_a_post_without_a_body_is_missing_body() -> None:
    ss, ps, _ = make_env()
    r = ps.call(ss, "POST", "/decision")
    assert r.status == 400 and r.json()["detail"] == "missing body"


def test_default_https_port_in_the_authority_is_the_same_ss() -> None:
    ss, ps, _ = make_env()
    ps.ss_authority = "ss.example:443"
    assert ps.connect(ss, SUB).status == 200


# ---------------------------------------------------- response signatures


def _signed_connect(ss: Any, ps: Any, accept: str) -> tuple[Any, Any]:
    req = ps.build("POST", "/connect", {"action": "connect", "id": ps.nid("c"),
                                        "iat": int(ps.clock()), "sub": SUB})
    req.headers["accept-signature"] = accept
    return req, ss.handle(req)


def _verify(ss: Any, req: Any, resp: Any, required: list[str]) -> None:
    from aauth_supervision_server.httpsig import HttpResponse

    hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.body)
    verify_response(hr, req, key_from_jwk(ss.key.public_jwk()), required,
                    expected_issuer="https://ss.example", now=ss.clock())


def test_response_signature_honours_the_requested_label_and_components() -> None:
    ss, ps, _ = make_env()
    req, resp = _signed_connect(ss, ps, 'resp=("@status" "content-digest" "@method";req)')
    assert resp.status == 200
    si = resp.headers["Signature-Input"]
    assert si.startswith("resp=") and '"@method";req' in si
    _verify(ss, req, resp, ["@status", "content-digest", "@method;req"])


def test_an_unsatisfiable_accept_signature_falls_back_to_the_minimum() -> None:
    ss, ps, _ = make_env()
    req, resp = _signed_connect(ss, ps, 'sig=("x-not-a-response-header")')
    assert resp.status == 200
    assert "x-not-a-response-header" not in resp.headers["Signature-Input"]
    _verify(ss, req, resp, ["@status", "content-type", "content-digest"])


def test_a_resolved_connect_poll_is_signed() -> None:
    from aauth_supervision_server.httpsig import HttpRequest

    ss, ps, _ = make_env(auto_connect=False)
    first = ps.connect(ss, SUB)
    code = next(p.code for p in ss.store.pending.values())
    form = f"code={code}&admin_token=operator-secret".encode()
    assert ss.handle(HttpRequest("POST", "ss.example", "/interaction", {}, form)).status == 200
    poll = ps.call(ss, "GET", first.headers["Location"])  # verifies the signature
    assert poll.status == 200 and "Signature" in poll.headers
    assert poll.json() == {"status": "connected"}


# -------------------------------------------------------------- clarification


def clarify_env(**over: Any) -> tuple[Any, Any, Any, str]:
    ss, ps, c = make_env(clarify_missing_justification=True, **over)
    return ss, ps, c, connected((ss, ps, c))


def test_clarification_round_limit_zero_asks_at_once() -> None:
    ss, ps, _, s256 = clarify_env()
    ss.cfg.clarification_rounds = 0
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 200 and r.json()["decision"] == "ask"
    assert r.json()["summary"] == ("The agent did not resolve the supervisor's question within "
                                   "the round limit.")


def test_first_clarification_is_round_one() -> None:
    ss, ps, _, s256 = clarify_env()
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202 and r.json()["decision"] == "clarify"
    pid = r.headers["Location"].rsplit("/", 1)[1]
    assert ss.store.pending[pid].rounds == 1


def test_an_answered_clarification_is_terminal_and_quotes_the_agent() -> None:
    ss, ps, _, s256 = clarify_env()
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    a = ps.call(ss, "POST", r.headers["Location"], {
        "action": "clarification_response", "clarification_response": "to notify the team"})
    assert a.status == 200 and a.json()["decision"] == "ask"  # not another clarify
    assert a.json()["summary"].endswith("; the agent says: to notify the team.")


def test_updated_request_carries_the_forwarded_proposal() -> None:
    ss, ps, _, s256 = clarify_env(transport="forwarded")
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202
    raw, digest = r3_bytes(INTERNAL)
    a = ps.call(ss, "POST", r.headers["Location"], {
        "action": "updated_request", "resource_token": ps.resource_token(MAIL, "mail.send",
                                                                         digest, s256),
        "presented_token": "a.b.c", "r3_proposal": b64u(raw)})
    assert a.status == 200 and a.json()["decision"] == "allow"


def test_a_retry_finds_its_own_pending_clarification() -> None:
    ss, ps, _, s256 = clarify_env()
    _, ra, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    _, rb, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    body_b = ps.sent[-1][1]
    again = ps.call(ss, "POST", "/decision", body_b)
    assert again.status == 202 and again.headers["Location"] == rb.headers["Location"]
    assert ra.headers["Location"] != rb.headers["Location"]


def test_a_retry_after_a_clarified_answer_is_byte_identical() -> None:
    ss, ps, clock, s256 = clarify_env()
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    body = ps.sent[-1][1]
    ps.call(ss, "POST", r.headers["Location"], {"action": "clarification_response",
                                                "clarification_response": "why"})
    first = ps.call(ss, "POST", "/decision", body)
    clock.t += 7
    second = ps.call(ss, "POST", "/decision", body)
    assert first.status == second.status == 200
    assert first.body == second.body
    assert first.headers["Signature"] == second.headers["Signature"]


def test_cancelling_a_clarification_abandons_its_record() -> None:
    ss, ps, _, s256 = clarify_env()
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert ps.call(ss, "DELETE", r.headers["Location"]).status == 204
    assert ss.store.decisions[Store.k(ps.issuer, sdi)].decision == "abandoned"


def test_a_one_second_timeout_still_sets_a_deadline_and_is_stated() -> None:
    # The timeout boundary is `> 0`, not `> 1`: a clarification_timeout of exactly 1 second
    # must still set a real deadline on the pending and still appear in the clarify body.
    ss, ps, clock, s256 = clarify_env()
    ss.cfg.clarification_timeout = 1
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert r.status == 202 and r.json()["timeout"] == 1
    pid = r.headers["Location"].rsplit("/", 1)[1]
    assert ss.store.pending[pid].deadline == clock() + 1


def test_an_expired_poll_whose_record_is_gone_still_times_out_cleanly() -> None:
    # Past the deadline the poll is `expired` (408). The decision record is normally present
    # and flipped to "expired", but even if it has been pruned the guard must not dereference
    # a missing record: the poll must still 408, never fall into the defensive 500.
    ss, ps, clock, s256 = clarify_env()
    ss.cfg.clarification_timeout = 5
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    sdi = ps.sent[-1][1]["sdi"]
    ss.store.decisions.pop(Store.k(ps.issuer, sdi))  # simulate a pruned record
    clock.t += 10  # past the deadline
    poll = ps.call(ss, "GET", r.headers["Location"])
    assert poll.status == 408 and poll.json()["error"] == "expired"


# -------------------------------------------------------------- idempotence


def test_a_retry_with_members_reordered_is_the_same_request() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)
    body = ps.sent[-1][1]
    again = ps.call(ss, "POST", "/decision", dict(reversed(list(body.items()))))
    assert again.status == 200 and again.json() == r.json()


def test_a_retried_mission_proposal_is_replayed_and_a_changed_one_refused() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    body = {"sdi": "d-mp", "iat": 1, "sub": SUB, "agent": AGENT,
            "agent_token": ps.agent_token(AGENT), "description": "x", "resources": [MAIL],
            "tools": []}
    first = ps.call(ss, "POST", "/mission", body)
    assert ps.call(ss, "POST", "/mission", body).body == first.body
    r = ps.call(ss, "POST", "/mission", body | {"description": "y"})
    assert r.status == 400 and r.json()["detail"] == "sdi already used for a different request"


def test_a_null_resources_member_is_invalid_request() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    r = ps.call(ss, "POST", "/mission", {"sdi": "d-n", "iat": 1, "sub": SUB, "agent": AGENT,
                                         "agent_token": ps.agent_token(AGENT),
                                         "description": "x", "resources": None})
    assert r.status == 400 and r.json()["detail"] == "resources must be an array"


# ------------------------------------------------------------------ missions


def test_a_mission_proposal_ask_carries_the_summary() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    r = ps.call(ss, "POST", "/mission", {"sdi": "d-a", "iat": 1, "sub": SUB, "agent": AGENT,
                                         "agent_token": ps.agent_token(AGENT), "description": "x",
                                         "tools": [{"name": "DeleteRepo"}], "resources": []})
    assert r.json()["decision"] == "ask"
    assert r.json()["summary"].startswith("The mission asks for tools that need your approval")


def _update(ps: Any, ss: Any, s256: str) -> Any:
    return ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": ps.nid("d"),
                                                    "iat": 1, "sub": SUB, "agent": AGENT,
                                                    "description": "also file the report"})


def test_mission_update_is_recorded_when_allowed() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    assert _update(ps, ss, s256).json()["decision"] == "allow"
    assert ss.store.missions[Store.k(ps.issuer, s256)].blob["_updates"] == ["also file the report"]


def test_mission_update_is_asked_when_configured_and_not_recorded() -> None:
    ss, ps, c = make_env(ask_on_mission_update=True)
    s256 = connected((ss, ps, c))
    r = _update(ps, ss, s256).json()
    assert r["decision"] == "ask"
    assert r["summary"] == "The agent reports a change to the mission: also file the report"
    assert "_updates" not in ss.store.missions[Store.k(ps.issuer, s256)].blob


# --------------------------------------------------------- permission acts


def test_permission_parameters_reach_the_policy() -> None:
    ss, ps, c = make_env(rules=with_rules(PAY_RULES))
    s256 = connected((ss, ps, c), tools=[{"name": "Pay", "description": "pay"}])
    _, small = permission(ps, ss, s256, "Pay", parameters={"amount": 5})
    _, large = permission(ps, ss, s256, "Pay", parameters={"amount": 500})
    assert small.json()["decision"] == "allow"
    assert large.json()["decision"] == "ask"  # payment is high impact, no resource evidence


def test_an_allowed_permission_is_history_at_once_and_only_then() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi, r = permission(ps, ss, s256, "WebSearch")
    assert r.json()["decision"] == "allow"
    assert [h.sdi for h in history(ss, ps, s256)] == [sdi]
    _, asked = permission(ps, ss, s256, "ReadFile")  # not an approved tool: asked
    assert asked.json()["decision"] == "ask"
    _, at = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)[:2]
    assert [h.sdi for h in history(ss, ps, s256)] == [sdi]  # auth_token waits for issuance


def test_a_permission_the_person_allows_joins_the_history() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    first, _ = permission(ps, ss, s256, "WebSearch")
    sdi, asked = permission(ps, ss, s256, "ReadFile")
    assert asked.json()["decision"] == "ask"
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow").status == 201
    assert [h.sdi for h in history(ss, ps, s256)] == [first, sdi]


def test_a_permission_the_person_denies_does_not_join_the_history() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi, _ = permission(ps, ss, s256, "ReadFile")
    ps.resolved(ss, SUB, AGENT, s256, sdi, "deny")
    assert history(ss, ps, s256) == []


def test_an_auth_token_the_person_allows_waits_for_issuance() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "ask"
    ps.resolved(ss, SUB, AGENT, s256, sdi, "allow")
    assert history(ss, ps, s256) == []
    ps.issued(ss, SUB, AGENT, s256, sdi, CAL)
    assert [h.sdi for h in history(ss, ps, s256)] == [sdi]


# ------------------------------------------------------------------- events


def test_issuance_after_an_ask_keeps_the_detail_and_notes_it() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CAL)
    assert r.json()["decision"] == "ask"
    ps.issued(ss, SUB, AGENT, s256, sdi, CAL)
    (h,) = history(ss, ps, s256)
    assert h.detail == "rule write (issued after ask)"


def test_replayed_issuance_is_classified_from_the_event() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    assert event(ps, ss, "auth_token.issued", s256, sdi="d-old", aud=MAIL,
                 scope="mail.send").status == 201
    (h,) = history(ss, ps, s256)
    assert (h.action_class, h.resource, h.sdi, h.amount) == ("send_external", MAIL, "d-old", 0)
    assert h.provenance == "configured" and h.detail == "uncertain: replayed"


def test_replayed_issuance_with_a_forwarded_proposal_is_resource_evidence() -> None:
    ss, ps, c = make_env(transport="forwarded+issued")
    s256 = connected((ss, ps, c))
    event(ps, ss, "auth_token.issued", s256, sdi="d-old", aud=MAIL, scope="mail.send",
          r3_proposal=b64u(r3_bytes(INTERNAL)[0]))
    (h,) = history(ss, ps, s256)
    assert (h.action_class, h.provenance, h.detail) == ("send_internal", "resource", "replayed")


def test_an_object_proposal_under_a_custom_member_is_taken_as_given() -> None:
    ss, ps, c = make_env(transport="forwarded", r3_member="r3x")
    s256 = connected((ss, ps, c))
    ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    body = dict(ps.sent[-1][1]) | {"sdi": "d-obj", "r3x": INTERNAL}
    r = ps.call(ss, "POST", "/decision", body)
    assert r.status == 200 and r.json()["decision"] == "allow"


def test_audit_record_is_agent_evidence_in_the_mission_history() -> None:
    ss, ps, c = make_env(rules=with_rules(PAY_RULES))
    s256 = connected((ss, ps, c))
    event(ps, ss, "audit.recorded", s256, action="Pay", parameters={"amount": 500})
    event(ps, ss, "audit.recorded", s256, action="Export", result={"contains": ["pii"]})
    event(ps, ss, "audit.recorded", s256, action="WebSearch")
    a, b, w = history(ss, ps, s256)
    assert (a.action_class, a.resource, a.provenance, a.sdi) == ("payment", "Pay", "agent", "")
    assert a.detail == "audit record"
    assert b.action_class == "read_sensitive"
    assert (w.action_class, w.amount) == ("read", 0)


def test_revocation_is_recorded_by_issuer_and_jti() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    event(ps, ss, "revocation.received", iss="https://as.example", jti="t-1")
    assert Store.k("https://as.example", "t-1") in ss.store.revoked


def test_agent_bound_records_the_binding() -> None:
    ss, ps, c = make_env()
    connected((ss, ps, c))
    event(ps, ss, "agent.bound", agent_iss="https://agent.example", agent_sub="s-1")
    rec = ss.store.agents[Store.k(ps.issuer, SUB, AGENT)]
    assert rec == {"agent_iss": "https://agent.example", "agent_sub": "s-1", "at": int(ps.clock())}



# ------------------------------------------------------- remaining edges


def test_without_accept_signature_the_response_label_is_sig() -> None:
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-1",
                                        "iat": int(ps.clock()), "sub": SUB})
    del req.headers["accept-signature"]
    resp = ss.handle(req)
    assert resp.status == 200 and resp.headers["Signature-Input"].startswith("sig=")
    for bad in ("((", ""):
        req.headers["accept-signature"] = bad
        assert ss.handle(req).headers["Signature-Input"].startswith("sig=")


def test_an_empty_clarification_answer_does_not_loop() -> None:
    ss, ps, _, s256 = clarify_env()
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    a = ps.call(ss, "POST", r.headers["Location"], {"action": "clarification_response",
                                                    "clarification_response": ""})
    assert a.status == 200 and a.json()["decision"] == "ask"


def test_a_retry_long_after_is_still_byte_identical() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    _, first, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL)
    body = ps.sent[-1][1]
    clock.t += 3600  # the PS signs the retry now; the SS's stored answer is an hour old
    again = ss.handle(ps.build("POST", "/decision", body))
    assert again.body == first.body and again.headers["Signature"] == first.headers["Signature"]


def test_replayed_issuance_with_a_proposal_is_resource_provenance_on_a_static_rule() -> None:
    ss, ps, c = make_env(transport="forwarded+issued")
    s256 = connected((ss, ps, c), resources=(CAL,))
    event(ps, ss, "auth_token.issued", s256, sdi="d-cal", aud=CAL,
          r3_proposal=b64u(r3_bytes({"operations": [{"operationId": "create"}]})[0]))
    (h,) = history(ss, ps, s256)
    assert (h.action_class, h.provenance) == ("write", "resource")


def test_an_action_on_a_terminated_mission_is_denied_with_the_reason() -> None:
    ss, ps, c = make_env()
    s256 = connected((ss, ps, c))
    assert ps.call(ss, "POST", f"/mission/{s256}", {"action": "terminated", "id": "e-t",
                                                    "iat": 1, "sub": SUB, "agent": AGENT,
                                                    "reason": "done"}).status == 201
    r = _update(ps, ss, s256).json()
    assert r["decision"] == "deny" and r["reason"] == "The mission has terminated."



# ------------------------------------------------------- server identifiers


@pytest.mark.parametrize("resource", ["https://EXFIL.example", "HTTPS://exfil.example",
                                      "https://exfil.example/", "https://exfil.example:8443",
                                      "http://exfil.example", "https://exfil.example/v1", ""])
def test_a_resource_that_is_not_a_server_identifier_is_refused(resource: str) -> None:
    # Core, Server Identifiers: lowercase https host only, compared as exact strings. Were a
    # case variant accepted, it would slip past a deny written for https://exfil.example.
    ss, ps, clock = make_env(deny_resources=["https://exfil.example"])
    s256 = connected((ss, ps, clock))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    assert "server identifier" in r.json()["detail"]
    body = {"sdi": ps.nid("d"), "act": "person_token", "iat": 1, "sub": SUB, "agent": AGENT,
            "agent_token": ps.agent_token(AGENT), "resource": resource}
    r = ps.call(ss, "POST", "/decision", body)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_the_conforming_identifier_is_still_denied() -> None:
    ss, ps, clock = make_env(deny_resources=["https://exfil.example"])
    s256 = connected((ss, ps, clock))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://exfil.example")
    assert r.status == 200 and r.json()["decision"] == "deny"
