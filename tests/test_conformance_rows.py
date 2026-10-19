"""Matrix rows held by a test that fails on an SS breaking the row in the way it names.

Each test refuses exactly what a non-conforming SS would take: a member REQUIRED on one
endpoint left out where another endpoint's test already checks it, an issuer or endpoint
that only looks right, an error under the right status but the wrong code. The row and
the draft line are named on each test.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.jwk import b64u, b64u_decode
from aauth_supervision_server.sfv import parse_dictionary
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import make_jwt

HR, MAIL, INF = "https://hr.example", "https://mail.example", "https://inference.example"
# Core, Server Identifiers (Protocol L1950-L1953): https, lowercase host, nothing after it.
SERVER_IDENTIFIER = re.compile(r"https://[a-z0-9-]+(\.[a-z0-9-]+)*")


def _metadata(ss: Any) -> dict[str, Any]:
    r = ss.handle(HttpRequest("GET", "ss.example", "/.well-known/aauth-supervisor.json"))
    assert r.status == 200
    md = r.json()
    assert isinstance(md, dict)
    return md


def _blob(agent: str = AGENT) -> tuple[str, str]:
    """A mission blob, as the PS reports it at approval: (s256, base64url bytes)."""
    raw = json.dumps({"agent": agent, "approved_at": "2026-10-06T00:00:00Z",
                      "description": "# Another mission", "approved_tools": [],
                      "approved_resources": [HR]}, separators=(",", ":")).encode()
    return b64u(hashlib.sha256(raw).digest()), b64u(raw)


def _requests(ps: Any, s256: str, iat: int) -> dict[str, tuple[str, dict[str, Any]]]:
    """One complete request of each kind the PS makes, by name: (path, body)."""
    new_s256, blob = _blob()
    base = {"iat": iat, "sub": SUB, "agent": AGENT}
    return {
        "connect": ("/connect", {"action": "connect", "id": "c-n", "iat": iat, "sub": SUB}),
        "proposal": ("/mission", base | {"sdi": "d-p", "agent_token": ps.agent_token(AGENT),
                                         "description": "# Plan", "resources": [HR]}),
        "approved": (f"/mission/{new_s256}", base | {"action": "approved", "id": "e-a",
                                                     "sdi": "d-p", "s256": new_s256,
                                                     "mission": blob}),
        "update": (f"/mission/{s256}", base | {"action": "update", "sdi": "d-u",
                                               "description": "Also read the calendar."}),
        "completion": (f"/mission/{s256}", base | {"action": "completion", "sdi": "d-c",
                                                   "summary": "Done."}),
        "terminated": (f"/mission/{s256}", base | {"action": "terminated", "id": "e-t",
                                                   "reason": "completed"}),
        "decision": ("/decision", base | {"sdi": "d-d", "act": "permission",
                                          "mission_s256": s256, "action": "WebSearch",
                                          "parameters": {"q": "x"}}),
        "event": ("/event", base | {"event": "agent.bound", "id": "e-b",
                                    "agent_iss": "https://agent.example", "agent_sub": AGENT}),
    }


TAKEN = {"connect": 200, "proposal": 200, "approved": 201, "update": 200, "completion": 200,
         "terminated": 201, "decision": 200, "event": 201}


def _without(name: str, member: str) -> tuple[Any, Any, str, Any]:
    """The SS, the PS, the mission, and the response to request `name` sent without
    `member`. The same request with it is taken, by another SS in the same state, so the
    refusal is the member's alone."""
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    path, body = _requests(ps, s256, int(clock()))[name]
    assert ps.call(ss, "POST", path, body).status == TAKEN[name], name
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    path, body = _requests(ps, s256, int(clock()))[name]
    assert member in body
    del body[member]
    return ss, ps, s256, ps.call(ss, "POST", path, body)


# ------------------------------------------------------------------ metadata


@pytest.mark.req("SUP-001")
def test_the_published_issuer_is_a_server_identifier_and_the_id_the_ss_signs_with(env) -> None:
    # Supervision L157: `issuer` conforms to the server identifier requirements, and "It is
    # the `id` the SS signs with". A PS registers the SS by it and compares it with the `id`
    # of every signed answer (L342), byte for byte (Protocol L1969).
    ss, ps, _ = env
    issuer = _metadata(ss)["issuer"]
    assert SERVER_IDENTIFIER.fullmatch(issuer), issuer
    r = ps.connect(ss, SUB)
    assert r.status == 200
    member = parse_dictionary(r.headers["Signature-Key"])["sig"]
    assert member.params["id"] == issuer  # type: ignore[union-attr]


@pytest.mark.req("SUP-008")
def test_every_endpoint_is_https_on_the_issuers_origin_and_answers_there(env) -> None:
    # Supervision L165: "Endpoint URLs MUST be HTTPS and MUST be on the `issuer`'s origin or
    # one the SS controls". This SS serves every endpoint itself, on its issuer's origin.
    ss, ps, clock = env
    md = _metadata(ss)
    origin = urlsplit(md["issuer"])
    endpoints = {k: v for k, v in md.items() if k.endswith("_endpoint")}
    assert set(endpoints) == {"connect_endpoint", "mission_endpoint", "decision_endpoint",
                              "event_endpoint"}
    for name, url in endpoints.items():
        u = urlsplit(url)
        assert (u.scheme, u.netloc) == ("https", origin.netloc), name
        assert not (u.query or u.fragment), name
    # The URL published is the one the SS answers at.
    path = {k: urlsplit(v).path for k, v in endpoints.items()}
    assert ps.call(ss, "POST", path["connect_endpoint"], {
        "action": "connect", "id": "c-1", "iat": int(clock()), "sub": SUB}).status == 200
    r = ps.call(ss, "POST", path["decision_endpoint"], {
        "sdi": "d-1", "act": "permission", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "action": "WebSearch", "parameters": {"q": "x"}})
    assert r.status == 200 and r.json()["sdi"] == "d-1"


@pytest.mark.req("REF-018", "REF-019", "REF-020")
@pytest.mark.parametrize("issuer", ["https://PS.example", "https://ps.example/",
                                    "HTTPS://ps.example", "https://ps.example:443"])
def test_a_ps_metadata_issuer_must_be_its_id_byte_for_byte(issuer: str) -> None:
    # Protocol L1969: "exact string comparison on server identifiers"; L1981, L1987: the
    # metadata `issuer` matches the URL it was fetched from "compared by byte equality",
    # or the document is rejected with `issuer_mismatch`. A case, a slash or a default
    # port that names the same host to a browser is still another identifier.
    ss, ps, _ = make_env()
    ss.resolver.fetcher.documents[f"{ps.issuer}/.well-known/aauth-person.json"]["issuer"] = issuer
    r = ps.connect(ss, SUB)
    assert r.status == 401, r.status
    assert r.headers["Signature-Error"] == "error=issuer_mismatch"
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


# ------------------------------------------------------------------ envelope


@pytest.mark.req("SUP-012")
@pytest.mark.parametrize("name", ["proposal", "update", "completion", "decision"])
def test_a_supervision_request_without_an_sdi_is_refused(name: str) -> None:
    # Supervision L196: `sdi` is REQUIRED on a supervision request: a proposal, an update, a
    # completion (L354-L357) and a decision request. No other identifier stands in for it.
    ss, ps, s256, r = _without(name, "sdi")
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    assert "sdi" in r.json()["detail"]
    m = ss.store.missions[Store.k(ps.issuer, s256)]
    assert (m.state, m.updates) == ("active", [])


@pytest.mark.req("SUP-013")
@pytest.mark.parametrize("name", ["approved", "terminated"])
def test_a_report_without_an_id_is_refused(name: str) -> None:
    # Supervision L197: `id` is REQUIRED on an event and on a report; `approved` and
    # `terminated` are reports (L355, L358), deduplicated on `(iss, id)` like an event.
    ss, ps, s256, r = _without(name, "id")
    assert r.status == 400 and r.json()["error"] == "invalid_request", r.status
    assert re.search(r"\bid\b", r.json()["detail"])
    assert ss.store.missions[Store.k(ps.issuer, s256)].state == "active"
    assert len(ss.store.missions) == 1  # the approved mission was not recorded either


@pytest.mark.req("SUP-014")
@pytest.mark.parametrize("name", ["connect", "proposal", "approved", "update", "completion",
                                  "terminated", "decision", "event"])
def test_every_request_without_an_iat_is_refused(name: str) -> None:
    # Supervision L194, L198: every request body carries `iat`, REQUIRED: the time of the act
    # at the PS. A request without it is decided at no time and is refused on every endpoint.
    ss, ps, s256, r = _without(name, "iat")
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    assert "iat" in r.json()["detail"]


@pytest.mark.req("SUP-016")
@pytest.mark.parametrize("name", ["proposal", "approved", "update", "completion",
                                  "terminated", "decision", "event"])
def test_every_request_about_an_agent_without_its_agent_is_refused(name: str) -> None:
    # Supervision L200: `agent` is REQUIRED; the SS keys an agent's history on it, so a
    # request with none is not decided or recorded for some agent of the SS's choosing.
    ss, ps, s256, r = _without(name, "agent")
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    assert re.search(r"\bagent\b", r.json()["detail"])
    assert ss.store.missions[Store.k(ps.issuer, s256)].history == []


# ------------------------------------------------------------------ connect and missions


@pytest.mark.req("SUP-019")
def test_a_connect_without_an_action_is_refused() -> None:
    # Supervision L238: `action` (REQUIRED) is `connect` or `disconnect`; a body naming
    # neither is not read as either (L631: missing member, `invalid_request`).
    ss, ps, clock = make_env()
    r = ps.call(ss, "POST", "/connect", {"id": "c-1", "iat": int(clock()), "sub": SUB})
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    assert Store.k(ps.issuer, SUB) not in ss.store.connections
    # Nor does it end a connection that exists.
    assert ps.connect(ss, SUB).status == 200
    r = ps.call(ss, "POST", "/connect", {"id": "c-2", "iat": int(clock()), "sub": SUB})
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    assert Store.k(ps.issuer, SUB) in ss.store.connections


@pytest.mark.req("SUP-031")
@pytest.mark.parametrize("name", ["approved", "update", "completion", "terminated"])
def test_a_mission_request_complete_but_for_its_action_is_refused(name: str) -> None:
    # Supervision L360: "an SS MUST reject a missing or unrecognized `action` with
    # `invalid_request`", even when the rest of the body is a well-formed request of one
    # kind: the SS does not guess which.
    ss, ps, s256, r = _without(name, "action")
    assert (r.status, r.json().get("error")) == (400, "invalid_request")
    m = ss.store.missions[Store.k(ps.issuer, s256)]
    assert (m.state, m.updates) == ("active", [])
    assert len(ss.store.missions) == 1


# ------------------------------------------------------------------ errors


@pytest.mark.req("SUP-062")
def test_a_throttled_request_is_rate_limited_with_retry_after() -> None:
    # Supervision L636: `rate_limited`, 429, "`Retry-After` is REQUIRED". The PS waits on
    # the code, so the status alone does not say what to do.
    ss, ps, clock = make_env()
    ss.cfg.rate_limit_per_minute = 1
    assert ps.connect(ss, SUB).status == 200
    r = ps.connect(ss, SUB)
    assert (r.status, r.json().get("error")) == (429, "rate_limited")
    assert re.fullmatch(r"[0-9]+", r.headers["Retry-After"]) and int(r.headers["Retry-After"]) > 0
    assert r.headers["Content-Type"] == "application/problem+json"


def _refusals() -> dict[str, Any]:
    """One refusal of each code the SS answers, made in process, by the code expected."""
    out: dict[str, Any] = {}
    ss, ps, clock = make_env(clarify_missing_justification=True)
    out["unknown_sub"] = ps.auth_token_request(ss, SUB, AGENT, "", HR)[1]
    s256 = connected((ss, ps, clock), resources=(HR, MAIL))
    out["invalid_request"] = ps.call(ss, "POST", "/decision", {
        "sdi": "d-x", "act": "fly", "iat": int(clock()), "sub": SUB, "agent": AGENT})
    out["unknown_mission"] = ps.auth_token_request(ss, SUB, AGENT, "NOPE", HR)[1]
    out["unknown_pending"] = ps.call(ss, "GET", "/pending/nope")
    _, clarify, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, scope="mail.send")
    assert clarify.status == 202
    clock.t += ss.cfg.clarification_timeout + 1
    out["expired"] = ps.call(ss, "GET", clarify.headers["Location"])
    out["invalid_code"] = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"",
                                                "code=AAAAAAAAAA"))
    out["invalid_signature"] = ss.handle(HttpRequest(
        "POST", "ss.example", "/decision", {"content-type": "application/json"}, b"{}"))
    ss.cfg.rate_limit_per_minute = 1
    ps.connect(ss, SUB)
    out["rate_limited"] = ps.connect(ss, SUB)
    ss.cfg.trusted_ps.clear()
    ss.cfg.rate_limit_per_minute = 0
    out["unsupported_iss"] = ps.connect(ss, SUB)
    return out


@pytest.mark.req("REF-049")
def test_every_refusal_names_its_error_code_in_the_body() -> None:
    # Protocol L2573-L2575: error bodies are problem details with `error` (REQUIRED), the
    # code, and "receivers MUST determine how to proceed from this member". Supervision
    # L627 answers every error in this format.
    for code, r in _refusals().items():
        assert r.status >= 400, code
        assert r.headers["Content-Type"] == "application/problem+json", code
        body = json.loads(r.body)
        assert body["error"] == code, (code, body)


# ------------------------------------------------------------------ updated request


def _resource_token(sim: Any, s256: str, scope: str, claims: dict[str, Any]) -> str:
    tok = sim.resource_token(MAIL, scope, mission_s256=s256)
    payload = json.loads(b64u_decode(tok.split(".")[1])) | claims
    return make_jwt(sim.resource_key, "aa-resource+jwt", payload)


@pytest.mark.req("REF-009")
@pytest.mark.parametrize("claim,other", [("ps", "https://other-ps.example"),
                                         ("sub", "someone-else"),
                                         ("agent_jkt", "another-thumbprint"),
                                         ("tenant", "other.example")])
def test_an_updated_request_must_keep_every_claim_the_core_names(claim: str, other: str) -> None:
    # Protocol L1117: the new resource token "MUST have the same `iss`, `ps`, `sub`,
    # `agent_jkt`, `mission_s256`, and `tenant` as the original". Each one differing alone
    # is another request, refused; the same claims with a smaller scope are taken.
    ss, ps, clock = make_env(clarify_missing_justification=True)
    s256 = connected((ss, ps, clock), resources=(HR, MAIL))
    same = {"agent_jkt": "agent-thumbprint", "tenant": "corp.example"}
    r = ps.call(ss, "POST", "/decision", {
        "sdi": "d-orig", "act": "auth_token", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "agent_token": ps.agent_token(AGENT), "presented_token": "a.b.c",
        "resource_token": _resource_token(ps, s256, "mail.send", same)})
    assert r.status == 202
    loc = r.headers["Location"]
    bad = ps.call(ss, "POST", loc, {"action": "updated_request", "presented_token": "a.b.c",
                                    "resource_token": _resource_token(
                                        ps, s256, "mail.read", same | {claim: other})})
    assert (bad.status, bad.json().get("error")) == (400, "invalid_request")
    assert bad.json()["detail"].endswith(f"in {claim}")
    assert ps.call(ss, "GET", loc).status == 202  # the question is still open
    ok = ps.call(ss, "POST", loc, {"action": "updated_request", "presented_token": "a.b.c",
                                   "resource_token": _resource_token(ps, s256, "mail.read",
                                                                     same)})
    assert ok.status == 200 and ok.json()["sdi"] == "d-orig"


# ------------------------------------------------------------------ pending URLs


@pytest.mark.req("REF-053")
def test_pending_urls_share_no_structure_a_guess_could_use() -> None:
    # Protocol L2837: "Pending URLs MUST be unguessable". Ids drawn at random share no long
    # prefix and spread over the whole base64url alphabet; ids from a counter, a clock or
    # a hash of the request would do neither. Sixteen connects awaiting the operator, each
    # with its own pending URL.
    ss, ps, clock = make_env(auto_connect=False)
    ids = []
    for i in range(16):
        r = ps.call(ss, "POST", "/connect", {"action": "connect", "id": f"c-{i}",
                                             "iat": int(clock()), "sub": f"person-{i}"})
        assert r.status == 202
        ids.append(r.headers["Location"].rsplit("/", 1)[1])
    assert len(set(ids)) == 16
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{22,}", i) for i in ids)
    for a in ids:
        for b in ids:
            if a != b:
                assert len(os.path.commonprefix([a, b])) < 8, (a, b)
    # 352 symbols drawn from 64: all but a handful of the alphabet appear.
    assert len(set("".join(ids))) >= 32


# ------------------------------------------------------------------ budgets


@pytest.mark.req("BUD-002", "BUD-004")
@pytest.mark.parametrize("budget", [{"amount": 1000.5, "unit": "USD", "decimals": 2},
                                    {"amount": 0.5, "unit": "USD", "decimals": 2},
                                    {"amount": 1000, "unit": "USD", "decimals": 2.5}])
def test_an_offer_whose_amount_or_scale_is_not_an_integer_is_no_budget(budget: Any) -> None:
    # Budgets L344, L346: `amount` and `decimals` are non-negative integers. An offer with a
    # fraction in either is not a budget object, so the SS has no bounded spend to hold
    # against its ceiling and puts the act to the person, as for an offer with no budget.
    ss, ps, clock = make_env(resource_budgets={INF: {"unit": "USD", "decimals": 2,
                                                     "max_amount": 2500}})
    s256 = connected((ss, ps, clock), resources=(HR, INF))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, INF, scope="inference.completions",
                                    budget=budget)
    d = r.json()
    assert d["decision"] == "ask" and "it offered no budget for this act" in d["summary"]
