"""One request must not be able to break the SS for every other request.

* A body nested deeper than any AAuth member needs is refused at once: kept in a record,
  it would make every later snapshot write fail, and every PS be answered `server_error`.
* A lone surrogate in a member the agent wrote (its justification) is still a request the
  SS can fingerprint: the decision stands instead of becoming `server_error`, which the PS
  reads as "unavailable" and puts to the person (L609 to L613).
* A second clarification round keeps the sdi bound to the request that opened it: the
  PS's retry of that request is answered, not refused (L211, L316).
* A state file in a directory that does not exist yet is created, not a `server_error`
  on every request; and the snapshot is written to disk before it replaces the old one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, SUB, Clock, connected, make_env

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Act, Classification, Decision
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.store import HistoryEntry, Mission, Reach, Store
from aauth_supervision_server.testing import SimulatedPS

MAIL, REC = "https://mail.example", "https://records.example"


def _nested(depth: int) -> Any:
    v: Any = "x"
    for _ in range(depth):
        v = {"a": v}
    return v


def _with_body(ps: SimulatedPS, clock: Clock, req: HttpRequest, body: bytes) -> HttpRequest:
    """`req` carrying `body` as written, signed again: a body the PS's JSON encoder could
    not write (Python 3.11's stops at the recursion limit) still reaches the SS."""
    from aauth_supervision_server.httpsig import content_digest, sign_message
    req.body = body
    req.headers["content-digest"] = content_digest(body)
    sk = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    req.headers.update({k.lower(): v for k, v in sign_message(
        ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"],
        ps.key, sk, req, created=int(clock())).items()})
    return req


def test_a_deeply_nested_body_is_refused_and_the_ss_keeps_answering(tmp_path: Path) -> None:
    ss, ps, clock = make_env(auto_connect=False)
    ss.store = Store(str(tmp_path / "ss.json"))
    req = ps.build("POST", "/connect", {"action": "connect", "id": "c-deep",
                                        "iat": int(clock()), "sub": SUB})
    deep = b'{"a":' * 2000 + b'"x"' + b'}' * 2000
    r = ss.handle(_with_body(ps, clock, req, req.body[:-1] + b',"x-ext":' + deep + b'}'))
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    assert ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c-2",
                                            "iat": int(clock()), "sub": SUB}).status == 202


def test_an_ordinary_nesting_depth_is_accepted() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), tools=[{"name": "Export", "description": "x"}])
    r = ps.call(ss, "POST", "/decision", {"sdi": ps.nid("d"), "act": "permission",
                                          "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                          "mission_s256": s256, "action": "Export",
                                          "parameters": _nested(20)})
    assert r.status == 200


def test_a_lone_surrogate_in_the_justification_does_not_turn_a_deny_into_an_error() -> None:
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock), resources=(REC, MAIL))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, REC)
    assert r.json()["decision"] == "allow"
    ps.issued(ss, SUB, AGENT, s256, sdi, REC)
    send = {"operations": [{"operationId": "send_email"}], "parameters": {"to": "x@evil.example"}}
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=send,
                                    justification="hi \ud800")
    assert r.status == 200 and r.json()["decision"] == "deny"


class TwoRounds:
    """A pluggable policy that asks the agent twice before it allows."""

    r3_member = None
    ask_on_mission_update = False

    def classify(self, act: Act) -> Classification:
        return Classification("x", "configured", False)

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision:
        if act.justification.count("answer") < 2:
            return Decision("clarify", clarification="Why?")
        return Decision("allow")

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        return Decision("allow")


def test_a_retry_between_clarification_rounds_is_still_the_same_request() -> None:
    clock, fetcher = Clock(), StaticFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    key = SigningKey.generate("ss-key-1")
    ps.ss_jwk = key.public_jwk()
    ss = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                        trusted_ps={ps.issuer: TrustedPS(auto_connect=True)}),
                           TwoRounds(), JwksUriResolver(fetcher), key, clock=clock)
    assert ps.connect(ss, SUB).status == 200
    body = {"sdi": "d-orig", "act": "permission", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "action": "Export"}
    first = ps.call(ss, "POST", "/decision", body)
    assert first.status == 202
    loc = first.headers["Location"]
    reply = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                      "clarification_response": "answer"})
    assert reply.status == 202
    retry = ps.call(ss, "POST", "/decision", body)
    assert retry.status == 202 and retry.headers["Location"] == loc
    final = ps.call(ss, "POST", loc, {"action": "clarification_response",
                                      "clarification_response": "answer"})
    assert final.status == 200 and final.json()["decision"] == "allow"
    again = ps.call(ss, "POST", "/decision", body)
    assert again.status == 200 and again.json()["decision"] == "allow"


def test_a_state_file_in_a_missing_directory_is_created(tmp_path: Path) -> None:
    state = tmp_path / "state" / "ss.json"
    ss, ps, clock = make_env()
    ss.store = Store(str(state))
    assert ps.connect(ss, SUB).status == 200
    assert json.loads(state.read_text())["connections"]


def test_the_interaction_page_looks_up_codes_under_the_store_lock() -> None:
    ss, ps, clock = make_env(auto_connect=False)
    assert ps.connect(ss, SUB).status == 202
    code = next(p.code for p in ss.store.pending.values() if p.kind == "connect")
    seen: list[bool] = []
    real = ss.store.pending_by_code

    def probe(c: str) -> Any:
        seen.append(ss.store.lock._is_owned())  # type: ignore[attr-defined]
        return real(c)

    ss.store.pending_by_code = probe  # type: ignore[method-assign]
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"",
                                 query=f"code={code}"))
    assert page.status == 200 and seen and all(seen)


@pytest.mark.parametrize("depth", [5_000, 200_000])
def test_a_body_nested_past_the_decoder_limit_is_refused_not_a_server_error(depth: int) -> None:
    # Where the JSON decoder gives up depends on the interpreter: CPython 3.14 parses 5000
    # levels (the SS's own depth check refuses them), and gives up at 200000 like the others.
    # Either way the answer is the same refusal.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), tools=[{"name": "Export", "description": "x"}])
    req = ps.build("POST", "/decision", {"sdi": "d-n", "act": "permission",
                                         "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                         "mission_s256": s256, "action": "Export"})
    body = (b'{"sdi":"d-n","act":"permission","sub":"x","parameters":' + b'[' * depth
            + b']' * depth + b'}')
    r = ss.handle(_with_body(ps, clock, req, body))
    assert r.status == 400 and "nests deeper" in r.json()["detail"]


def test_the_snapshot_is_on_disk_before_it_replaces_the_old_one(
        tmp_path: Path, monkeypatch: Any) -> None:
    from aauth_supervision_server import store as store_mod
    calls: list[str] = []
    real_fsync, real_replace = store_mod.os.fsync, store_mod.os.replace
    monkeypatch.setattr(store_mod.os, "fsync",
                        lambda fd: (calls.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(store_mod.os, "replace",
                        lambda a, b: (calls.append("replace"), real_replace(a, b))[1])
    Store(str(tmp_path / "ss.json")).save()
    assert calls == ["fsync", "replace"]


def test_the_snapshot_is_written_through_a_new_owner_only_file(
        tmp_path: Path, monkeypatch: Any) -> None:
    # The snapshot carries forwarded token claims and mission text. It is written through a
    # temporary file created anew (O_EXCL) with mode 0o600 (asserted on the os.open call,
    # since Windows ignores mode bits), under a name no one can plant a file or link at
    # beforehand: what is already at the old fixed name is never opened.
    from aauth_supervision_server import store as store_mod
    path = tmp_path / "ss.json"
    planted = path.with_name(path.name + ".tmp")
    planted.write_text("planted", encoding="utf-8")
    seen: list[tuple[str, int, int, bool]] = []
    real_open = store_mod.os.open

    def spy(p: Any, flags: int, mode: int = 0o777) -> int:
        seen.append((str(p), flags, mode, Path(p).exists()))
        return real_open(p, flags, mode)

    monkeypatch.setattr(store_mod.os, "open", spy)
    Store(str(path)).save()
    ((name, flags, mode, existed),) = seen
    assert mode == 0o600 and flags & os.O_EXCL and not existed and name != str(planted)
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == Store.VERSION
    assert planted.read_text(encoding="utf-8") == "planted"
    assert sorted(x.name for x in tmp_path.iterdir()) == ["ss.json", "ss.json.tmp"]


# ------------------------------------------------------------ the mission blob

def _approve_blob(ss: Any, ps: Any, blob: Any) -> tuple[Any, str]:
    import hashlib

    from aauth_supervision_server.jwk import b64u
    raw = json.dumps(blob, separators=(",", ":")).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": ps.nid("e"), "sdi": ps.nid("d"), "iat": 1, "sub": SUB,
        "agent": AGENT, "s256": s256, "mission": b64u(raw)})
    return r, s256


def test_a_mission_blob_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    """Protocol, Mission Approval: `mission` decodes to the mission blob, a JSON object.
    Stored, any other value would make every later decision in the mission `server_error`
    until it ends, and the snapshot unreadable at the next start, so the SS would set
    aside every PS's state."""
    ss, ps, _ = make_env()
    ss.store = Store(str(tmp_path / "ss.json"))
    assert ps.connect(ss, SUB).status == 200
    for blob in (["not", "an", "object"], "text", 7, None):
        r, _ = _approve_blob(ss, ps, blob)
        assert r.status == 400 and r.json()["error"] == "invalid_request", blob
    reloaded = Store(str(tmp_path / "ss.json"))
    assert reloaded.load_error == "" and reloaded.connections


def test_mission_blob_lists_of_the_wrong_type_are_refused() -> None:
    """Protocol L1426-L1427: `approved_tools` and `approved_resources` are arrays. Stored as
    a number, a boolean or null, one would make every later decision that reads it
    `server_error`; stored as a string or object, it would be misread (a resource whose
    identifier is a substring of an `approved_resources` string would count as
    approved)."""
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    base = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "d"}
    for name in ("approved_tools", "approved_resources"):
        for bad in (5, "https://hr.example", {"name": "x"}):
            r, _ = _approve_blob(ss, ps, base | {name: bad})
            assert r.status == 400 and r.json()["error"] == "invalid_request", (name, bad)
    r, s256 = _approve_blob(ss, ps, base | {"approved_tools": [], "approved_resources": []})
    assert r.status == 201
    _, d, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example", scope="read")
    assert d.status == 200


def test_an_update_never_writes_into_the_blob_the_ps_built() -> None:
    """Protocol L1429: the blob's members are a floor, a PS MAY add its own, and a reader
    MUST ignore members it does not recognize. The SS keeps accepted updates beside the
    blob, so a PS member that happens to share a name is neither changed nor a crash."""
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    blob = {"agent": AGENT, "approved_at": "2026-10-06T00:00:00Z", "description": "d",
            "_updates": 5}
    r, s256 = _approve_blob(ss, ps, blob)
    assert r.status == 201
    u = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": ps.nid("d"),
                                                 "iat": 1, "sub": SUB, "agent": AGENT,
                                                 "description": "also file the report"})
    assert u.status == 200 and u.json()["decision"] == "allow"
    m = ss.store.missions[Store.k(ps.issuer, s256)]
    assert m.blob == blob and m.updates == ["also file the report"]


# ------------------------------------------------------------ bytes the SS decodes itself

_DEEP = b"[" * 200_000 + b"]" * 200_000


@pytest.mark.parametrize("deep", ["payload", "header"])
def test_a_forwarded_token_nested_past_the_decoder_limit_is_refused(deep: str) -> None:
    """A resource token is a string, so the body's depth check does not reach its payload
    or header; one nested past the JSON decoder's own limit is refused, never a
    `server_error`."""
    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    head = b64u(_DEEP if deep == "header" else b'{"typ":"aa-resource+jwt","alg":"Ed25519"}')
    payload = b64u(_DEEP if deep == "payload" else b'{"iss":"https://hr.example"}')
    tok = head + "." + payload + ".sig"
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "agent_token": ps.agent_token(AGENT), "resource_token": tok,
        "presented_token": "a.b.c"})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_r3_bytes_nested_past_the_decoder_limit_are_refused() -> None:
    """The same for the R3 bytes the extension decodes, in a decision request and in a
    replayed `auth_token.issued`."""
    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock))
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
        "resource_token": ps.resource_token("https://hr.example", "read", mission_s256=s256),
        "presented_token": "a.b.c", "r3_proposal": b64u(_DEEP)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    e = ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-replayed", "iat": 1,
        "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "j",
        "aud": "https://hr.example", "exp": 3600, "issuer": ps.issuer,
        "r3_proposal": b64u(_DEEP)})
    assert e.status == 400 and e.json()["error"] == "invalid_request"


@pytest.mark.parametrize("value", [2 ** 53, -(2 ** 53), 10 ** 400])
def test_a_time_past_the_interoperable_range_is_refused_before_anything_changes(value: int) -> None:
    """I-JSON (RFC 7493 Section 2.2) bounds the integers JSON parsers hold exactly at
    2^53 - 1. A time past it is no time, refused before anything changes: an `iat` of
    10^400 must not make `decision.resolved` a `server_error` after marking the ask
    resolved, which would leave the PS's retry nothing to apply its answer to."""
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://unlisted.example")
    assert r.json()["decision"] == "ask"
    ev = {"event": "decision.resolved", "id": ps.nid("e"), "sdi": sdi, "sub": SUB,
          "agent": AGENT, "mission_s256": s256, "answer": "allow", "apply": "mission"}
    bad = ps.call(ss, "POST", "/event", ev | {"iat": value})
    assert bad.status == 400 and bad.json()["error"] == "invalid_request"
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "ask"
    assert ps.call(ss, "POST", "/event", ev | {"iat": int(clock())}).status == 201
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "resolved_allow"
    issued = ps.call(ss, "POST", "/event", {
        "event": "auth_token.issued", "id": ps.nid("e"), "sdi": sdi, "iat": int(clock()),
        "sub": SUB, "agent": AGENT, "mission_s256": s256, "jti": "j",
        "aud": "https://unlisted.example", "exp": value, "issuer": ps.issuer})
    assert issued.status == 400 and issued.json()["error"] == "invalid_request"


def test_a_parameter_too_large_for_a_float_is_not_visible() -> None:
    """`param_gt` compares a parameter as a number. A JSON integer past the float range
    (an agent can send one in a permission's `parameters`) is not visible, like a value
    that is not a number, never an OverflowError and a `server_error`."""
    rules = [{"resource": "*", "tool": "Transfer", "param_gt": {"amount": 100},
              "class": "payment"},
             {"resource": "*", "tool": "Transfer", "class": "read", "if_unknown": "payment"}]
    answers = []
    for amount in (10 ** 400, "not a number"):
        ss, ps, clock = make_env(rules=rules)
        s256 = connected((ss, ps, clock), tools=[{"name": "Transfer", "description": "x"}])
        r = ps.call(ss, "POST", "/decision", {
            "sdi": ps.nid("d"), "act": "permission", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "action": "Transfer", "parameters": {"amount": amount}})
        assert r.status == 200
        answers.append(r.json()["decision"])
    assert answers[0] == answers[1] == "ask"


@pytest.mark.parametrize("encode", [
    lambda s: b"\xef\xbb\xbf" + s.encode("utf-8"),   # UTF-8 with a byte order mark
    lambda s: s.encode("utf-16"),                     # UTF-16, with its byte order mark
    lambda s: s.encode("utf-32"),
])
def test_a_body_that_is_not_plain_utf8_json_is_refused(encode: Any) -> None:
    # JSON between systems is UTF-8 with no byte order mark (RFC 8259 Section 8.1): a body
    # in another encoding, or marked, is one a strict reader of the same signed bytes would
    # refuse, so this SS refuses it too, before anything is read from it.
    from conftest import SUB, make_env

    from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message
    from aauth_supervision_server.testing import ACCEPT_SIG
    ss, ps, clock = make_env()
    raw = encode(json.dumps({"action": "connect", "id": ps.nid("c"), "iat": int(clock()),
                             "sub": SUB}))
    headers = {"accept-signature": ACCEPT_SIG, "content-type": "application/json",
               "content-digest": content_digest(raw)}
    req = HttpRequest("POST", ps.ss_authority, "/connect", headers, raw)
    key = f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"'
    req.headers.update({k.lower(): v for k, v in sign_message(
        ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"],
        ps.key, key, req, created=int(clock())).items()})
    r = ss.handle(req)
    assert r.status == 400 and "UTF-8" in r.json()["detail"], r.body
    assert ss.store.connections == {}


def test_a_body_just_past_the_ss_s_own_depth_limit_is_refused_on_every_python() -> None:
    # 100 levels: every CPython's decoder parses them, so it is the SS's own check that
    # refuses (on 3.11 the decoder gives up first on the 2000 levels above).
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock), tools=[{"name": "Export", "description": "x"}])
    r = ps.call(ss, "POST", "/decision", {"sdi": ps.nid("d"), "act": "permission",
                                          "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                          "mission_s256": s256, "action": "Export",
                                          "parameters": _nested(100)})
    assert r.status == 400 and r.json()["detail"] == "body nests deeper than 64 levels"
