"""What a request can make the SS keep and write, bounded.

- The person opening the confirmation page is written (`interacting` survives a restart).
- A signer only open registration admits keeps an id only with a record it opens: its
  disconnects and repeated connects add none, and the ids go with the records.
- Such a signer's metadata `name` is kept plain and cut, as the page shows it.
- At the global cap, a new signer's connect takes the place of the oldest record of the
  signer that holds the most, so no group of names keeps every other signer out.
- A refusal writes the snapshot only after a change it follows; a retry answered from what
  is kept writes nothing.
- A proposal's and an update's `description` is bounded, and so is a tool name.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server import service
from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import SimulatedPS


def _stranger(ss: Any, clock: Any, n: int = 0, name: str = "") -> SimulatedPS:
    other = SimulatedPS(issuer=f"https://other{n}.example", transport="current", clock=clock)
    if name:
        other.name = name
    other.install(ss.resolver.fetcher)
    if name:
        ss.resolver.fetcher.documents[f"{other.issuer}/.well-known/aauth-person.json"][
            "name"] = name
    other.ss_jwk = ss.key.public_jwk()
    ss.cfg.open_registration = True
    return other


def _post(ss: Any, ps: Any, clock: Any, action: str, cid: str, sub: str) -> Any:
    return ps.call(ss, "POST", "/connect", {"action": action, "id": cid,
                                            "iat": int(clock()), "sub": sub})


def test_the_person_at_the_page_is_written(tmp_path: Path) -> None:
    ss, ps, clock = make_env(auto_connect=False)
    ss.store = Store(str(tmp_path / "ss.json"))
    r = ps.connect(ss, SUB)
    code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
    page = ss.handle(HttpRequest("GET", "ss.example", "/interaction", {}, b"", f"code={code}"))
    assert page.status == 200
    ss.store = Store(str(tmp_path / "ss.json"))           # a restart
    assert ps.call(ss, "GET", r.headers["Location"]).json() == {"status": "interacting"}


def test_a_stranger_keeps_an_id_only_with_a_record_it_opens() -> None:
    ss, _, clock = make_env()
    other = _stranger(ss, clock)
    before = len(ss.store.events_seen)
    writes = _counting(ss)
    for i in range(20):                                   # nothing to disconnect
        assert _post(ss, other, clock, "disconnect", f"d-{i}", "p").status == 200
    assert len(ss.store.events_seen) == before and writes[0] == 0
    assert _post(ss, other, clock, "connect", "c-1", "p").status == 202
    for i in range(20):                                   # answered from that record
        assert _post(ss, other, clock, "connect", f"c-x{i}", "p").status == 202
    assert len(ss.store.events_seen) == before + 1
    assert _post(ss, other, clock, "disconnect", "d-x", "p").status == 200
    assert len(ss.store.events_seen) == before + 1
    clock.t += 3 * service.CONNECT_LIFETIME              # the record goes, its id with it
    _post(ss, _stranger(ss, clock, 1), clock, "connect", "c-2", "q")
    assert not any(k.startswith(Store.k("connect", other.issuer)) for k in ss.store.events_seen)


def test_a_stranger_s_name_is_kept_plain_and_cut() -> None:
    ss, _, clock = make_env()
    other = _stranger(ss, clock, name="Acme" + chr(0x202E) + "N" * 100_000)
    assert _post(ss, other, clock, "connect", "c-1", "p").status == 202
    (p,) = (p for p in ss.store.pending.values() if p.iss == other.issuer)
    kept = p.request["_ps_name"]
    assert len(kept) <= service.MAX_NAME and chr(0x202E) not in kept


def test_at_the_global_cap_the_biggest_holder_makes_room(monkeypatch: Any) -> None:
    monkeypatch.setattr(service, "MAX_UNCONFIRMED", 4)
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 3)
    ss, _, clock = make_env()
    flood = [_stranger(ss, clock, n) for n in range(2)]
    for i in range(3):
        assert _post(ss, flood[0], clock, "connect", f"a-{i}", f"p{i}").status == 202
        clock.t += 1
    assert _post(ss, flood[1], clock, "connect", "b-0", "q0").status == 202
    honest = _stranger(ss, clock, 9)
    assert _post(ss, honest, clock, "connect", "h-0", "me").status == 202
    held = [p.iss for p in ss.store.pending.values()]
    assert held.count(flood[0].issuer) == 2 and honest.issuer in held
    # The signer holding the most is refused, not made room for.
    r = _post(ss, flood[0], clock, "connect", "a-9", "p9")
    assert r.status == 429 and r.json()["error"] == "rate_limited"


def _counting(ss: Any) -> list[int]:
    n = [0]
    save = ss.store.save

    def counted() -> None:
        n[0] += 1
        save()

    ss.store.save = counted
    return n


def test_a_refusal_writes_nothing_unless_it_follows_a_change(tmp_path: Path) -> None:
    ss, ps, clock = make_env(clarify_missing_justification=True)
    ss.store = Store(str(tmp_path / "ss.json"))
    s256 = connected((ss, ps, clock))
    writes = _counting(ss)
    assert ps.call(ss, "GET", "/pending/nothing-here").status == 404
    r = ps.call(ss, "POST", "/decision", {"sdi": "d-1", "iat": int(clock()), "sub": SUB,
                                          "agent": AGENT})
    assert r.status == 400 and writes[0] == 0
    # A retry of a question still open, and of a decision whose signature is re-made.
    _, q, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    assert q.status == 202
    n = writes[0]
    body = ps.sent[-1][1]
    assert ps.call(ss, "POST", "/decision", body).status == 202 and writes[0] == n
    _, a, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    n = writes[0]
    reordered = dict(reversed(list(ps.sent[-1][1].items())))
    for _ in range(2):                                   # re-signed, nothing kept
        assert ps.call(ss, "POST", "/decision", reordered).status == 200
    assert writes[0] == n


@pytest.mark.parametrize("where", ["proposal", "update"])
def test_a_description_past_the_bound_is_refused(where: str) -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    text = "x" * (service.MAX_DESCRIPTION + 1)
    if where == "proposal":
        r = ps.call(ss, "POST", "/mission", {
            "sdi": "d-p", "iat": int(clock()), "sub": SUB, "agent": AGENT,
            "agent_token": ps.agent_token(AGENT), "description": text, "resources": [],
            "tools": []})
    else:
        r = ps.call(ss, "POST", f"/mission/{s256}", {
            "action": "update", "sdi": "d-u", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "description": text})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_tool_name_past_the_bound_is_refused() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    r = ps.call(ss, "POST", "/event", {"event": "audit.recorded", "id": "e-1",
                                       "iat": int(clock()), "sub": SUB, "agent": AGENT,
                                       "mission_s256": s256,
                                       "action": "T" * (service.MAX_TOOL_NAME + 1)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_proposal_s_tools_are_bounded_like_its_description() -> None:
    ss, ps, clock = make_env()
    connected((ss, ps, clock))
    each = service.MAX_TOOLS // 16
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-t", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "x", "resources": [],
        "tools": [{"name": f"T{i}", "description": "d" * each} for i in range(17)]})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_an_approved_mission_past_the_bound_is_refused() -> None:
    import hashlib
    import json

    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env()
    connected((ss, ps, clock))
    blob = {"agent": AGENT, "description": "x" * service.MAX_MISSION, "approved_tools": []}
    raw = json.dumps(blob).encode()
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": "e-big", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def _named(ss: Any, clock: Any, host: str) -> SimulatedPS:
    ps = SimulatedPS(issuer=f"https://{host}", transport="current", clock=clock)
    ps.install(ss.resolver.fetcher)
    ps.ss_jwk = ss.key.public_jwk()
    ss.cfg.open_registration = True
    return ps


def test_names_under_one_domain_cannot_push_an_honest_connect_out(monkeypatch: Any) -> None:
    # Names made under one domain (a wildcard DNS entry makes any number) are one signer
    # at the global cap: they can fill it, but not push an honest connect out.
    monkeypatch.setattr(service, "MAX_UNCONFIRMED", 4)
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 3)
    for parent in ("evil.example", "evil.co.uk"):
        ss, _, clock = make_env()
        flood = [_named(ss, clock, f"a{i}.{parent}") for i in range(4)]
        for i, ps in enumerate(flood):
            assert _post(ss, ps, clock, "connect", f"c-{i}", "p").status == 202
        honest = _named(ss, clock, "ps.bank.co.uk")
        assert _post(ss, honest, clock, "connect", "h-0", "me").status == 202
        for i, ps in enumerate(flood):
            _post(ss, ps, clock, "connect", f"c-again-{i}", "q")
        assert honest.issuer in [p.iss for p in ss.store.pending.values()], parent


def test_a_signer_under_a_shared_suffix_holds_only_its_own_share(monkeypatch: Any) -> None:
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 3)
    ss, _, clock = make_env()
    mallory, alice = _named(ss, clock, "mallory.github.io"), _named(ss, clock, "alice.github.io")
    for i in range(3):
        assert _post(ss, mallory, clock, "connect", f"m-{i}", f"p{i}").status == 202
    assert _post(ss, mallory, clock, "connect", "m-9", "p9").status == 429
    assert _post(ss, alice, clock, "connect", "a-0", "me").status == 202


def test_a_token_s_scope_and_a_proposal_s_operations_are_bounded() -> None:
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock))
    many = " ".join(f"s{i}" for i in range(service.MAX_LIST + 1))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example", scope=many)
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    ops = {"operations": [{"operationId": f"op{i}"} for i in range(service.MAX_LIST + 1)]}
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example", proposal=ops)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_the_domain_a_signer_s_name_is_made_under() -> None:
    from aauth_supervision_server.resolver import signer_domain
    assert signer_domain("https://a.b.evil.example") == "evil.example"
    assert signer_domain("https://ps.bank.co.uk") == "bank.co.uk"
    assert signer_domain("https://ps.bank.com.au") == "bank.com.au"
    # A short domain under a two-letter TLD is one domain, whatever names it makes.
    assert signer_domain("https://n1.abc.io") == signer_domain("https://n2.abc.io") == "abc.io"
    assert signer_domain("https://x.t.co") == "t.co"
    assert signer_domain("https://x.y.a1.de") == "a1.de"
    # Under a hosting suffix each site is its own.
    assert signer_domain("https://alice.github.io") == "alice.github.io"
    assert signer_domain("https://ps.mallory.vercel.app") == "mallory.vercel.app"
    assert signer_domain("https://EXAMPLE.org.") == "example.org"
    assert signer_domain("https://127.0.0.1") == "127.0.0.1"
    assert signer_domain("https://[::1") == "https://[::1"     # not a URL urllib reads


def test_text_is_bounded_by_the_size_it_is_kept_at() -> None:
    # A character outside the Basic Multilingual Plane is kept as two escapes (12 bytes):
    # the bound is on what is kept, not on the count of characters.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    emoji = chr(0x1F600) * (service.MAX_DESCRIPTION // 6)
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "update", "sdi": "d-u", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "description": emoji})
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-t", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "x", "resources": [],
        "tools": [{"name": "T", "description": chr(0x1F600) * (service.MAX_TOOLS // 6)}]})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_the_members_kept_from_events_are_bounded() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "terminated", "id": "e-t", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "reason": "r" * (service.MAX_DESCRIPTION + 1)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"
    r = ps.call(ss, "POST", "/event", {
        "event": "agent.bound", "id": "e-b", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_iss": "https://ap.example", "agent_sub": "s" * (service.MAX_ID_LEN + 1)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_refused_issuance_report_changes_nothing() -> None:
    # A report with no decision on record books its audiences; one refused for its scope
    # must not have widened an audience already booked before it is refused.
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))

    def report(auds: list[str], exp: int, scope: str) -> Any:
        return ps.call(ss, "POST", "/event", {
            "event": "auth_token.issued", "id": ps.nid("e"), "sdi": "d-x", "jti": "t-1",
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "mission_s256": s256,
            "aud": auds, "exp": exp, "scope": scope})

    assert report(["https://hr.example"], int(clock()) + 600, "a").status == 201
    many = " ".join(f"s{i}" for i in range(service.MAX_LIST + 1))
    r = report(["https://hr.example", "https://mail.example"], int(clock()) + 9000, many)
    assert r.status == 400
    (h,) = (h for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256) if h.sdi == "d-x")
    assert h.token_exp == int(clock()) + 600


def test_only_connects_awaiting_confirmation_count_against_a_signer(monkeypatch: Any) -> None:
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 2)
    ss, _, clock = make_env()
    other = _stranger(ss, clock)
    for i in range(4):
        assert _post(ss, other, clock, "connect", f"c-{i}", f"p{i}").status == 202
        (p,) = (p for p in ss.store.pending.values()
                if p.iss == other.issuer and not p.resolved)
        p.resolved = "allow"                              # the person confirmed it


def test_an_approved_mission_is_bounded_by_the_size_it_is_kept_at() -> None:
    import hashlib
    import json

    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env()
    connected((ss, ps, clock))
    blob = {"agent": AGENT, "description": "é" * (service.MAX_MISSION // 3)}
    raw = json.dumps(blob, ensure_ascii=False).encode()
    assert len(raw) < service.MAX_MISSION
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": "e-big2", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_an_approved_mission_of_many_small_values_is_refused() -> None:
    # The blob is kept parsed: what it costs is the number of values, not only its bytes.
    import hashlib
    import json

    from aauth_supervision_server.jwk import b64u
    ss, ps, clock = make_env()
    connected((ss, ps, clock))
    blob = {"agent": AGENT, "description": "x", "approved_tools": [[]] * 50_000}
    raw = json.dumps(blob, separators=(",", ":")).encode()
    assert len(raw) < service.MAX_MISSION
    s256 = b64u(hashlib.sha256(raw).digest())
    r = ps.call(ss, "POST", f"/mission/{s256}", {
        "action": "approved", "id": "e-many", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "s256": s256, "mission": b64u(raw)})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_proposal_whose_mission_would_hold_too_many_values_is_refused() -> None:
    # The SS echoes an allowed proposal's tools whole in the mission it approves
    # (Supervision L397-L420): tools within the byte bound but past what an approved
    # mission may hold in values are refused at the proposal, not after the person
    # approved them (the approved mission would then be refused, and never usable).
    ss, ps, clock = make_env()
    connected((ss, ps, clock))
    schema = {"type": "object", "properties": {"x": {"enum": ["a"] * 520}}}
    tools = [{"name": f"T{i}", "description": "d", "inputSchema": schema} for i in range(20)]
    assert service._kept_len(tools) <= service.MAX_TOOLS
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-v", "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "x", "resources": [],
        "tools": tools})
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_a_connect_failed_by_wrong_operator_tokens_still_counts_against_its_signer(
        monkeypatch: Any) -> None:
    # Five wrong tokens fail a connect (Protocol L2398). Were a failed connect no longer
    # held against its signer, it could open another, with a fresh code, and guess on
    # without end. It counts until its record goes, as one awaiting confirmation does.
    monkeypatch.setattr(service, "MAX_UNCONFIRMED_PER_PS", 3)
    ss, _, clock = make_env()
    ss.cfg.admin_token = "operator-secret"
    mallory = _stranger(ss, clock)
    for i in range(3):
        r = _post(ss, mallory, clock, "connect", f"m-{i}", f"p{i}")
        assert r.status == 202
        code = r.headers["AAuth-Requirement"].split('code="')[1].rstrip('"')
        for _ in range(service.MAX_OPERATOR_FAILURES):
            guess = ss.handle(HttpRequest("POST", "ss.example", "/interaction", {},
                                          f"code={code}&admin_token=guess".encode()))
            assert guess.status == 403
    r = _post(ss, mallory, clock, "connect", "m-9", "p9")
    assert r.status == 429 and r.json()["error"] == "rate_limited"
