"""Service edges the end-to-end suites pass through without pinning.

Discovery endpoints, routing, per-PS rate limiting, connect acceptance, and the
development interaction page: each answer's exact status, headers and effect.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import SUB, Clock, policy_cfg

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import MAX_OPERATOR_FAILURES, ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.store import Store
from aauth_supervision_server.testing import SimulatedPS


def make(sign: bool = True, trust: TrustedPS | None = None, **cfg: Any
         ) -> tuple[SupervisionServer, SimulatedPS, Clock]:
    clock = Clock()
    fetcher = StaticFetcher()
    ps = SimulatedPS(clock=clock)
    ps.install(fetcher)
    key = SigningKey.generate("ss-key-1") if sign else None
    config = ServerConfig(issuer="https://ss.example",
                          trusted_ps={ps.issuer: trust or TrustedPS(auto_connect=True)},
                          admin_token="operator-secret", **cfg)
    ss = SupervisionServer(config, Policy(policy_cfg()), JwksUriResolver(fetcher), key,
                           clock=clock)
    if key:
        ps.ss_jwk = key.public_jwk()
    return ss, ps, clock


def get(ss: SupervisionServer, path: str, query: str = "", method: str = "GET",
        body: bytes = b"") -> Any:
    return ss.handle(HttpRequest(method, "ss.example", path, {}, body, query))


# ---------------------------------------------------------------- discovery


def test_metadata_endpoint() -> None:
    ss, _, _ = make(documentation_uri="https://ss.example/docs")
    r = get(ss, "/.well-known/aauth-supervisor.json")
    assert r.status == 200 and r.headers["Cache-Control"] == "max-age=300"
    md = r.json()
    assert md["documentation_uri"] == "https://ss.example/docs"
    assert md["jwks_uri"] == "https://ss.example/.well-known/jwks.json"
    assert md["name"] == "AAuth APC Supervisor"


def test_metadata_omits_what_is_not_configured() -> None:
    ss, _, _ = make(sign=False)
    md = get(ss, "/.well-known/aauth-supervisor.json").json()
    assert "documentation_uri" not in md and "jwks_uri" not in md


def test_jwks_endpoint() -> None:
    ss, _, _ = make()
    r = get(ss, "/.well-known/jwks.json")
    assert r.status == 200 and r.headers["Cache-Control"] == "max-age=300"
    assert r.json()["keys"] == [ss.key.public_jwk()]  # type: ignore[union-attr]
    unsigned, _, _ = make(sign=False)
    assert get(unsigned, "/.well-known/jwks.json").json() == {"keys": []}


def test_health_is_get_only() -> None:
    ss, _, _ = make()
    r = get(ss, "/health")
    assert r.status == 200 and r.json() == {"status": "ok"}
    assert get(ss, "/health/").status == 200  # a trailing slash is the same path
    assert get(ss, "/health", method="POST").status != 200


def test_an_unknown_endpoint_is_a_plain_404_not_an_aauth_error_code() -> None:
    # Supervision L631 pairs `invalid_request` with 400: a 404 must not carry it. A path
    # the SS does not serve is no Supervision request, so it gets HTTP's own 404 with an
    # RFC 9457 body and no AAuth `error` (the PS reads an unlisted status as
    # `server_error`, L639, and treats the SS as unavailable, as for invalid_request).
    ss, ps, _ = make()
    r = ps.call(ss, "POST", "/nothing-here", {"x": 1})
    assert r.status == 404 and r.headers["Content-Type"] == "application/problem+json"
    assert r.json() == {"type": "about:blank", "title": "Not Found", "status": 404}
    # A resource the SS serves, with a method it does not: 405, naming those it does.
    r = get(ss, "/pending/abc", method="HEAD")
    assert r.status == 405 and r.headers["Allow"] == "GET, POST, DELETE"
    assert r.json() == {"error": "invalid_request", "type": "about:blank",
                        "title": "Method Not Allowed", "status": 405}
    # A method the server implements nowhere: 501 (RFC 9110 9.1).
    assert ps.call(ss, "PUT", "/pending/abc", {"x": 1}).status == 501


def test_pending_poll_needs_no_body_but_a_post_does() -> None:
    ss, ps, _ = make()
    assert ps.call(ss, "GET", "/pending/unknown").status == 404  # reached the handler
    r = ps.call(ss, "POST", "/pending/unknown")
    assert r.status == 400 and r.json()["detail"] == "missing body"


# ------------------------------------------------------------- rate limiting


def test_rate_limit_counts_per_minute_and_reports_retry_after() -> None:
    ss, ps, clock = make(rate_limit_per_minute=2)
    assert ps.connect(ss, SUB).status == 200
    clock.t += 10
    assert ps.connect(ss, SUB).status == 200
    clock.t += 5
    r = ps.connect(ss, SUB)
    assert r.status == 429 and r.json()["error"] == "rate_limited"
    assert r.headers["Retry-After"] == "45"  # the first request leaves the window at +60
    clock.t += 44.5
    assert ps.connect(ss, SUB).status == 429  # 59.5 s after the first: still inside
    clock.t += 0.5
    assert ps.connect(ss, SUB).status == 200  # exactly 60 s: the first has left the window


def test_rate_limit_of_one_and_minimum_retry_after() -> None:
    ss, ps, clock = make(rate_limit_per_minute=1)
    assert ps.connect(ss, SUB).status == 200
    clock.t += 59.9
    r = ps.connect(ss, SUB)
    assert r.status == 429 and r.headers["Retry-After"] == "1"  # never 0


def test_a_throttled_poll_is_slow_down_not_rate_limited() -> None:
    """Supervision L639: "Polling a pending URL uses the polling error codes of the AAuth
    Protocol", whose code for polling too often is `slow_down`, 429 (Protocol L2626).
    `rate_limited` stays the answer on the other endpoints (Supervision L636)."""
    ss, ps, clock = make(trust=TrustedPS(), rate_limit_per_minute=2)
    loc = ps.connect(ss, SUB).headers["Location"]
    assert ps.call(ss, "GET", loc).status == 202
    r = ps.call(ss, "GET", loc)
    assert r.status == 429 and r.json()["error"] == "slow_down"
    assert r.headers["Retry-After"] == "60"
    assert ps.connect(ss, SUB).json()["error"] == "rate_limited"


def test_no_rate_limit_by_default() -> None:
    ss, ps, _ = make()
    assert all(ps.connect(ss, SUB).status == 200 for _ in range(30))


# ------------------------------------------------------------------- connect


def _connect(ss: SupervisionServer, ps: SimulatedPS, **extra: Any) -> Any:
    return ps.call(ss, "POST", "/connect", {"action": "connect", "id": ps.nid("c"),
                                            "iat": int(ps.clock()), "sub": SUB, **extra})


def test_auto_connect_and_disconnect() -> None:
    ss, ps, _ = make()
    r = _connect(ss, ps)
    assert r.status == 200 and r.json() == {"status": "connected"}
    assert Store.k(ps.issuer, SUB) in ss.store.connections
    r = ps.call(ss, "POST", "/connect", {"action": "disconnect", "id": ps.nid("c"),
                                         "iat": int(ps.clock()), "sub": SUB})
    assert r.status == 200 and r.json() == {"status": "disconnected"}
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


def test_tenant_acceptance_connects_only_listed_tenants() -> None:
    ss, ps, _ = make(trust=TrustedPS(tenants=["acme"]))
    assert _connect(ss, ps, tenant="other").status == 202
    ss2, ps2, _ = make(trust=TrustedPS(tenants=["acme"]))
    r = _connect(ss2, ps2, tenant="acme")
    assert r.status == 200 and ss2.store.connections[Store.k(ps2.issuer, SUB)]["tenant"] == "acme"


def test_a_retried_connect_reports_the_current_state() -> None:
    ss, ps, _ = make()
    body = {"action": "connect", "id": "c-fixed", "iat": int(ps.clock()), "sub": SUB}
    first, again = ps.call(ss, "POST", "/connect", body), ps.call(ss, "POST", "/connect", body)
    assert first.status == again.status == 200
    assert first.json() == again.json() == {"status": "connected"}
    ps.call(ss, "POST", "/connect", {"action": "disconnect", "id": "d-1",
                                     "iat": int(ps.clock()), "sub": SUB})
    r = ps.call(ss, "POST", "/connect", body)
    assert r.status == 200 and r.json() == {"status": "disconnected"}


def test_a_retried_connect_while_pending_reports_pending() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    other = ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c-other",
                                             "iat": int(ps.clock()), "sub": "someone-else"})
    body = {"action": "connect", "id": "c-fixed", "iat": int(ps.clock()), "sub": SUB}
    first = ps.call(ss, "POST", "/connect", body)
    again = ps.call(ss, "POST", "/connect", body)
    assert first.status == again.status == 202
    assert first.headers["Location"] == again.headers["Location"]
    assert again.headers["Location"] != other.headers["Location"]


def test_a_second_connect_reuses_the_open_pending() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    a, b = _connect(ss, ps), _connect(ss, ps)
    assert a.headers["Location"] == b.headers["Location"]
    assert sum(1 for p in ss.store.pending.values() if p.kind == "connect") == 1


@pytest.mark.req("REF-046")
def test_pending_connect_response_shape() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    r = _connect(ss, ps)
    assert r.status == 202 and r.json() == {"status": "pending"}
    assert r.headers["Retry-After"] == "5" and r.headers["Cache-Control"] == "no-store"
    assert r.headers["Location"].startswith("/pending/")
    assert 'url="https://ss.example/interaction"' in r.headers["AAuth-Requirement"]


# --------------------------------------------------------- interaction page


def _pending_code(ss: SupervisionServer) -> str:
    return next(p.code for p in ss.store.pending.values() if p.kind == "connect")


def _form(code: str, token: str) -> bytes:
    return f"code={code}&admin_token={token}".encode()


def test_interaction_confirms_a_pending_connect() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    _connect(ss, ps)
    code = _pending_code(ss)
    page = get(ss, "/interaction", query=f"code={code}")
    assert page.status == 200 and code.encode() in page.body
    assert page.headers["Cache-Control"] == "no-store"
    # The confirmation page must not be framed by another origin (clickjacking).
    assert page.headers["X-Frame-Options"] == "DENY"
    assert page.headers["Content-Security-Policy"] == "frame-ancestors 'none'"
    # Any token, including one that is not ASCII, is refused cleanly, never a 500.
    wrong = get(ss, "/interaction", method="POST", body=_form(code, "%C3%A9"))
    assert wrong.status == 403 and code in {p.code for p in ss.store.pending.values()}
    done = get(ss, "/interaction", method="POST", body=_form(code, "operator-secret"))
    assert done.status == 200 and done.body == b"Connected.\n"
    assert ss.store.connections[Store.k(ps.issuer, SUB)] == {
        "iss": ps.issuer, "sub": SUB, "tenant": None, "at": int(ps.clock())}
    # The code is now used: neither the page nor a second confirmation accepts it
    # (Protocol L2396: `invalid_code`, 410 per L2625).
    used = get(ss, "/interaction", query=f"code={code}")
    assert used.status == 410 and used.json()["error"] == "invalid_code"
    again = get(ss, "/interaction", method="POST", body=_form(code, "operator-secret"))
    assert again.status == 410 and again.json()["error"] == "invalid_code"


def test_interaction_refuses_without_the_operator_token() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    _connect(ss, ps)
    code = _pending_code(ss)
    for token in ("", "wrong"):
        r = get(ss, "/interaction", method="POST", body=_form(code, token))
        assert r.status == 403
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


def test_interaction_fails_a_connect_after_repeated_wrong_operator_tokens() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    _connect(ss, ps)
    code = _pending_code(ss)
    for _ in range(MAX_OPERATOR_FAILURES):
        assert get(ss, "/interaction", method="POST", body=_form(code, "guess")).status == 403
    # That connect failed for good: even the right token is refused for its code now, so
    # the token cannot be guessed against it (Protocol L2398).
    late = get(ss, "/interaction", method="POST", body=_form(code, "operator-secret"))
    assert late.status == 410 and late.json()["error"] == "invalid_code"
    assert Store.k(ps.issuer, SUB) not in ss.store.connections


def test_a_correct_operator_token_resets_the_failure_count() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    _connect(ss, ps)
    for _ in range(MAX_OPERATOR_FAILURES - 1):
        get(ss, "/interaction", method="POST", body=_form("unknown", "guess"))
    assert get(ss, "/interaction", method="POST", body=_form("unknown", "operator-secret")).status == 410
    for _ in range(MAX_OPERATOR_FAILURES - 1):
        get(ss, "/interaction", method="POST", body=_form("unknown", "guess"))
    done = get(ss, "/interaction", method="POST", body=_form(_pending_code(ss), "operator-secret"))
    assert done.status == 200


def test_interaction_with_no_operator_token_configured_refuses_everyone() -> None:
    ss, ps, _ = make(trust=TrustedPS())
    ss.cfg.admin_token = ""
    _connect(ss, ps)
    r = get(ss, "/interaction", method="POST", body=_form(_pending_code(ss), ""))
    assert r.status == 403


def test_interaction_unknown_code_and_method() -> None:
    ss, _, _ = make()
    r = get(ss, "/interaction", query="code=NOPE")
    # Protocol L2625: `invalid_code`, 410, "Interaction code not recognized or already
    # consumed", in the Error Response Format.
    assert r.status == 410 and r.json() == {"error": "invalid_code",
                                            "detail": "unknown or used code"}
    r = get(ss, "/interaction", method="DELETE")
    assert r.status == 405 and r.headers["Allow"] == "GET, HEAD, POST"


# -------------------------------------------------------------- config load


@pytest.mark.parametrize("member", ["signature_window", "rate_limit_per_minute",
                                    "clarification_rounds", "clarification_timeout"])
def test_server_config_integers_may_be_zero_but_not_negative(member: str) -> None:
    assert getattr(ServerConfig.from_dict({"issuer": "https://ss.example", member: 0}),
                   member) == 0
    with pytest.raises(ValueError, match="must not be negative"):
        ServerConfig.from_dict({"issuer": "https://ss.example", member: -1})


def test_server_config_trusted_ps_shapes() -> None:
    base = {"issuer": "https://ss.example"}
    cfg = ServerConfig.from_dict(base | {"trusted_ps": {"https://ps.example": {}}})
    assert cfg.trusted_ps["https://ps.example"] == TrustedPS()
    for bad in ({"auto_connect": "yes"}, {"tenants": "acme"}, {"tenants": [1]},
                {"extra": True}, []):
        with pytest.raises(ValueError, match="trusted_ps"):
            ServerConfig.from_dict(base | {"trusted_ps": {"https://ps.example": bad}})


def test_posts_with_no_live_code_cannot_lock_the_interaction_page() -> None:
    # The lock bounds guessing the operator token against connects awaiting confirmation:
    # a post that names no live code is refused as such and never counts, so a client with
    # no code cannot lock the page for the operator.
    ss, ps, _ = make(trust=TrustedPS())
    _connect(ss, ps)
    for code in ("", "NOPE") * MAX_OPERATOR_FAILURES:
        r = get(ss, "/interaction", method="POST", body=_form(code, "guess"))
        assert r.status == 410 and r.json()["error"] == "invalid_code"
    done = get(ss, "/interaction", method="POST", body=_form(_pending_code(ss), "operator-secret"))
    assert done.status == 200 and done.body == b"Connected.\n"


def test_wrong_tokens_against_one_connect_fail_that_connect_only() -> None:
    # Protocol L2398: after a few failed attempts the pending interaction fails for good
    # and its code is `invalid_code` from then on. Only that one: the page stays open for
    # every other connect, so whoever holds one live code (any signer, under open
    # registration) cannot stop the operator confirming the others.
    ss, ps, _ = make(trust=TrustedPS())
    first = _connect(ss, ps)
    code = _pending_code(ss)
    for _ in range(MAX_OPERATOR_FAILURES):
        assert get(ss, "/interaction", method="POST", body=_form(code, "guess")).status == 403
    late = get(ss, "/interaction", method="POST", body=_form(code, "operator-secret"))
    assert late.status == 410 and late.json()["error"] == "invalid_code"
    poll = ps.call(ss, "GET", first.headers["Location"])
    assert poll.status == 403 and poll.json()["error"] == "denied"
    other = "8f14e45fceea167a5a36dedd4bea2544"
    ps.call(ss, "POST", "/connect", {"action": "connect", "id": ps.nid("c"),
                                     "iat": int(ps.clock()), "sub": other})
    code2 = next(p.code for p in ss.store.pending.values()
                 if p.kind == "connect" and p.sub == other)
    done = get(ss, "/interaction", method="POST", body=_form(code2, "operator-secret"))
    assert done.status == 200 and done.body == b"Connected.\n"


def test_wrong_tokens_against_a_connect_are_kept_with_its_record(tmp_path: Any) -> None:
    # The count goes where the connect goes: dropped with its record, so codes that expire
    # after a wrong token or two leave nothing behind, and kept in the snapshot with it,
    # so a restart gives no one five more tries.
    ss, ps, clock = make(trust=TrustedPS())
    path = str(tmp_path / "ss.json")
    ss.store = Store(path)
    _connect(ss, ps)
    code = _pending_code(ss)
    for _ in range(MAX_OPERATOR_FAILURES - 1):
        assert get(ss, "/interaction", method="POST", body=_form(code, "guess")).status == 403
    ss.store.save()
    again = SupervisionServer(ss.cfg, ss.policy, ss.resolver, ss.key, Store(path), clock=clock)
    assert get(again, "/interaction", method="POST", body=_form(code, "guess")).status == 403
    late = get(again, "/interaction", method="POST", body=_form(code, "operator-secret"))
    assert late.status == 410 and late.json()["error"] == "invalid_code"
