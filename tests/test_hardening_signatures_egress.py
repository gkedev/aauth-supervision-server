"""Hardening regressions: signature parameters and covered values, JWKS refetch and key
rules, egress destinations, field-line combination, store keys and policy provenance
(one test per defect)."""

from __future__ import annotations

import http.client
import threading

import pytest
from conftest import AGENT, SUB, connected, make_env, policy_cfg

from aauth_supervision_server.egress import FetchError, HttpsFetcher, _is_public
from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.http_server import serve
from aauth_supervision_server.httpsig import signature_base
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Act, Policy
from aauth_supervision_server.resolver import _find
from aauth_supervision_server.sfv import InnerList, Item, ser_bare
from aauth_supervision_server.store import HistoryEntry, Store

HR, MAIL = "https://hr.example", "https://mail.example"
UNLISTED = "https://unlisted.example"
CONNECT = {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB}


def _ask(env):
    ss, ps, clock = env
    s256 = connected(env, resources=(HR, MAIL))
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, UNLISTED)
    assert r.json()["decision"] == "ask"
    return s256, sdi


@pytest.mark.req("SUP-052")
def test_reach_not_offered_counts_once():
    env = make_env()
    ss, ps, _ = env
    s256, sdi = _ask(env)
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, "allow", "forever").status == 201
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "resolved_allow"
    assert ss.store.reach == []  # an unrecognized reach is never stored
    sdi2, r2, _ = ps.auth_token_request(ss, SUB, AGENT, s256, UNLISTED)
    assert r2.json()["decision"] == "ask"  # so it is asked again
    ps.resolved(ss, SUB, AGENT, s256, sdi2, "allow", "mission")  # an offered one works
    assert [r.value for r in ss.store.reach] == ["mission"]


@pytest.mark.req("SUP-051")
def test_answer_must_be_allow_deny_or_abandoned():
    env = make_env()
    ss, ps, _ = env
    s256, sdi = _ask(env)
    r = ps.resolved(ss, SUB, AGENT, s256, sdi, "maybe")
    assert r.status == 400
    assert ss.store.decisions[f"{ps.issuer}|{sdi}"].decision == "ask"


def test_alg_parameter_must_match_the_key():
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", CONNECT)
    req.headers["signature-input"] += ';alg="rsa-pss-sha512"'
    r = ss.handle(req)
    assert r.status == 401 and "does not match the key" in r.json()["detail"]


def test_non_ascii_covered_value_is_a_client_error():
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", CONNECT)
    req.headers["content-type"] = "application/json; charset=ütf-8"
    r = ss.handle(req)
    assert r.status == 401 and r.json()["error"] == "invalid_input"
    comps = InnerList([Item("content-type")], {"created": 1})
    with pytest.raises(SignatureError, match="not ASCII"):
        signature_base(comps, req)


def test_unknown_kid_refetch_is_rate_limited():
    ss, ps, clock = make_env()
    ps.call(ss, "POST", "/connect", CONNECT)
    fetcher = ss.resolver.fetcher
    req = ps.build("POST", "/connect", CONNECT | {"id": "c-2"})
    req.headers["signature-key"] = req.headers["signature-key"].replace(
        'kid="', 'kid="nope-')
    before = len(fetcher.calls)
    for _ in range(5):
        assert ss.handle(req).status == 401
    assert len(fetcher.calls) - before <= 2  # one refetch (metadata + JWKS), not five
    clock.t += 31
    ss.handle(req)
    assert len(fetcher.calls) - before <= 4  # the next refetch only after the interval


def test_jwks_kid_must_be_unique_and_a_signing_key():
    jwk = SigningKey.generate("k").public_jwk()
    assert _find({"keys": [jwk]}, "k") is not None
    with pytest.raises(SignatureError, match="not unique"):
        _find({"keys": [jwk, dict(jwk)]}, "k")
    with pytest.raises(SignatureError, match="not a signing key"):
        _find({"keys": [jwk | {"use": "enc"}]}, "k")


@pytest.mark.parametrize("ip, public", [
    ("8.8.8.8", True), ("2001:4860:4860::8888", True),
    ("100.64.0.1", False),  # shared address space (CGNAT)
    ("192.0.2.1", False),  # documentation
    ("::ffff:127.0.0.1", False), ("::ffff:10.0.0.1", False),  # IPv4-mapped
    ("169.254.169.254", False), ("fe80::1%eth0", False), ("0.0.0.0", False),
])
def test_egress_refuses_non_global_destinations(ip, public):
    assert _is_public(ip) is public


def test_egress_refuses_userinfo():
    with pytest.raises(FetchError, match="userinfo"):
        HttpsFetcher().fetch_json("https://user@ps.example/.well-known/aauth-person.json")


def test_connect_reads_the_ps_name_without_a_network_call():
    ss, ps, _ = make_env(auto_connect=False)
    fetcher = ss.resolver.fetcher
    ps.call(ss, "POST", "/connect", {"action": "connect", "id": "c-0", "iat": 1, "sub": "other"})
    before = len(fetcher.calls)
    r = ps.call(ss, "POST", "/connect", CONNECT)
    assert r.status == 202
    assert len(fetcher.calls) == before  # metadata already cached by key discovery
    p = next(x for x in ss.store.pending.values() if x.sub == SUB)
    assert p.request["_ps_name"] == fetcher.documents[
        ps.issuer + "/.well-known/aauth-person.json"].get("name", "")


def _send(httpd, req, extra: list[tuple[str, str]]) -> int:
    c = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
    c.putrequest(req.method, req.path, skip_host=True, skip_accept_encoding=True)
    for k, v in req.headers.items():
        c.putheader(k, v)
    for k, v in extra:
        c.putheader(k, v)
    c.putheader("Content-Length", str(len(req.body)))
    c.endheaders(req.body)
    status = c.getresponse().status
    c.close()
    return status


def test_repeated_field_lines_combine_and_host_is_single():
    ss, ps, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req = ps.build("POST", "/connect", CONNECT)
        req.headers["host"] = req.authority
        # A second Signature line with another label is combined, not substituted: the
        # PS's own signature still verifies.
        assert _send(httpd, req, [("Signature", "decoy=:AAAA:")]) == 200
        req2 = ps.build("POST", "/connect", CONNECT | {"id": "c-2"})
        req2.headers["host"] = "evil.example"  # first Host line; the real one follows
        assert _send(httpd, req2, [("Host", req2.authority)]) == 400
    finally:
        httpd.shutdown()
        httpd.server_close()



def test_store_keys_do_not_collide():
    assert Store.k("iss", "a|b", "c") != Store.k("iss", "a", "b|c")
    assert Store.k("iss", "a%7Cb") != Store.k("iss", "a|b")
    assert Store.k("https://ps.example", "d-1") == "https://ps.example|d-1"  # plain unchanged


def test_uncertain_entry_does_not_mask_a_certain_violation():
    pol = Policy(policy_cfg())
    certain = HistoryEntry("read_sensitive", HR, "resource")
    shaky = HistoryEntry("read_sensitive", HR, "configured", detail="uncertain: assumed")
    assert pol._composition("send_external", False, MAIL, [shaky, certain]) == (
        ["read_sensitive", "send_external"], False)
    assert pol._composition("send_external", False, MAIL, [shaky]) == (
        ["read_sensitive", "send_external"], True)
    w = HistoryEntry("write", "https://calendar.example", "configured")
    assert pol._composition("send_internal", False, MAIL, [shaky, certain, w])[1] is False


def test_agent_data_cannot_lower_any_rule_shape():
    # A policy author's low-severity data rule ahead of a severe catch-all.
    pol = Policy(policy_cfg(rules=[
        {"resource": "*", "tool": "Upload", "param_domain_not_in": {"to": ["evil.example"]},
         "class": "read"},
        {"resource": "*", "tool": "Upload", "class": "send_external"}]))
    claimed = Act("permission", "ps", SUB, AGENT, tool="Upload",
                  parameters={"to": "ok@corp.example"}, parameters_provenance="agent")
    c = pol.classify(claimed)
    assert c.cls == "send_external" and c.provenance == "agent"
    shown = Act("auth_token", "ps", SUB, AGENT, tool="Upload",
                parameters={"to": "ok@corp.example"}, parameters_provenance="resource")
    assert pol.classify(shown).cls == "read"  # resource-asserted data may lower it


@pytest.mark.parametrize("v, s", [(2.0, "2.0"), (1.5, "1.5"), (0.125, "0.125"), (-3.0, "-3.0")])
def test_decimal_keeps_a_fractional_digit(v, s):
    assert ser_bare(v) == s
