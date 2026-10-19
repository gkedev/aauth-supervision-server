"""Hardening regressions: budget amounts, multiple signature labels, mission list
types, high-impact permissions, deny globs and signer ids (one test per defect)."""

from __future__ import annotations

import pytest
from conftest import AGENT, SUB, make_env, policy_cfg

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.httpsig import sign_message
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Act, Policy
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.store import Mission

PAY = "https://pay.example"
CONNECT = {"action": "connect", "id": "c-1", "iat": 1, "sub": SUB}


def _mission(**blob):
    return Mission("m", AGENT, SUB, "ps", blob={"approved_resources": [PAY], **blob})


def _pay(amount):
    return Act("auth_token", "ps", SUB, AGENT, resource=PAY, operations=["pay"],
               parameters={"amount": amount}, parameters_provenance="resource")


@pytest.mark.parametrize("amount", [-1_000_000, "-5", True, 1.5, "1e9", "١٢"])
def test_unreadable_or_negative_amount_is_not_counted(amount):
    pol = Policy(policy_cfg())
    c = pol.classify(_pay(amount))
    assert c.cls == "payment" and c.amount is None
    d = pol.decide(_pay(amount), _mission(), [], [], now=1.0)
    assert d.decision == "ask"  # the budget cannot be checked, so the person is asked


def test_readable_amounts_count_and_one_over_the_ceiling_is_denied():
    pol = Policy(policy_cfg())
    assert pol.classify(_pay(600_000)).amount == 600_000
    assert pol.classify(_pay(2.0)).amount == 2 and pol.classify(_pay("7")).amount == 7
    d = pol.decide(_pay(600_000), _mission(), [], [], now=1.0)
    assert d.decision == "deny" and "Budget exceeded" in d.reason


def test_the_ps_signature_verifies_when_it_is_not_the_first_label():
    # Signature-Key -09 Section 3.2: several signatures, the complete Signature-Key set
    # before any is created, each covering signature-key. The PS signature comes second.
    ss, ps, clock = make_env()
    req = ps.build("POST", "/connect", CONNECT)
    names = ["@method", "@authority", "@path", "signature-key", "content-digest", "content-type"]
    other = SigningKey.generate("other")
    sk = ('a=jwks_uri;id="https://other.example";dwk="aauth-person.json";kid="other", '
          f'sig=jwks_uri;id="{ps.issuer}";dwk="aauth-person.json";kid="{ps.key.kid}"')
    ha = sign_message(names, other, sk, req, label="a", created=int(clock()))
    hs = sign_message(names, ps.key, sk, req, label="sig", created=int(clock()))
    req.headers["signature-key"] = sk
    for h in ("Signature-Input", "Signature"):
        req.headers[h.lower()] = ha[h] + ", " + hs[h]
    r = ss.handle(req)
    assert r.status == 200, r.body


def test_too_many_labels_are_refused():
    ss, ps, _ = make_env()
    req = ps.build("POST", "/connect", CONNECT)
    for i in range(5):
        for h, v in (("signature-input", f'x{i}=("@method");created=1'),
                     ("signature", f"x{i}=:AAAA:"),
                     ("signature-key", f'x{i}=jwks_uri;id="https://a.example";dwk="d";kid="k"')):
            req.headers[h] = v + ", " + req.headers[h]
    r = ss.handle(req)
    assert r.status == 401 and "more than" in r.json()["detail"]


@pytest.mark.parametrize("field", ["resources", "tools"])
def test_non_array_mission_lists_are_a_client_error(field):
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    body = {"sdi": "p-1", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": "x",
            "description": "# d", field: 123}
    r = ps.call(ss, "POST", "/mission", body)
    assert r.status == 400 and r.json()["error"] == "invalid_request"


def test_high_impact_permission_is_put_to_the_person():
    pol = Policy(policy_cfg())
    mission = _mission(approved_tools=[{"name": "SendEmail"}])
    act = Act("permission", "ps", SUB, AGENT, tool="SendEmail",
              parameters={"to": "x@outside.example"}, parameters_provenance="agent")
    assert pol.decide(act, mission, [], [], now=1.0).decision == "ask"
    internal = Act("permission", "ps", SUB, AGENT, tool="SendEmail",
                   parameters={"to": "x@corp.example"}, parameters_provenance="agent")
    # Agent data cannot lower a class, so an internal-looking send is still high impact.
    assert pol.decide(internal, mission, [], [], now=1.0).decision == "ask"
    read = Act("permission", "ps", SUB, AGENT, tool="WebSearch", parameters_provenance="agent")
    assert pol.decide(read, _mission(approved_tools=[{"name": "WebSearch"}]), [], [],
                      now=1.0).decision == "allow"


def test_person_token_without_resource_is_not_matched_by_deny_globs():
    pol = Policy(policy_cfg(deny_resources=["*"]))
    act = Act("person_token", "ps", SUB, AGENT, resource="")
    assert pol.decide(act, None, [], [], now=1.0).decision != "deny"
    assert pol.decide(Act("person_token", "ps", SUB, AGENT, resource=PAY), None, [], [],
                      now=1.0).decision == "deny"


@pytest.mark.parametrize("sid", ["https://ps.example?x=1", "https://ps.example#f",
                                 "https://u@ps.example"])
def test_signer_id_with_query_fragment_or_userinfo_is_refused(sid):
    res = JwksUriResolver(StaticFetcher())
    with pytest.raises(SignatureError, match="userinfo, query or fragment"):
        res.resolve(sid, "aauth-person.json", "k", 1.0)
