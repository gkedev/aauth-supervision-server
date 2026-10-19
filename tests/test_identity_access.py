"""Person tokens at resources that serve on identity (Person Identity Access).

A resource may serve a request on a person token alone (Protocol L326-L346: "No resource
token, no auth token"), so for such a resource the SS's only sight of the access is the
token's issuance (`person_token.issued`, Supervision L539), including the person tokens
the PS issues for approved resources at mission approval (Protocol L1415). A policy lists
those resources (`serves_on_identity`); a person token for one joins history as an
uncertain act of the resource's class, usable until its `exp`: it can make a later act be
asked, never denied, and it spends no budget. A person token for any other resource is an
identity check and changes nothing.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.cli import validate_policy
from aauth_supervision_server.policy import Act, Policy, PolicyConfig, SupervisionPolicy

REC, DOCS, CHAT = "https://records.example", "https://docs.example", "https://chat.example"
PAY, INF = "https://pay.example", "https://inference.example"
RULES = [{"resource": REC, "class": "read_sensitive"},
         {"resource": DOCS, "class": "write"},
         {"resource": CHAT, "class": "send_internal"},
         {"resource": PAY, "class": "payment"},
         {"resource": INF, "class": "read"}]


def _env(**over: Any) -> tuple[Any, Any, Any, str]:
    over.setdefault("prohibited_pairs", [["read_sensitive", "send_internal"]])
    over.setdefault("prohibited_sequences", [])
    over.setdefault("high_impact", [])
    over.setdefault("serves_on_identity", [REC, PAY, INF])
    over.setdefault("allow_unlisted_resources", True)
    ss, ps, clock = make_env(rules=RULES, **over)
    # A mission that names no resource serving on identity: its approval issues no person
    # token that is an act (Supervision L417; `tests/test_approval_person_tokens.py`), so
    # these tests about reported person tokens start with nothing read.
    s256 = connected((ss, ps, clock), resources=(DOCS, CHAT))
    return ss, ps, clock, s256


def _person_token(ss: Any, ps: Any, clock: Any, s256: str, aud: Any, jti: str = "pt-1",
                  exp: int | None = 3600, sdi: str = "d-pt") -> int:
    body = {"event": "person_token.issued", "id": ps.nid("e"), "sdi": sdi,
            "iat": int(clock()), "sub": SUB, "agent": AGENT, "jti": jti, "aud": aud}
    if s256:
        body["mission_s256"] = s256
    if exp is not None:
        body["exp"] = int(clock()) + exp
    return int(ps.call(ss, "POST", "/event", body).status)


def _take(ss: Any, ps: Any, s256: str, resource: str, **kw: Any) -> str:
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource, **kw)
    d = str(r.json()["decision"])
    if d == "allow":
        assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
    return d


def test_a_person_token_where_the_resource_serves_on_identity_composes_as_uncertain() -> None:
    ss, ps, clock, s256 = _env()
    assert _person_token(ss, ps, clock, s256, REC) == 201
    # Certain rules on both sides: with an auth token at REC this would be denied.
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, CHAT)
    d = r.json()
    assert d["decision"] == "ask" and "`read_sensitive`, then `send_internal`" in d["summary"]
    (h,) = ss.store.history_for(ps.issuer, SUB, AGENT, s256)
    assert (h.action_class, h.resource, h.jti) == ("read_sensitive", REC, "pt-1")
    assert h.detail.startswith("uncertain") and h.token_exp == int(clock()) + 3600


def test_a_person_token_for_any_other_resource_changes_nothing() -> None:
    ss, ps, clock, s256 = _env(serves_on_identity=[])
    assert _person_token(ss, ps, clock, s256, REC) == 201
    assert ss.store.history_for(ps.issuer, SUB, AGENT, s256) == []
    assert _take(ss, ps, s256, CHAT) == "allow"


def test_outside_missions_and_on_replay_too() -> None:
    # Outside any mission, and with no decision under the sdi (a routing change replays
    # outstanding person tokens, Supervision L619): the same act.
    ss, ps, clock, s256 = _env()
    assert _person_token(ss, ps, clock, "", REC, sdi="d-unknown") == 201
    assert _take(ss, ps, "", CHAT) == "ask"


def test_the_same_token_reported_twice_is_one_act() -> None:
    ss, ps, clock, s256 = _env()
    assert _person_token(ss, ps, clock, s256, REC, jti="pt-1") == 201
    assert _person_token(ss, ps, clock, s256, REC, jti="pt-1") == 201
    assert _person_token(ss, ps, clock, s256, REC, jti="pt-2") == 201
    assert [h.jti for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == ["pt-1", "pt-2"]


def test_an_audience_array_is_one_act_per_listed_resource() -> None:
    ss, ps, clock, s256 = _env()
    assert _person_token(ss, ps, clock, s256, [REC, DOCS, PAY]) == 201
    assert [h.resource for h in ss.store.history_for(ps.issuer, SUB, AGENT, s256)] == [REC, PAY]


@pytest.mark.parametrize("aud", ["https://Records.example", []])
def test_an_audience_that_is_not_a_server_identifier_is_refused(aud: Any) -> None:
    ss, ps, clock, s256 = _env()
    assert _person_token(ss, ps, clock, s256, aud) == 400


@pytest.mark.parametrize("exp,send", [(10, "allow"), (3600, "ask")])
def test_the_act_lasts_until_the_tokens_exp(exp: int, send: str) -> None:
    # The read is a later step than the write: the person token, issued first, completes
    # the sequence only if it can still be used after the write, until its `exp`.
    ss, ps, clock, s256 = _env(prohibited_pairs=[],
                               prohibited_sequences=[["write", "read_sensitive", "send_internal"]])
    assert _person_token(ss, ps, clock, s256, REC, exp=exp) == 201
    clock.t += 200                      # past an exp of 10 and the margin
    assert _take(ss, ps, s256, DOCS) == "allow"
    assert _take(ss, ps, s256, CHAT) == send


def test_a_person_token_spends_no_budget() -> None:
    usd = {"unit": "USD", "decimals": 2}
    ss, ps, clock, s256 = _env(budgets={"payment": {"max_count": 1}},
                               resource_budgets={INF: usd | {"max_amount": 1000}})
    assert _person_token(ss, ps, clock, s256, PAY, jti="pt-pay") == 201
    assert _person_token(ss, ps, clock, s256, INF, jti="pt-inf") == 201
    assert _take(ss, ps, s256, PAY) == "allow"
    assert _take(ss, ps, s256, INF, budget=usd | {"amount": 500}) == "allow"


def test_the_policy_lists_must_be_strings() -> None:
    with pytest.raises(ValueError):
        PolicyConfig.from_dict({"serves_on_identity": "https://records.example"})
    p = Policy(PolicyConfig.from_dict({"serves_on_identity": ["https://*.example"]}))
    assert p.serves_on_identity(REC) and not p.serves_on_identity("https://records.test")
    assert isinstance(p, SupervisionPolicy)
    assert validate_policy({"severity": ["unclassified"],
                            "serves_on_identity": ["https://records.example"]}) == []


def test_a_person_token_composes_as_each_class_its_resource_has() -> None:
    # Mail serves on a person token: the policy gives mail.example several classes, so a
    # person token for it is booked as the most severe (send_external) and composes as
    # each of the others too, uncertain: what the resource served on it is not seen. Live
    # when a write is decided after a sensitive read, it may take the send_internal step.
    mail, cal = "https://mail.example", "https://calendar.example"
    rules = [*RULES,
             {"resource": mail, "scope": "mail.send", "class": "send_internal",
              "if_unknown": "send_external"},
             {"resource": mail, "scope": "mail.read", "class": "read_internal"},
             {"resource": cal, "class": "write"}]
    ss, ps, clock = make_env(rules=rules, prohibited_pairs=[], high_impact=[],
                             serves_on_identity=[mail], allow_unlisted_resources=True,
                             prohibited_sequences=[["read_sensitive", "write", "send_internal"]])
    s256 = connected((ss, ps, clock), resources=(DOCS, CHAT))
    c = ss.policy.classify(Act("person_token", ps.issuer, SUB, AGENT, "", resource=mail))
    assert c.cls == "send_external" and c.uncertain
    assert sorted(a.cls for a in c.blind) == ["read_internal", "send_internal"]
    assert _person_token(ss, ps, clock, s256, mail) == 201
    assert _take(ss, ps, s256, REC) == "allow"
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, cal)
    d = r.json()
    assert d["decision"] == "ask", d
    assert "`read_sensitive`, then `write`, then `send_internal`" in d["summary"]
    assert "person token" in d["summary"] and "agent's word" not in d["summary"]
