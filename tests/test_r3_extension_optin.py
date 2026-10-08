"""The forwarded R3 proposal (`r3_proposal`, AAuth #256) is a NON-SPEC extension.

It is off unless the policy names the member (`r3_member`). With it off, the server is
spec-only Supervision -00: the member is ignored, never parsed, never checked.
"""
from __future__ import annotations

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.jwk import b64u
from aauth_supervision_server.policy import PolicyConfig
from aauth_supervision_server.testing import r3_bytes

MAIL = "https://mail.example"


def _tampered_body(ps, s256):
    raw, digest = r3_bytes({"operations": [{"operationId": "send_email"}],
                            "parameters": {"to": "a@corp.example"}})
    return {"sdi": "d-x", "act": "auth_token", "iat": 1, "sub": SUB, "agent": AGENT,
            "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token(MAIL, "", digest, s256),
            "presented_token": "a.b.c",
            "r3_proposal": b64u(raw.replace(b"corp.example", b"evil.example"))}


def test_default_config_is_spec_only():
    assert PolicyConfig().r3_member is None
    assert PolicyConfig.from_dict({}).r3_member is None


def test_null_disables_and_empty_is_rejected():
    assert PolicyConfig.from_dict({"r3_member": None}).r3_member is None
    with pytest.raises(ValueError, match="r3_member"):
        PolicyConfig.from_dict({"r3_member": ""})
    with pytest.raises(ValueError, match="r3_member"):
        PolicyConfig.from_dict({"r3_member": 7})


def test_extension_on_checks_the_proposal():
    ss, ps, clock = make_env(transport="forwarded")  # example policy opts in
    s256 = connected((ss, ps, clock))
    r = ps.call(ss, "POST", "/decision", _tampered_body(ps, s256))
    assert r.status == 400 and "r3_s256" in r.json()["detail"]


def test_extension_off_ignores_the_member():
    ss, ps, clock = make_env(transport="forwarded", r3_member=None)
    s256 = connected((ss, ps, clock))
    r = ps.call(ss, "POST", "/decision", _tampered_body(ps, s256))
    # Spec-only: the unknown member is not parsed, so the mismatch is never seen and the
    # act is decided on the spec members alone (no resource-asserted operations).
    assert r.status == 200
    assert r.json()["decision"] in ("allow", "ask", "deny", "clarify")
    rec = ss.store.decisions[f"{ps.issuer}|d-x"]
    assert rec is not None



def test_forwarded_r3_document_gives_operations_but_no_parameters():
    # R3 Issuer Processing step 5: the issuer evaluates the R3 *document's* `operations`
    # on any R3 resource token, not only a per-call proposal. The same member carries it,
    # checked against the same `r3_s256`. A document names operations but no parameters,
    # so a recipient-dependent operation stays unknown and is put to the person.
    ss, ps, clock = make_env(transport="forwarded")
    s256 = connected((ss, ps, clock))
    document = {"vocabulary": "urn:aauth:vocabulary:mcp",
                "operations": [{"tool": "send_email"}],
                "display": {"summary": "Send email as you"}}
    sdi, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, MAIL, proposal=document)
    assert r.status == 200 and r.json()["decision"] == "ask"
    # The `send_email` operation from the document selected the mail rule; only the
    # recipient it needs to tell internal from external was missing.
    entry = ss.store.decisions[f"{ps.issuer}|{sdi}"].entry
    assert entry is not None and entry.action_class == "send_external"
    assert "more specific rule is unavailable" in entry.detail
