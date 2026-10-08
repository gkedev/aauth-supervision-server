"""The protocol layer is policy-agnostic.

`SupervisionServer` is pure Supervision -00 wire logic. The decision model is a plug:
anything that satisfies `SupervisionPolicy` (three methods + two attributes) can drive
it. The APC `Policy` is one such plug; here a deliberately trivial, non-APC policy drives
the same unmodified server end-to-end through the real signed-request path, proving the
two are swappable without touching the protocol layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from conftest import AGENT, SUB, Clock

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import (
    Act,
    Classification,
    Decision,
    Policy,
    PolicyConfig,
    SupervisionPolicy,
)
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.store import HistoryEntry, Mission, Reach
from aauth_supervision_server.testing import SimulatedPS


@dataclass
class TrivialPolicy:
    """A minimal, non-APC decision model: a flat resource allow-list.

    No classes, no composition closure, no budgets, no reach, no R3 data. It allows an act
    (and a proposal) only when every resource it touches is on the allow-list, and asks for
    anything else. It implements `SupervisionPolicy` by shape alone (duck-typed), with no
    import of or dependency on the APC `Policy`."""

    allow: set[str] = field(default_factory=set)
    r3_member: str = "r3_proposal"
    ask_on_mission_update: bool = False

    def classify(self, act: Act) -> Classification:
        cls = "allowed" if act.resource in self.allow else "unlisted"
        return Classification(cls=cls, provenance="configured", uncertain=False)

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision:
        if act.resource in self.allow:
            return Decision("allow", reason="On the allow-list.")
        return Decision("ask", summary=f"{act.resource} is not on the allow-list.")

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        resources = body.get("resources", [])
        if not isinstance(resources, list):
            return Decision("deny", reason="resources must be an array.")
        unlisted = [r for r in resources if r not in self.allow]
        if unlisted:
            return Decision("deny", reason=f"Not on the allow-list: {', '.join(unlisted)}.")
        return Decision("allow", summary="All resources allow-listed.", narrow={
            "description": str(body.get("description", "")),
            "approved_resources": list(resources), "approved_tools": []})


def make_env_with(policy: SupervisionPolicy) -> tuple[SupervisionServer, SimulatedPS, Clock]:
    """The conftest `make_env` plumbing, but with an injected policy of any shape."""
    clock = Clock()
    fetcher = StaticFetcher()
    ps = SimulatedPS(transport="current", clock=clock)
    ps.install(fetcher)
    key = SigningKey.generate("ss-key-1")
    cfg = ServerConfig(issuer="https://ss.example",
                       trusted_ps={ps.issuer: TrustedPS(auto_connect=True)},
                       admin_token="operator-secret")
    ss = SupervisionServer(cfg, policy, JwksUriResolver(fetcher), key, clock=clock)
    ps.ss_jwk = key.public_jwk()
    return ss, ps, clock


def _approve(ps: SimulatedPS, ss: SupervisionServer, resources: list[str]) -> str:
    assert ps.connect(ss, SUB).status == 200
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Trivial", resources)
    assert r.status == 200 and s256, r.body
    return s256


def test_runtime_checkable_both_policies_satisfy_the_protocol() -> None:
    # The APC policy and a hand-written trivial policy both satisfy the same interface.
    apc = Policy(PolicyConfig(severity=["low"], rules=[]))
    assert isinstance(apc, SupervisionPolicy)
    assert isinstance(TrivialPolicy(allow={"https://hr.example"}), SupervisionPolicy)
    # A policy missing a method does NOT satisfy it.

    class Broken:
        r3_member = "r3_proposal"
        ask_on_mission_update = False

    assert not isinstance(Broken(), SupervisionPolicy)


def test_trivial_policy_drives_the_unmodified_server_end_to_end() -> None:
    """The whole mission + auth_token flow runs on the trivial policy through the real
    signed-request path. The server never knows the policy is not APC."""
    ss, ps, clock = make_env_with(TrivialPolicy(allow={"https://hr.example"}))

    # Proposal with an allow-listed resource is approved by the trivial policy.
    s256 = _approve(ps, ss, ["https://hr.example"])

    # An auth_token for the allow-listed resource is allowed.
    _sdi, resp, _body = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert resp.status == 200, resp.body
    d = resp.json()
    assert isinstance(d, dict) and d["decision"] == "allow"

    # An auth_token for a resource NOT on the allow-list is asked, by the same policy.
    _sdi2, resp2, _b2 = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example")
    assert resp2.status == 200, resp2.body
    d2 = resp2.json()
    assert isinstance(d2, dict) and d2["decision"] == "ask"


def test_trivial_policy_denies_a_proposal_with_an_unlisted_resource() -> None:
    ss, ps, clock = make_env_with(TrivialPolicy(allow={"https://hr.example"}))
    assert ps.connect(ss, SUB).status == 200
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Trivial",
                                     ["https://hr.example", "https://payments.example"])
    assert r.status == 200
    d = r.json()
    assert isinstance(d, dict) and d["decision"] == "deny"
    assert "payments.example" in d.get("reason", "")
    assert not s256


def test_apc_policy_still_drives_the_same_server() -> None:
    # The default APC policy drives the identical server construction unchanged.
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    cfg = PolicyConfig.from_dict(json.loads((root / "examples" / "policy.json").read_text()))
    ss, ps, clock = make_env_with(Policy(cfg))
    assert ps.connect(ss, SUB).status == 200
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Prepare the review",
                                     ["https://hr.example"],
                                     [{"name": "WebSearch", "description": "Search"}])
    assert r.status == 200 and s256, r.body
