from __future__ import annotations

import json
from pathlib import Path

import pytest

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy, PolicyConfig
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.testing import SimulatedPS

ROOT = Path(__file__).resolve().parents[1]
SUB = "8f14e45fceea167a5a36dedd4bea2543"
AGENT = "aauth:assistant@agent.example"


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "req(*ids): conformance-matrix rows this test proves (docs/conformance-matrix.md)")


class Clock:
    def __init__(self, t: float = 1_790_600_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def policy_cfg(**over) -> PolicyConfig:
    d = json.loads((ROOT / "examples" / "policy.json").read_text())
    # The example has records.example serve on a person token alone, which makes approving
    # any mission naming it an act (the token the PS issues at approval). Most tests use
    # records.example as a sensitive resource read through auth tokens; the tests about
    # Person Identity Access name `serves_on_identity` themselves.
    d["serves_on_identity"] = []
    d.update(over)
    return PolicyConfig.from_dict(d)


@pytest.fixture
def env():
    return make_env()


def make_env(transport: str = "current", sign: bool = True, auto_connect: bool = True,
             **policy_over):
    clock = Clock()
    fetcher = StaticFetcher()
    ps = SimulatedPS(transport=transport, clock=clock)
    ps.install(fetcher)
    key = SigningKey.generate("ss-key-1") if sign else None
    cfg = ServerConfig(issuer="https://ss.example",
                       trusted_ps={ps.issuer: TrustedPS(auto_connect=auto_connect)},
                       admin_token="operator-secret")
    ss = SupervisionServer(cfg, Policy(policy_cfg(**policy_over)), JwksUriResolver(fetcher),
                           key, clock=clock)
    if key:
        ps.ss_jwk = key.public_jwk()
    return ss, ps, clock


def connected(env, resources=("https://hr.example", "https://mail.example"), tools=None):
    ss, ps, _ = env
    assert ps.connect(ss, SUB).status == 200
    r, s256 = ps.propose_and_approve(ss, SUB, AGENT, "# Prepare the review", list(resources),
                                     tools or [{"name": "WebSearch", "description": "Search"}])
    assert r.status == 200 and s256
    return s256
