"""Interop with aauth-go, the Go AAuth module on aauth.dev.

aauth-go (https://github.com/aauth-dev/aauth-go, v0.2.0, pinned in
`interop/aauth-go/go.mod`) signs and verifies AAuth requests in Go, on yaronf/httpsign,
sharing nothing with this repository. `interop/aauth-go/main.go` is a thin command over
its public API: `ServerSigner.SignRequest`, the signer a PS uses for a request it makes
in its own right under the `jwks_uri` scheme, and `VerifyServerRequest` with body
coverage required, as a PS or SS endpoint verifies one.

Three checks, each in both directions where it applies:

* a request aauth-go signs as a PS verifies here, with and without a body;
* a request this code signs verifies with aauth-go;
* two whole missions run against the unmodified server with every PS request signed by
  aauth-go: one ends in the split exfiltration, which the APC policy denies with the R3
  proposal forwarded (the opt-in AAuth #256 extension; without it the act is asked), and
  one, under Supervision -00 as written, catches a prohibited sequence whose tokens are
  taken last step first.

Go is needed to build the command. Without it these tests skip, unless
`AAUTH_SS_REQUIRE_GO=1` (set in CI), where a missing toolchain is a failure.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, ROOT, SUB, connected, policy_cfg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message, verify_request
from aauth_supervision_server.jwk import SigningKey, VerifyKey, b64u, key_from_jwk
from aauth_supervision_server.policy import Policy
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.testing import ACCEPT_SIG, SimulatedPS, r3_bytes

PS = "https://ps.example"
DWK = "aauth-person.json"
KID = "ps-key-1"
SEED = bytes(range(32))
KEY = SigningKey("Ed25519", KID, Ed25519PrivateKey.from_private_bytes(SEED))
JWK = KEY.public_jwk()
SK = f'sig=jwks_uri;id="{PS}";dwk="{DWK}";kid="{KID}"'
BODY = json.dumps({"sdi": "d-1", "act": "permission"}).encode()
BASE = ["@method", "@authority", "@path", "signature-key"]
BODY_COMPONENTS = ["content-digest", "content-type"]
CASES = [("POST", "/decision", BODY), ("GET", "/pending/p-1", b"")]


@pytest.fixture(scope="module")
def authgo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    go = shutil.which("go")
    if go is None:
        if os.environ.get("AAUTH_SS_REQUIRE_GO") == "1":
            pytest.fail("AAUTH_SS_REQUIRE_GO=1 but no Go toolchain is on PATH")
        pytest.skip("Go toolchain not on PATH (the aauth-go interop runs in CI)")
    exe = tmp_path_factory.mktemp("authgo") / ("authgo-interop" + (".exe" if os.name == "nt" else ""))
    subprocess.run([go, "build", "-o", str(exe), "."], cwd=ROOT / "interop" / "aauth-go",
                   check=True, timeout=600)
    return exe


def _run(exe: Path, cmd: str, payload: dict[str, Any]) -> dict[str, Any]:
    done = subprocess.run([str(exe), cmd], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    out: dict[str, Any] = json.loads(done.stdout)
    return out


def _go_sign(exe: Path, method: str, path: str, headers: dict[str, str], body: bytes) -> dict[str, str]:
    out = _run(exe, "sign", {"issuer": PS, "dwk": DWK, "kid": KID, "seed": b64u(SEED),
                             "method": method, "url": f"https://ss.example{path}",
                             "headers": headers, "body": b64u(body)})
    signed: dict[str, str] = out["headers"]
    return signed


class _Resolver:
    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        assert (signer_id, dwk, kid) == (PS, DWK, KID)
        return key_from_jwk(JWK)


@pytest.mark.parametrize("method,path,body", CASES)
def test_a_request_signed_by_auth_go_verifies_here(authgo: Path, method: str, path: str,
                                                   body: bytes) -> None:
    headers = {"Content-Type": "application/json"} if body else {}
    signed = _go_sign(authgo, method, path, headers, body)
    assert signed["signature-key"] == SK  # aauth-go's own jwks_uri serialization
    req = HttpRequest(method, "ss.example", path, signed, body)
    signer = verify_request(req, _Resolver(), required=BASE + (BODY_COMPONENTS if body else []),
                            now=time.time())
    assert signer.id == PS


@pytest.mark.parametrize("method,path,body", CASES)
def test_a_request_signed_here_verifies_with_auth_go(authgo: Path, method: str, path: str,
                                                     body: bytes) -> None:
    headers = {"signature-key": SK}
    names = list(BASE)
    if body:
        headers |= {"content-type": "application/json", "content-digest": content_digest(body)}
        names += BODY_COMPONENTS
    req = HttpRequest(method, "ss.example", path, dict(headers), body)
    signed = {**headers, **sign_message(names, KEY, SK, req, created=int(time.time()))}
    out = _run(authgo, "verify", {"issuer": PS, "dwk": DWK, "kid": KID, "x": JWK["x"],
                                  "method": method, "url": f"https://ss.example{path}",
                                  "headers": signed, "body": b64u(body)})
    assert out == {"ok": True, "id": PS}


def test_auth_go_rejects_a_tampered_request_signed_here(authgo: Path) -> None:
    # Control for the test above: the same request with one byte of the body changed
    # must fail at aauth-go, so a passing verify is not a verifier that accepts anything.
    headers = {"signature-key": SK, "content-type": "application/json",
               "content-digest": content_digest(BODY)}
    req = HttpRequest("POST", "ss.example", "/decision", dict(headers), BODY)
    signed = {**headers, **sign_message(BASE + BODY_COMPONENTS, KEY, SK, req,
                                        created=int(time.time()))}
    out = _run(authgo, "verify", {"issuer": PS, "dwk": DWK, "kid": KID, "x": JWK["x"],
                                  "method": "POST", "url": "https://ss.example/decision",
                                  "headers": signed, "body": b64u(BODY.replace(b"d-1", b"d-2"))})
    assert out["ok"] is False and "content-digest" in out["error"]


class _AuthGoPS(SimulatedPS):
    """The simulated PS, with every request it sends signed by aauth-go instead of here."""

    exe: Path
    signed_by_auth_go = 0

    def build(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpRequest:
        raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else b""
        headers = {"Accept-Signature": ACCEPT_SIG}
        if raw:
            headers |= {"Content-Type": "application/json", "Prefer": "wait=30"}
        signed = _go_sign(self.exe, method, path, headers, raw)
        self.signed_by_auth_go += 1
        return HttpRequest(method, self.ss_authority, path, signed, raw)


def test_a_mission_runs_with_every_ps_request_signed_by_auth_go(authgo: Path) -> None:
    ps = _AuthGoPS(issuer=PS, key=KEY, transport="forwarded", clock=time.time)
    ps.exe = authgo
    fetcher = StaticFetcher()
    ps.install(fetcher)
    ss_key = SigningKey.generate("ss-key-1")
    ss = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                        trusted_ps={PS: TrustedPS(auto_connect=True)}),
                           Policy(policy_cfg()), JwksUriResolver(fetcher), ss_key, clock=time.time)
    ps.ss_jwk = ss_key.public_jwk()  # every 200 is also checked as a signed SS answer
    s256 = connected((ss, ps, None), resources=("https://records.example", "https://mail.example"))

    def decide(resource: str, proposal: dict[str, Any]) -> str:
        raw, digest = r3_bytes(proposal)
        sdi = ps.nid("d")
        resp = ps.call(ss, "POST", "/decision", {
            "sdi": sdi, "act": "auth_token", "iat": int(time.time()), "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "agent_token": ps.agent_token(AGENT),
            "resource_token": ps.resource_token(resource, "", digest, s256),
            "presented_token": "a.b.c", "r3_proposal": b64u(raw)})
        assert resp.status == 200, resp.body
        decision: str = resp.json()["decision"]
        if decision == "allow":
            assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
        return decision

    assert decide("https://records.example", {"operations": [{"tool": "export"}],
                                              "parameters": {}}) == "allow"
    assert decide("https://mail.example", {"operations": [{"tool": "send_email"}],
                                           "parameters": {"to": "drop@evil.example"}}) == "deny"
    # connect, mission proposal and approval, two decisions, one issuance: every request
    # the server accepted was signed by aauth-go.
    assert ps.sent and all(status in (200, 201) for _, _, status in ps.sent)
    assert ps.signed_by_auth_go == len(ps.sent) >= 5


def test_tokens_taken_in_reverse_order_are_caught_with_requests_signed_by_auth_go(
        authgo: Path) -> None:
    # The shipped example's sequence read_sensitive -> write -> send_internal, with the
    # tokens taken last step first. Every PS request is signed by aauth-go, including the
    # `auth_token.issued` events whose `exp` the SS relies on.
    rec, docs, chat = "https://records.example", "https://docs.example", "https://chat.example"
    rules = [{"resource": rec, "class": "read_sensitive"},
             {"resource": docs, "class": "write"},
             {"resource": chat, "class": "send_internal"}]
    ps = _AuthGoPS(issuer=PS, key=KEY, transport="current", clock=time.time)
    ps.exe = authgo
    fetcher = StaticFetcher()
    ps.install(fetcher)
    ss_key = SigningKey.generate("ss-key-1")
    ss = SupervisionServer(ServerConfig(issuer="https://ss.example",
                                        trusted_ps={PS: TrustedPS(auto_connect=True)}),
                           Policy(policy_cfg(rules=rules, prohibited_pairs=[])),
                           JwksUriResolver(fetcher), ss_key, clock=time.time)
    ps.ss_jwk = ss_key.public_jwk()
    s256 = connected((ss, ps, None), resources=(rec, docs, chat))

    def take(resource: str) -> str:
        sdi, resp, _ = ps.auth_token_request(ss, SUB, AGENT, s256, resource)
        assert resp.status == 200, resp.body
        decision: str = resp.json()["decision"]
        if decision == "allow":
            assert ps.issued(ss, SUB, AGENT, s256, sdi, resource).status == 201
        return decision

    assert take(chat) == "allow"
    assert take(docs) == "allow"
    assert take(rec) == "deny"
    assert ps.signed_by_auth_go == len(ps.sent) >= 8
