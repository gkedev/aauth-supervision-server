"""A simulated Person Server that speaks Supervision -00 to an SS.

Used by the tests and the adversarial suite. It signs as a server under the
`jwks_uri` scheme, mints the forwarded tokens (agent, person, resource, auth) as
real signed JWTs, assembles mission blobs, and sends events and replays exactly
as the draft describes. It can also forward the R3 per-call proposal the way
AAuth #256 proposes (`transport="forwarded"`).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .egress import StaticFetcher
from .errors import Response
from .httpsig import HttpRequest, HttpResponse, content_digest, sign_message, verify_response
from .jwk import SigningKey, b64u, key_from_jwk

ACCEPT_SIG = ('sig=("@status" "content-type" "content-digest" "content-digest";req '
              '"@authority";req "@path";req)')


def make_jwt(key: SigningKey, typ: str, claims: dict[str, Any]) -> str:
    header = {"typ": typ, "alg": key.alg, "kid": key.kid}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = key.sign(f"{h}.{p}".encode())
    return f"{h}.{p}.{b64u(sig)}"


def r3_bytes(doc: dict[str, Any]) -> tuple[bytes, str]:
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return raw, b64u(hashlib.sha256(raw).digest())


@dataclass
class SimulatedPS:
    issuer: str = "https://ps.example"
    ss_authority: str = "ss.example"
    ss_issuer: str = "https://ss.example"
    transport: str = "current"  # current | forwarded | forwarded+issued
    clock: Callable[[], float] = time.time
    key: SigningKey = field(default_factory=lambda: SigningKey.generate("ps-key-1"))
    resource_key: SigningKey = field(default_factory=lambda: SigningKey.generate("rs-key-1"))
    ap_key: SigningKey = field(default_factory=lambda: SigningKey.generate("ap-key-1"))
    ss_jwk: dict[str, Any] | None = None
    _ids: Any = field(default_factory=lambda: itertools.count(1))
    sent: list[tuple[str, dict[str, Any], int]] = field(default_factory=list)

    def documents(self) -> dict[str, Any]:
        return {
            f"{self.issuer}/.well-known/aauth-person.json": {
                "issuer": self.issuer, "name": "Example Person Server",
                "jwks_uri": f"{self.issuer}/.well-known/jwks.json"},
            f"{self.issuer}/.well-known/jwks.json": {"keys": [self.key.public_jwk()]},
        }

    def install(self, fetcher: StaticFetcher) -> None:
        fetcher.documents.update(self.documents())

    def nid(self, prefix: str) -> str:
        return f"{prefix}-{next(self._ids):04d}"

    # ------------------------------------------------------------ transport

    def build(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpRequest:
        """A signed PS request, ready for in-process delivery or a real socket."""
        raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else b""
        headers = {"accept-signature": ACCEPT_SIG}
        names = ["@method", "@authority", "@path", "signature-key"]
        if raw:
            headers.update({"content-type": "application/json",
                            "content-digest": content_digest(raw), "prefer": "wait=30"})
            names += ["content-digest", "content-type"]
        req = HttpRequest(method, self.ss_authority, path, headers, raw)
        sk = f'sig=jwks_uri;id="{self.issuer}";dwk="aauth-person.json";kid="{self.key.kid}"'
        h = sign_message(names, self.key, sk, req, created=int(self.clock()))
        req.headers.update({k.lower(): v for k, v in h.items()})
        return req

    def call(self, server: Any, method: str, path: str, body: dict[str, Any] | None = None,
             *, verify: bool = True) -> Response:
        req = self.build(method, path, body)
        resp: Response = server.handle(req)
        self.sent.append((path, body or {}, resp.status))
        if verify and self.ss_jwk and resp.status == 200 and resp.body:
            # L342: an unsigned terminal response from an SS with a jwks_uri is server_error,
            # and the signer id must be the issuer of the SS called.
            hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                              resp.body)
            verify_response(hr, req, key_from_jwk(self.ss_jwk),
                            ["@status", "content-type", "content-digest"],
                            expected_issuer=self.ss_issuer, now=self.clock())
        return resp

    # ------------------------------------------------------------ tokens

    def agent_token(self, agent: str) -> str:
        local, dom = agent.removeprefix("aauth:").split("@")
        return make_jwt(self.ap_key, "aa-agent+jwt", {
            "iss": f"https://{dom}", "sub": agent, "ps": self.issuer,
            "cnf": {"jwk": self.ap_key.public_jwk()}, "iat": int(self.clock()),
            "exp": int(self.clock()) + 3600})

    def resource_token(self, resource: str, scope: str = "", r3_s256: str = "",
                       mission_s256: str = "", budget: dict[str, Any] | None = None,
                       consumed: dict[str, Any] | None = None) -> str:
        claims: dict[str, Any] = {"iss": resource, "dwk": "aauth-resource.json",
                                  "aud": self.issuer, "ps": self.issuer, "sub": "rs-sub",
                                  "jti": self.nid("rt"), "iat": int(self.clock()),
                                  "exp": int(self.clock()) + 300}
        if scope:
            claims["scope"] = scope
        if r3_s256:
            claims["r3_uri"] = f"{resource}/r3/{r3_s256}"
            claims["r3_s256"] = r3_s256
        if mission_s256:
            claims["mission_s256"] = mission_s256
        if budget is not None:  # AAuth Budgets: the resource's offer, and what was metered
            claims["budget"] = budget
        if consumed is not None:
            claims["budget_consumed"] = consumed
        return make_jwt(self.resource_key, "aa-resource+jwt", claims)

    # ------------------------------------------------------------ protocol steps

    def connect(self, server: Any, sub: str) -> Response:
        return self.call(server, "POST", "/connect", {"action": "connect", "id": self.nid("c"),
                                                      "iat": int(self.clock()), "sub": sub})

    def propose_and_approve(self, server: Any, sub: str, agent: str, description: str,
                            resources: list[str], tools: list[dict[str, str]] | None = None
                            ) -> tuple[Response, str]:
        sdi = self.nid("d")
        r = self.call(server, "POST", "/mission", {
            "sdi": sdi, "iat": int(self.clock()), "sub": sub, "agent": agent,
            "agent_token": self.agent_token(agent), "description": description,
            "tools": tools or [], "resources": resources})
        d = r.json()
        assert isinstance(d, dict)
        if d.get("decision") != "allow":
            return r, ""
        blob = {"agent": agent, "approved_at": "2026-10-06T00:00:00Z",
                "description": d["description"],
                "approved_tools": d.get("approved_tools", []),
                "approved_resources": d.get("approved_resources", [])}
        if d.get("expires_at"):
            blob["expires_at"] = d["expires_at"]
        raw = json.dumps(blob, separators=(",", ":")).encode()
        s256 = b64u(hashlib.sha256(raw).digest())
        rep = self.call(server, "POST", f"/mission/{s256}", {
            "action": "approved", "id": self.nid("e"), "sdi": sdi, "iat": int(self.clock()),
            "sub": sub, "agent": agent, "s256": s256, "mission": b64u(raw)})
        assert rep.status == 201, rep.body
        self._last_blob = (s256, raw)
        return r, s256

    def auth_token_request(self, server: Any, sub: str, agent: str, mission_s256: str,
                           resource: str, *, scope: str = "", proposal: dict[str, Any] | None
                           = None, justification: str = "", sdi: str | None = None,
                           budget: dict[str, Any] | None = None,
                           consumed: dict[str, Any] | None = None
                           ) -> tuple[str, Response, dict[str, Any] | None]:
        sdi = sdi or self.nid("d")
        r3_s256 = ""
        member: str | None = None
        if proposal is not None:
            raw, r3_s256 = r3_bytes(proposal)
            member = b64u(raw)
        body: dict[str, Any] = {
            "sdi": sdi, "act": "auth_token", "iat": int(self.clock()), "sub": sub,
            "agent": agent, "agent_token": self.agent_token(agent),
            "resource_token": self.resource_token(resource, scope, r3_s256, mission_s256,
                                                  budget, consumed),
            "presented_token": make_jwt(self.key, "aa-person+jwt", {
                "iss": self.issuer, "aud": resource, "sub": "p", "iat": int(self.clock())}),
        }
        if mission_s256:
            body["mission_s256"] = mission_s256
        if justification:
            body["justification"] = justification
        if self.transport.startswith("forwarded") and member is not None:
            body["r3_proposal"] = member
        resp = self.call(server, "POST", "/decision", body)
        return sdi, resp, (proposal if self.transport.startswith("forwarded") else None)

    def issued(self, server: Any, sub: str, agent: str, mission_s256: str, sdi: str,
               resource: str, scope: str = "", proposal: dict[str, Any] | None = None,
               jti: str | None = None) -> Response:
        body: dict[str, Any] = {"event": "auth_token.issued", "id": self.nid("e"), "sdi": sdi,
                                "iat": int(self.clock()), "sub": sub, "agent": agent,
                                "jti": jti or self.nid("at"), "aud": resource,
                                "scope": scope or None,
                                "exp": int(self.clock()) + 3600, "issuer": self.issuer}
        if mission_s256:
            body["mission_s256"] = mission_s256
        if self.transport == "forwarded+issued" and proposal is not None:
            body["r3_proposal"] = b64u(r3_bytes(proposal)[0])
        return self.call(server, "POST", "/event", body)

    def resolved(self, server: Any, sub: str, agent: str, mission_s256: str, sdi: str,
                 answer: str, apply: str | None = None) -> Response:
        body: dict[str, Any] = {"event": "decision.resolved", "id": self.nid("e"), "sdi": sdi,
                                "iat": int(self.clock()), "sub": sub, "agent": agent,
                                "answer": answer}
        if mission_s256:
            body["mission_s256"] = mission_s256
        if apply:
            body["apply"] = apply
        return self.call(server, "POST", "/event", body)

    def replay_to(self, server: Any, sub: str, agent: str) -> None:
        """Routing change: replay everything this PS sent, in order, to a new SS."""
        self.connect(server, sub)
        for path, body, status in list(self.sent):
            if path == "/connect" or (path == "/event" and status != 201):
                continue
            if path.startswith("/mission/") and body.get("action") in ("approved", "terminated"):
                self.call(server, "POST", path, body)
            elif path == "/event":
                self.call(server, "POST", path, body)
