"""Interop with an independent AAuth signature implementation.

`regent-httpsig` (https://github.com/regent-protocol/regent-httpsig, listed in the AAuth
README's implementations table) signs and verifies AAuth requests with code that shares
nothing with this repository. Requests it signs under the `jwks_uri` scheme must verify
here, and requests this SS's signer produces must verify there, with and without a body.
This breaks the circularity of testing `httpsig` only against `testing.SimulatedPS`.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest
import regent_httpsig.verify as regent_verify
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from regent_httpsig.sign import content_digest as regent_digest
from regent_httpsig.sign import sign_request as regent_sign

from aauth_supervision_server.httpsig import HttpRequest, content_digest, sign_message, verify_request
from aauth_supervision_server.jwk import SigningKey, VerifyKey, key_from_jwk

PS = "https://ps.example"
SK = f'sig=jwks_uri;id="{PS}";dwk="aauth-person.json";kid="ps-1"'
BODY = json.dumps({"sdi": "d-1", "act": "permission"}).encode()
BASE = ["@method", "@authority", "@path", "signature-key"]
BODY_COMPONENTS = ["content-digest", "content-type"]
CASES = [("POST", "/decision", BODY), ("GET", "/pending/p-1", b"")]

PRIVATE = Ed25519PrivateKey.generate()
KEY = SigningKey("Ed25519", "ps-1", PRIVATE)
JWK = KEY.public_jwk()


class _Resolver:
    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey:
        assert (signer_id, dwk, kid) == (PS, "aauth-person.json", "ps-1")
        return key_from_jwk(JWK)


@pytest.mark.parametrize("method,path,body", CASES)
def test_a_request_signed_by_regent_httpsig_verifies_here(method: str, path: str, body: bytes) -> None:
    headers = {"Signature-Key": SK}
    covered = tuple(BASE)
    if body:
        headers |= {"Content-Digest": regent_digest(body), "Content-Type": "application/json"}
        covered += tuple(BODY_COMPONENTS)
    signed = regent_sign(PRIVATE, method, f"https://ss.example{path}", headers, covered=covered)
    req = HttpRequest(method, "ss.example", path, {k.lower(): v for k, v in signed.items()}, body)
    signer = verify_request(req, _Resolver(), required=BASE + (BODY_COMPONENTS if body else []),
                            now=time.time())
    assert signer.id == PS


@pytest.mark.parametrize("method,path,body", CASES)
def test_a_request_signed_here_verifies_with_regent_httpsig(method: str, path: str, body: bytes,
                                                           monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_ssrf_guard(*_: Any, **__: Any) -> None:  # ps.example is a test name, not a host
        return None

    monkeypatch.setattr(regent_verify, "assert_public_url", no_ssrf_guard)
    headers = {"signature-key": SK}
    names = list(BASE)
    if body:
        headers |= {"content-type": "application/json", "content-digest": content_digest(body)}
        names += BODY_COMPONENTS
    req = HttpRequest(method, "ss.example", path, dict(headers), body)
    signed = {**headers, **sign_message(names, KEY, SK, req, created=int(time.time()))}

    def serve(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/aauth-person.json":
            return httpx.Response(200, json={"issuer": PS, "jwks_uri": f"{PS}/jwks.json"})
        if request.url.path == "/jwks.json":
            return httpx.Response(200, json={"keys": [JWK]})
        return httpx.Response(404)

    async def verify() -> Any:
        async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
            verifier = regent_verify.HttpsigVerifier(http_client=client)
            return await verifier.verify_server(method, f"https://ss.example{path}", signed, body or None)

    result = asyncio.run(verify())
    assert isinstance(result, regent_verify.VerifiedSignature), result
