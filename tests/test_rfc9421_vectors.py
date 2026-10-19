"""RFC 9421 Appendix B test vectors, run against this SS's own httpsig code.

These are the published inter-operability vectors from the HTTP Message Signatures
RFC. They pin the signature-base construction and the Ed25519/ES256 verification
paths to the standard's own keys and signatures, independently of any code here.

- B.1.3 is the example ECDSA P-256 key, B.1.4 the example Ed25519 key.
- B.2.4 signs a response with ecdsa-p256-sha256. ECDSA is non-deterministic
  (RFC 9421 7.3.5), so the vector is *verified* against the published signature,
  never reproduced.
- B.2.6 signs a request with ed25519. Ed25519 is deterministic, so this vector is
  both reproduced (sign) and verified (verify) through this code.

Each vector exercises `signature_base` (byte-for-byte) plus `jwk.VerifyKey.verify`
and `jwk.key_from_jwk`, so a regression in canonicalisation, EC point handling, or
Ed25519 handling fails here against the standard rather than against this repository's own fixtures.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from aauth_supervision_server.httpsig import HttpRequest, HttpResponse, build_components, signature_base
from aauth_supervision_server.jwk import b64u, key_from_jwk

# ---------------------------------------------------------------- B.1.3 ECDSA P-256
# RFC 9421 Appendix B.1.3, "Example ECC P-256 Test Key" (test-key-ecc-p256).
B13_EC_PUBLIC_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf\n"
    b"w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==\n"
    b"-----END PUBLIC KEY-----\n"
)

# ---------------------------------------------------------------- B.1.4 Ed25519
# RFC 9421 Appendix B.1.4, "Example Ed25519 Test Key" (test-key-ed25519).
B14_ED25519_PRIVATE_PEM = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
    b"-----END PRIVATE KEY-----\n"
)


def _ec_public_jwk(pem: bytes, kid: str) -> dict:
    """Build this SS's JWK form from the RFC's PEM, so key_from_jwk is exercised."""
    pub = load_pem_public_key(pem)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    nums = pub.public_numbers()
    return {
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
        "x": b64u(nums.x.to_bytes(32, "big")), "y": b64u(nums.y.to_bytes(32, "big")),
    }


def _ed25519_public_jwk(raw: bytes, kid: str) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "use": "sig", "kid": kid,
            "x": b64u(raw)}


# =============================================================== B.2.6 ed25519

def test_b26_ed25519_signature_base_and_sign_verify() -> None:
    """B.2.6: reproduce the published signature and verify it through this SS's code."""
    priv = load_pem_private_key(B14_ED25519_PRIVATE_PEM, None)
    assert isinstance(priv, ed25519.Ed25519PrivateKey)

    req = HttpRequest(
        "POST", "example.com", "/foo",
        {"date": "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json",
         "content-length": "18"},
        query="param=Value&Pet=dog",
    )
    comps = build_components(
        ["date", "@method", "@path", "@authority", "content-type", "content-length"],
        1618884473, "test-key-ed25519")
    base = signature_base(comps, req)

    # Published B.2.6 signature value.
    published = ("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5l"
                 "Ip5WPpBKRCw==")
    produced = base64.b64encode(priv.sign(base)).decode()
    assert produced == published, "signature base does not match RFC 9421 B.2.6"

    # Verify the published signature through this SS's VerifyKey (Ed25519 path).
    raw_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    vk = key_from_jwk(_ed25519_public_jwk(raw_pub, "test-key-ed25519"))
    assert vk.verify(base64.b64decode(published), base) is True
    # A one-byte change to the base must fail.
    assert vk.verify(base64.b64decode(published), base + b"x") is False


# =============================================================== B.2.4 ecdsa-p256-sha256

# B.2.4 signs an HTTP response. The covered-component values are fixed by the vector.
_B24_SIG_PARAMS = ('("@status" "content-type" "content-digest" "content-length")'
                   ';created=1618884473;keyid="test-key-ecc-p256"')
_B24_CONTENT_DIGEST = ("sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX6"
                       "9wWdXymyU0rjJuahq4l5aGgfLQ==:")
# Published B.2.4 signature (base64, ECDSA (r||s) is 64 bytes before base64).
_B24_SIGNATURE = ("wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUE"
                  "kLIj+32oiasw==")


def _b24_response_base() -> bytes:
    """Rebuild the B.2.4 signature base from the vector's covered values."""
    resp = HttpResponse(
        200,
        {"content-type": "application/json", "content-digest": _B24_CONTENT_DIGEST,
         "content-length": "23"},
    )
    req = HttpRequest("POST", "example.com", "/foo")
    comps = build_components(
        ["@status", "content-type", "content-digest", "content-length"],
        1618884473, "test-key-ecc-p256")
    return signature_base(comps, req, resp)


def test_b24_signature_base_shape() -> None:
    """The rebuilt base matches the RFC's published B.2.4 signature base, line for line."""
    lines = _b24_response_base().decode().splitlines()
    assert lines == [
        '"@status": 200',
        '"content-type": application/json',
        f'"content-digest": {_B24_CONTENT_DIGEST}',
        '"content-length": 23',
        f'"@signature-params": {_B24_SIG_PARAMS}',
    ]


def test_b24_ecdsa_verify_published_signature() -> None:
    """Verify the published ECDSA P-256 signature through this SS's VerifyKey (ES256)."""
    vk = key_from_jwk(_ec_public_jwk(B13_EC_PUBLIC_PEM, "test-key-ecc-p256"))
    base = _b24_response_base()
    sig = base64.b64decode(_B24_SIGNATURE)
    assert len(sig) == 64, "ES256 raw signature must be r||s (64 bytes)"
    assert vk.verify(sig, base) is True, "RFC 9421 B.2.4 signature failed to verify"
    # A tampered base must not verify.
    assert vk.verify(sig, base[:-1] + b"0") is False
