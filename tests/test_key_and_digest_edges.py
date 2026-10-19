"""Keys that bind no signer, and digests that name two bodies, are refused.

- An Ed25519 public key of small order (a point whose eighth multiple is the identity)
  lets anyone make a signature that verifies under it, so a request signed "by" it
  proves nothing about who sent it. Such keys are refused, and so is a non-canonical
  encoding (RFC 8032 5.1.3: "If the resulting value is >= p, decoding fails", and a zero
  x with its sign bit set fails too).
- An ES256 coordinate is the full size of the curve's (RFC 7518 6.2.1.2, 6.2.1.3: "MUST
  be the full size of a coordinate"), and the point is on the curve.
- A Content-Digest that names one algorithm twice is refused: a Structured Fields parser
  keeps the last (RFC 9651 4.2.2), a reader of the logged request may take the first, and
  the SS's signed answer covers the whole field.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from aauth_supervision_server.errors import SignatureError
from aauth_supervision_server.httpsig import check_content_digest
from aauth_supervision_server.jwk import SigningKey, b64u, b64u_decode, key_from_jwk

P = 2 ** 255 - 19
Y8 = 0x7A03AC9277FDC74EC6CC392CFA53202A0F67100D760B3CBA4FD84D3D706A17C7  # order 8


def _ed(y: int, sign: int = 0) -> dict[str, str]:
    raw = (y | (sign << 255)).to_bytes(32, "little")
    return {"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "kid": "k", "x": b64u(raw)}


@pytest.mark.parametrize("y", [0, 1, P - 1, Y8, P - Y8],
                         ids=["order-4", "identity", "order-2", "order-8", "order-8-negated"])
@pytest.mark.parametrize("sign", [0, 1])
def test_an_ed25519_key_of_small_order_is_refused(y: int, sign: int) -> None:
    with pytest.raises(SignatureError) as e:
        key_from_jwk(_ed(y, sign))
    assert e.value.error == "invalid_key"


@pytest.mark.parametrize("y", [P, P + 1, 2 ** 255 - 1])
def test_an_ed25519_key_not_canonically_encoded_is_refused(y: int) -> None:
    with pytest.raises(SignatureError) as e:
        key_from_jwk(_ed(y))
    assert e.value.error == "invalid_key"


def test_the_forgery_a_small_order_key_allows() -> None:
    # Why: under the identity as public key, R = identity and S = 0 verify for any message.
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pk = ed25519.Ed25519PublicKey.from_public_bytes((1).to_bytes(32, "little"))
    pk.verify((1).to_bytes(32, "little") + bytes(32), b"any message at all")


def test_a_generated_ed25519_key_is_accepted() -> None:
    for _ in range(20):
        jwk = SigningKey.generate("k").public_jwk()
        assert key_from_jwk(jwk).jwk["x"] == jwk["x"]


def _es256() -> dict[str, str]:
    return SigningKey.generate("e", "ES256").public_jwk()


@pytest.mark.parametrize("member", ["x", "y"])
@pytest.mark.parametrize("change", ["leading-zero", "doubled", "short"])
def test_an_es256_coordinate_not_the_full_size_is_refused(member: str, change: str) -> None:
    jwk = _es256()
    raw = b64u_decode(jwk[member])
    jwk[member] = b64u({"leading-zero": b"\x00" + raw, "doubled": bytes(32) + raw,
                        "short": raw[1:]}[change])
    with pytest.raises(SignatureError) as e:
        key_from_jwk(jwk)
    assert e.value.error == "invalid_key"


def test_an_es256_point_off_the_curve_is_refused() -> None:
    jwk = _es256()
    y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    jwk["y"] = b64u(((y + 1) % (2 ** 256)).to_bytes(32, "big"))
    with pytest.raises(SignatureError) as e:
        key_from_jwk(jwk)
    assert e.value.error == "invalid_key"


def test_a_generated_es256_key_is_accepted() -> None:
    for _ in range(20):
        jwk = _es256()
        assert key_from_jwk(jwk).jwk == jwk


def _sha256(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def test_a_content_digest_naming_an_algorithm_twice_is_refused() -> None:
    body, other = b'{"a":1}', b'{"a":2}'
    assert check_content_digest(_sha256(body), body)
    assert not check_content_digest(_sha256(other) + ", " + _sha256(body), body)
    assert not check_content_digest(_sha256(body) + ", " + _sha256(body), body)
    sha512 = "sha-512=:" + base64.b64encode(hashlib.sha512(body).digest()).decode() + ":"
    assert check_content_digest(_sha256(body) + ", " + sha512, body)
