"""JWK handling and algorithm determination (Signature-Key 3.3, core Signature Algorithms)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .errors import SignatureError

SUPPORTED_ALGS = ("Ed25519", "ES256")
# Signature-Key 4.2: a List of Tokens, each the JOSE identifier verbatim (not quoted Strings).
_ACCEPT_ALGS = ", ".join(SUPPORTED_ALGS)
_PROHIBITED = {"none", "EdDSA", "HS256", "HS384", "HS512"}
# Ed25519: the field prime (RFC 8032 5.1), and the y-coordinates of the points of small
# order, whose eighth multiple is the identity. Under such a public key anyone can make a
# signature that verifies, so it binds no signer.
_P25519 = 2 ** 255 - 19
_Y8 = 0x7A03AC9277FDC74EC6CC392CFA53202A0F67100D760B3CBA4FD84D3D706A17C7
_SMALL_ORDER_Y = frozenset({0, 1, _P25519 - 1, _Y8, _P25519 - _Y8})


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or any(c in s for c in "+/="):
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass(frozen=True)
class VerifyKey:
    alg: str
    jwk: dict[str, Any]

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            if self.alg == "Ed25519":
                pk = ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(self.jwk["x"]))
                pk.verify(signature, message)
                return True
            if self.alg != "ES256":  # fail closed on any alg this class does not implement
                return False
            if len(signature) != 64:  # ES256: r || s, 32 bytes each (RFC 9421, 3.3.4)
                return False
            x = int.from_bytes(b64u_decode(self.jwk["x"]), "big")
            y = int.from_bytes(b64u_decode(self.jwk["y"]), "big")
            pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, KeyError):
            return False


def key_from_jwk(jwk: dict[str, Any]) -> VerifyKey:
    """Apply Algorithm Determination: alg present, fully specified, consistent with kty/crv."""
    if not isinstance(jwk, dict):
        raise SignatureError("invalid_key", "JWK is not an object")
    alg = jwk.get("alg")
    if not isinstance(alg, str):
        alg = None  # absent, or not a name: no algorithm is determined
    if not alg or alg in _PROHIBITED or jwk.get("kty") == "oct":
        raise SignatureError(
            "unsupported_algorithm", f"alg {alg!r} absent, polymorphic or prohibited",
            {"Accept-Signature-Alg": _ACCEPT_ALGS})
    if alg not in SUPPORTED_ALGS:
        raise SignatureError(
            "unsupported_algorithm", f"alg {alg} not implemented",
            {"Accept-Signature-Alg": _ACCEPT_ALGS})
    try:
        if alg == "Ed25519":
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                raise SignatureError("invalid_key", "kty/crv disagree with alg Ed25519")
            raw = b64u_decode(jwk["x"])
            if len(raw) != 32:
                raise SignatureError("invalid_key", "bad Ed25519 x")
            y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
            if y >= _P25519:  # RFC 8032 5.1.3: "decoding fails"
                raise SignatureError("invalid_key", "Ed25519 x is not canonically encoded")
            if y in _SMALL_ORDER_Y:
                raise SignatureError("invalid_key", "Ed25519 x is a point of small order")
        else:
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
                raise SignatureError("invalid_key", "kty/crv disagree with alg ES256")
            cx, cy = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
            if len(cx) != 32 or len(cy) != 32:
                # RFC 7518 6.2.1.2, 6.2.1.3: "the full size of a coordinate for the curve".
                raise SignatureError("invalid_key", "ES256 x and y are 32 octets each")
            # A point off the curve is refused here (ValueError), not at each verification.
            ec.EllipticCurvePublicNumbers(int.from_bytes(cx, "big"), int.from_bytes(cy, "big"),
                                          ec.SECP256R1()).public_key()
    except (KeyError, ValueError) as e:
        raise SignatureError("invalid_key", f"malformed JWK: {e}") from e
    if "d" in jwk:
        raise SignatureError("invalid_key", "private key material in a public JWK")
    return VerifyKey(alg, dict(jwk))


class SigningKey:
    """A private signing key with its public JWK."""

    def __init__(self, alg: str, kid: str, private: Any) -> None:
        # Signature-Key carries the kid as a Structured Field String (RFC 9651 3.3.3):
        # printable ASCII only. Any other could never be sent, and nothing signed with
        # this key would verify.
        if not isinstance(kid, str) or not kid or any(not 0x20 <= ord(c) <= 0x7E for c in kid):
            raise ValueError(f"kid must be printable ASCII: {kid!r}")
        self.alg = alg
        self.kid = kid
        self._priv = private

    @classmethod
    def generate(cls, kid: str, alg: str = "Ed25519") -> SigningKey:
        if alg == "Ed25519":
            return cls(alg, kid, ed25519.Ed25519PrivateKey.generate())
        if alg == "ES256":
            return cls(alg, kid, ec.generate_private_key(ec.SECP256R1()))
        raise ValueError(alg)

    def public_jwk(self) -> dict[str, Any]:
        if self.alg == "Ed25519":
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            raw = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw), "alg": "Ed25519",
                    "kid": self.kid, "use": "sig"}
        nums = self._priv.public_key().public_numbers()
        return {"kty": "EC", "crv": "P-256", "x": b64u(nums.x.to_bytes(32, "big")),
                "y": b64u(nums.y.to_bytes(32, "big")), "alg": "ES256", "kid": self.kid,
                "use": "sig"}

    def sign(self, message: bytes) -> bytes:
        if self.alg == "Ed25519":
            return bytes(self._priv.sign(message))
        der = self._priv.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def private_jwk(self) -> dict[str, Any]:
        """Export for local key files (never served)."""
        jwk = self.public_jwk()
        if self.alg == "Ed25519":
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
            )

            raw = self._priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            jwk["d"] = b64u(raw)
        else:
            jwk["d"] = b64u(self._priv.private_numbers().private_value.to_bytes(32, "big"))
        return jwk

    @classmethod
    def from_private_jwk(cls, jwk: dict[str, Any]) -> SigningKey:
        alg = jwk["alg"]
        d = b64u_decode(jwk["d"])
        if alg == "Ed25519":
            return cls(alg, jwk["kid"], ed25519.Ed25519PrivateKey.from_private_bytes(d))
        if alg == "ES256":
            return cls(alg, jwk["kid"], ec.derive_private_key(int.from_bytes(d, "big"),
                                                               ec.SECP256R1()))
        raise ValueError(alg)
