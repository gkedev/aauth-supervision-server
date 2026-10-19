"""HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530), as profiled by AAuth.

Only what a Supervision Server needs: verifying PS requests signed under the
`jwks_uri` Signature-Key scheme, and signing its own responses (Supervision,
Signed Decisions), including `;req` components bound to the request.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .errors import ProtocolError, SignatureError
from .jwk import SigningKey, VerifyKey
from .sfv import (
    InnerList,
    Item,
    SFVError,
    Token,
    parse_dictionary,
    ser_dictionary,
    ser_inner_list,
)


@dataclass
class HttpRequest:
    method: str
    authority: str  # host[:port], as the client addressed it
    path: str  # path only, no query
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names
    body: bytes = b""
    query: str = ""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)  # lower-case names
    body: bytes = b""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


# ---------------------------------------------------------------- Content-Digest


def content_digest(body: bytes) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def check_content_digest(value: str | None, body: bytes) -> bool:
    if value is None:
        return False
    try:
        # One digest per algorithm: a parser keeps the last of two, a reader of the logged
        # request may take the first, and a signed answer covers the whole field.
        d = parse_dictionary(value, unique=True)
    except SFVError:
        return False
    seen = False
    for alg, h in (("sha-256", hashlib.sha256), ("sha-512", hashlib.sha512)):
        m = d.get(alg)
        if m is None:
            continue
        if not (isinstance(m, Item) and isinstance(m.value, bytes)):
            return False
        if m.value != h(body).digest():
            return False  # a present digest that is wrong fails, whatever else matches
        seen = True
    return seen


# ------------------------------------------------------------------ signature base


def _normalize_authority(a: str) -> str:
    """RFC 9421 2.2.3: lower-cased, default port omitted. AAuth parties are HTTPS, so
    only :443 is a default port; https://host:80 names a different origin."""
    a = a.strip().lower()
    return a[: -len(":443")] if a.endswith(":443") else a


def _component_value(it: Item, req: HttpRequest, resp: HttpResponse | None) -> str:
    name = it.value
    if not isinstance(name, str):
        raise SignatureError("invalid_input", "component identifier must be a string")
    # RFC 9421 Section 2.5: a component parameter "that is unknown or does not apply to
    # the component identifier" MUST produce an error. This verifier implements `req`
    # alone (`sf`, `key`, `bs`, `name`, `tr` are not), and `req` applies only to a
    # request component covered in a response.
    if any(p != "req" for p in it.params) or (
            "req" in it.params and (resp is None or it.params["req"] is not True)):
        raise SignatureError("invalid_input",
                             f"unsupported component parameter on {name}: "
                             f"{', '.join(sorted(it.params))}")
    use_req = resp is None or it.params.get("req") is True
    if name.startswith("@"):
        if name == "@status":
            if resp is None or it.params.get("req"):
                raise SignatureError("invalid_input", "@status only on a response")
            return str(resp.status)
        src = req
        if name == "@method":
            return src.method.upper()
        if name == "@authority":
            return _normalize_authority(src.authority)
        if name == "@path":
            return src.path or "/"
        if name == "@query":
            return "?" + src.query
        if name == "@target-uri":
            q = f"?{src.query}" if src.query else ""
            return f"https://{_normalize_authority(src.authority)}{src.path or '/'}{q}"
        raise SignatureError("invalid_input", f"unsupported derived component {name}")
    msg: HttpRequest | HttpResponse = req if use_req else resp  # type: ignore[assignment]
    v = msg.header(name)
    if v is None:
        raise SignatureError("invalid_input", f"covered header {name} is absent")
    # RFC 9421 Section 2.1: an obs-fold becomes one space; nothing else in the value changes.
    return re.sub(r"\r?\n[ \t]+", " ", v).strip()


def signature_base(components: InnerList, req: HttpRequest,
                   resp: HttpResponse | None = None) -> bytes:
    lines = []
    seen = set()
    for it in components.items:
        ident = ser_inner_list(InnerList([it]))[1:-1]
        if ident in seen:
            raise SignatureError("invalid_input", f"duplicate component {ident}")
        seen.add(ident)
        lines.append(f"{ident}: {_component_value(it, req, resp)}")
    lines.append('"@signature-params": ' + ser_inner_list(components))
    try:
        return "\n".join(lines).encode("ascii")
    except UnicodeEncodeError as e:
        # RFC 9110 field values are visible ASCII; a non-ASCII covered value cannot be signed.
        raise SignatureError("invalid_input", "covered component is not ASCII") from e


def build_components(names: list[str], created: int, keyid: str | None = None,
                     extra: dict[str, int | str] | None = None) -> InnerList:
    items = []
    for n in names:
        if n.endswith(";req"):
            items.append(Item(n[: -len(";req")], {"req": True}))
        else:
            items.append(Item(n))
    params: dict[str, int | str] = {"created": created}
    if keyid:
        params["keyid"] = keyid
    params.update(extra or {})
    return InnerList(items, dict(params))  # type: ignore[arg-type]


def _covered_names(il: InnerList) -> set[str]:
    out = set()
    for it in il.items:
        n = str(it.value)
        out.add(n + ";req" if it.params.get("req") else n)
    return out


# -------------------------------------------------------------------- signing


def sign_message(names: list[str], key: SigningKey, signature_key_value: str,
                 req: HttpRequest, resp: HttpResponse | None = None, label: str = "sig",
                 created: int | None = None) -> dict[str, str]:
    """Return Signature-Input, Signature and Signature-Key headers for req or resp."""
    created = int(time.time()) if created is None else created
    comps = build_components(names, created, key.kid)
    target: HttpRequest | HttpResponse = resp if resp is not None else req
    if "signature-key" in names:
        target.headers["signature-key"] = signature_key_value
    base = signature_base(comps, req, resp)
    sig = key.sign(base)
    return {
        "Signature-Input": ser_dictionary({label: comps}),
        "Signature": ser_dictionary({label: Item(sig)}),
        "Signature-Key": signature_key_value,
    }


# ------------------------------------------------------------------ verification


class KeyResolver(Protocol):
    def resolve(self, signer_id: str, dwk: str, kid: str, now: float | None = None) -> VerifyKey: ...


@dataclass(frozen=True)
class VerifiedSigner:
    id: str
    dwk: str
    kid: str
    label: str
    created: int
    covered: frozenset[str]
    received: float = 0.0  # the verifier's clock when it checked `created`


def verify_request(req: HttpRequest, resolver: KeyResolver, *, required: list[str],
                   window: int = 60, now: float | None = None,
                   expected_dwk: str | None = "aauth-person.json",
                   admit: Callable[[str], None] | None = None) -> VerifiedSigner:
    """Core, Verification (Server), for a server signer under the jwks_uri scheme.

    `admit(id)` is called with the signer's id before its keys are discovered, and
    raises to refuse a signer the verifier does not accept: no fetch is made for it."""
    now = time.time() if now is None else now
    si, sg, sk = req.header("signature-input"), req.header("signature"), req.header("signature-key")
    if not (si and sg and sk):
        raise SignatureError("invalid_signature", "Signature, Signature-Input and Signature-Key required")
    if max(len(si), len(sg), len(sk)) > MAX_SIGNATURE_FIELD:
        # Parsing walks every byte before anything is checked; an honest field of up to
        # MAX_LABELS signatures is a few hundred bytes each.
        raise SignatureError("invalid_signature", "signature field too long")
    try:
        d_si, d_sg, d_sk = parse_dictionary(si), parse_dictionary(sg), parse_dictionary(sk)
    except SFVError as e:
        raise SignatureError("invalid_signature", f"malformed signature headers: {e}") from e
    labels = [lb for lb in d_sk if lb in d_si and lb in d_sg]
    if not labels:
        raise SignatureError("invalid_signature", "no label present in all three headers")
    if len(labels) > MAX_LABELS:
        raise SignatureError("invalid_signature", f"more than {MAX_LABELS} signatures")
    # Signature-Key -09 Section 3.2 allows several signatures per message. Evaluate each
    # complete label and accept the first that verifies, so an added label can neither
    # replace nor mask the one the server needs. The first failure is reported.
    # A signer the verifier does not accept (`admit` refuses it) fails its label only.
    errors: list[ProtocolError] = []
    for label in labels:
        try:
            return _verify_label(req, resolver, label, d_si, d_sg, d_sk, required=required,
                                 window=window, now=now, expected_dwk=expected_dwk,
                                 admit=admit)
        except ProtocolError as e:
            errors.append(e)
    raise errors[0]


MAX_LABELS = 4
# The longest Signature, Signature-Input or Signature-Key field parsed, in characters.
MAX_SIGNATURE_FIELD = 8192


def _verify_label(req: HttpRequest, resolver: KeyResolver, label: str, d_si: Any, d_sg: Any,
                  d_sk: Any, *, required: list[str], window: int, now: float,
                  expected_dwk: str | None,
                  admit: Callable[[str], None] | None = None) -> VerifiedSigner:
    comps, sigm, keym = d_si[label], d_sg[label], d_sk[label]
    if not isinstance(comps, InnerList) or not isinstance(sigm, Item) or \
            not isinstance(sigm.value, bytes) or not isinstance(keym, Item):
        raise SignatureError("invalid_signature", "malformed signature member")
    covered = _covered_names(comps)
    missing = [c for c in required if c not in covered]
    if missing:
        raise SignatureError("invalid_input", f"required components not covered: {missing}",
                             {"Signature-Error": "error=invalid_input, required_input=("
                              + " ".join(f'"{c}"' for c in required) + ")"})
    created = comps.params.get("created")
    if not isinstance(created, int) or isinstance(created, bool):
        raise SignatureError("invalid_signature", "created parameter missing")
    if created < now - window:
        raise SignatureError("invalid_signature", "signature older than the validity window")
    if created > now + window:
        raise SignatureError("clock_skew", "created is ahead of the server clock")
    expires = comps.params.get("expires")
    if "expires" in comps.params and (not isinstance(expires, int) or isinstance(expires, bool)):
        # RFC 9421 Section 2.3: "expires: Expiration time as a UNIX timestamp value of type
        # Integer". Another type is a malformed parameter, not an absent one.
        raise SignatureError("invalid_signature", "expires is not an Integer")
    if isinstance(expires, int) and expires < now:
        raise SignatureError("invalid_signature", "signature expired")
    scheme = keym.value
    if not isinstance(scheme, Token) or scheme.value != "jwks_uri":
        raise SignatureError("unsupported_scheme", "a PS signs as a server under jwks_uri",
                             {"Accept-Signature-Scheme": "jwks_uri"})
    params = [keym.params.get(p) for p in ("id", "dwk", "kid")]
    sid, dwk, kid = (x if isinstance(x, str) else "" for x in params)
    if not (sid and dwk and kid):
        raise SignatureError("invalid_key", "jwks_uri requires id, dwk and kid")
    if expected_dwk is not None and dwk != expected_dwk:
        raise SignatureError("invalid_key", f"dwk {dwk!r}, expected {expected_dwk!r}")
    if req.body and not check_content_digest(req.header("content-digest"), req.body):
        raise SignatureError("invalid_signature", "Content-Digest does not match the body")
    if admit is not None:
        admit(sid)
    key = resolver.resolve(sid, dwk, kid, now)
    # Protocol L2236: verifiers "MUST ignore" an `alg` parameter; the key decides.
    base = signature_base(comps, req)
    if not key.verify(sigm.value, base):
        # Protocol L2286: a cached key that fails is refreshed once and the signature
        # tried again (a key replaced under its kid), within the fetch floor.
        refresh = getattr(resolver, "refresh", None)
        fresh = refresh(sid, dwk, kid, now) if callable(refresh) else key
        if fresh == key or not fresh.verify(sigm.value, base):
            raise SignatureError("invalid_signature", "signature does not verify")
    return VerifiedSigner(sid, dwk, kid, label, created, frozenset(covered), now)


def verify_response(resp: HttpResponse, req: HttpRequest, key: VerifyKey,
                    required: list[str], *, expected_issuer: str | None = None,
                    window: int | None = 300, now: float | None = None) -> str:
    """Verify an SS response signature as a PS must (Supervision, Signed Decisions).

    The label must appear in Signature-Input, Signature and Signature-Key; the
    `id` in Signature-Key must be the issuer of the SS called (L342) when
    `expected_issuer` is given; `created` must fall within `window` seconds, unless
    `window` is None (no age check: a retried decision is "the same signed response",
    L316, so its `created` is that of the first answer; docs/findings.md F6).
    Returns the signer id.
    """
    si, sg, sk = resp.header("signature-input"), resp.header("signature"), \
        resp.header("signature-key")
    if not (si and sg and sk):
        raise SignatureError("invalid_signature", "unsigned response")
    try:
        d_si, d_sg, d_sk = parse_dictionary(si), parse_dictionary(sg), parse_dictionary(sk)
    except SFVError as e:
        raise SignatureError("invalid_signature", f"malformed signature fields: {e}") from e
    labels = [lb for lb in d_si if lb in d_sg and lb in d_sk]
    if len(labels) != 1:
        raise SignatureError("invalid_signature", "expected exactly one complete signature label")
    label = labels[0]
    comps, sigm, keym = d_si[label], d_sg[label], d_sk[label]
    if not (isinstance(comps, InnerList) and isinstance(sigm, Item) and isinstance(keym, Item)):
        raise SignatureError("invalid_signature", "malformed signature members")
    signer = str(keym.params.get("id") or "")
    if expected_issuer is not None and signer != expected_issuer:
        raise SignatureError("invalid_signature",
                             f"response signed by {signer!r}, not the SS called")
    created = comps.params.get("created")
    if not isinstance(created, int) or isinstance(created, bool):
        raise SignatureError("invalid_signature", "response signature has no created time")
    t = time.time() if now is None else now
    if window is not None and abs(t - created) > window:
        raise SignatureError("invalid_signature", "response signature outside the window")
    missing = [c for c in required if c not in _covered_names(comps)]
    if missing:
        raise SignatureError("invalid_input", f"response does not cover {missing}")
    if not check_content_digest(resp.header("content-digest"), resp.body):
        raise SignatureError("invalid_signature", "response Content-Digest mismatch")
    # Protocol L2236: an `alg` parameter is ignored here too.
    if not isinstance(sigm.value, bytes) or not key.verify(sigm.value,
                                                           signature_base(comps, req, resp)):
        raise SignatureError("invalid_signature", "response signature does not verify")
    return signer
