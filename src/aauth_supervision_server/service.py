"""The Supervision Server: protocol logic of AAuth Supervision -00.

`SupervisionServer.handle()` takes a parsed HTTP request and returns a
response. It has no socket code, so the whole protocol is testable in-process;
`http_server.py` adapts it to a real listener.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import html
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .errors import (
    ProtocolError,
    Response,
    SignatureError,
    invalid_request,
    json_response,
    rate_limited,
    server_error,
    unknown_mission,
    unknown_pending,
    unknown_sub,
    unsupported_iss,
)
from .httpsig import (
    HttpRequest,
    HttpResponse,
    KeyResolver,
    VerifiedSigner,
    content_digest,
    sign_message,
    verify_request,
    verify_response,
)
from .jwk import SigningKey, b64u, b64u_decode, key_from_jwk
from .policy import SERVER_ID, Act, Decision, SupervisionPolicy
from .sfv import InnerList, SFVError, parse_dictionary
from .store import (
    DecisionRecord,
    HistoryEntry,
    Mission,
    Pending,
    Reach,
    Store,
    StoredResponse,
)

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
EVENTS = {"person_token.issued", "auth_token.issued", "decision.resolved", "audit.recorded",
          "interaction.requested", "agent.bound", "revocation.received"}
ACTS = {"person_token", "auth_token", "permission"}
BASE_COMPONENTS = ["@method", "@authority", "@path", "signature-key"]
BODY_COMPONENTS = ["content-digest", "content-type"]
# Wrong operator tokens the development interaction page tolerates before it locks.
MAX_OPERATOR_FAILURES = 5


@dataclass
class TrustedPS:
    auto_connect: bool = False
    tenants: list[str] = field(default_factory=list)


@dataclass
class ServerConfig:
    issuer: str
    name: str = "AAuth APC Supervisor"
    trusted_ps: dict[str, TrustedPS] = field(default_factory=dict)
    open_registration: bool = False  # accept unknown PSes, with person interaction at connect
    signature_window: int = 60
    rate_limit_per_minute: int = 0
    clarification_rounds: int = 3
    clarification_timeout: int = 120
    admin_token: str = ""  # confirms connect interactions on the dev interaction page
    documentation_uri: str = ""

    def __post_init__(self) -> None:
        # Supervision L165: endpoint URLs MUST be HTTPS on the issuer's origin. Every
        # endpoint is built from `issuer`, so an HTTPS origin here is what guarantees it.
        p = urlsplit(self.issuer)
        if p.scheme != "https" or not p.hostname or p.query or p.fragment or "@" in p.netloc:
            raise ValueError(f"issuer must be an https URL with no userinfo, query or fragment: "
                             f"{self.issuer!r}")
    @property
    def authority(self) -> str:
        return (urlsplit(self.issuer).netloc or "").lower()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServerConfig:
        """Build a config from its JSON form; a misspelt or mistyped member is an error,
        never silently ignored."""
        types: dict[str, type | tuple[type, ...]] = {
            "issuer": str, "name": str, "trusted_ps": dict, "open_registration": bool,
            "signature_window": int, "rate_limit_per_minute": int, "clarification_rounds": int,
            "clarification_timeout": int, "admin_token": str, "documentation_uri": str}
        for k, v in d.items():
            if k not in types:
                raise ValueError(f"server config: unknown member {k!r}")
            t = types[k]
            if not isinstance(v, t) or (t is int and isinstance(v, bool)):
                raise ValueError(f"server config: {k} has the wrong type")
            if t is int and v < 0:
                raise ValueError(f"server config: {k} must not be negative")
        if "issuer" not in d:
            raise ValueError("server config: issuer is required")
        tp = {}
        for k, v in d.get("trusted_ps", {}).items():
            if not isinstance(v, dict) or set(v) - {"auto_connect", "tenants"}:
                raise ValueError(f"server config: trusted_ps[{k!r}] has unknown members")
            if ("auto_connect" in v and not isinstance(v["auto_connect"], bool)) or (
                    "tenants" in v and not (isinstance(v["tenants"], list)
                                            and all(isinstance(x, str) for x in v["tenants"]))):
                raise ValueError(f"server config: trusted_ps[{k!r}] has the wrong types")
            tp[k] = TrustedPS(**v)
        known = {f for f in cls.__dataclass_fields__ if f != "trusted_ps"}
        return cls(**{k: v for k, v in d.items() if k in known}, trusted_ps=tp)


# JSON types of the members the drafts define (Supervision -00 Envelope, Connect, Mission
# Endpoint, Decision Endpoint, Event Endpoint). A member of the wrong type is a malformed
# request, answered `invalid_request`, never a server error. Members not listed are
# extensions and pass through; code that reads one checks its type where it reads it.
_STR_MEMBERS = frozenset({
    "sdi", "id", "sub", "agent", "mission_s256", "action", "act", "event", "tenant",
    "resource", "resource_token", "presented_token", "agent_token", "upstream_token",
    "subagent_token", "justification", "description", "summary", "answer", "apply",
    "reason", "s256", "mission", "jti", "scope", "issuer", "iss", "agent_iss", "agent_sub",
    "token_type", "type", "url", "recommendation", "supervisor", "r3_proposal",
    "clarification_response"})
_INT_MEMBERS = frozenset({"iat", "exp"})
_OBJ_MEMBERS = frozenset({"parameters", "proposed"})
_LIST_MEMBERS = frozenset({"tools", "resources", "transcript"})


def _check_member_types(b: dict[str, Any]) -> None:
    for k, v in b.items():
        if v is None:
            continue  # absent in effect; `_require` refuses it where the member is REQUIRED
        if k in _STR_MEMBERS:
            ok = isinstance(v, str)
        elif k in _INT_MEMBERS:
            ok = isinstance(v, int) and not isinstance(v, bool)
        elif k in _OBJ_MEMBERS:
            ok = isinstance(v, dict)
        elif k in _LIST_MEMBERS:
            ok = isinstance(v, list)
        elif k == "aud":  # a JWT audience: a string or an array of strings
            ok = isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))
        else:
            continue
        if not ok:
            raise invalid_request(f"member {k!r} has the wrong JSON type")


def _server_identifier(value: Any, what: str) -> str:
    """Core, Server Identifiers: https, host only, lowercase, no port, path or trailing slash.

    Policy patterns (`deny_resources`, rule `resource`) compare identifiers as exact
    strings, as the core requires, so a non-conforming value such as
    `https://EXFIL.example` would otherwise slip past a deny written for
    `https://exfil.example`. The PS must validate these; the SS refuses one that is not.
    """
    s = str(value or "")
    if not SERVER_ID.fullmatch(s):
        raise ProtocolError(400, "invalid_request", f"{what} is not a server identifier: {s!r}")
    return s


MAX_BUDGET = 2 ** 53  # Budgets, Range Limits: a JSON number is exact only to 2^53


def _budget_int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_BUDGET else None


def _budget_claims(act: Act, rt: dict[str, Any]) -> None:
    """AAuth Budgets, Resource Token Extensions: the `budget` offer and the
    `budget_consumed` record. Both are resource-signed and forwarded by the PS as the agent
    sent them. An offer that is not a well-formed budget object is treated as absent (a
    policy with a ceiling at the resource then asks), and a record is read only beside a
    usable offer, in that offer's scale, as Budgets requires."""
    b = rt.get("budget")
    if not isinstance(b, dict):
        return
    amount, decimals, unit = _budget_int(b.get("amount")), _budget_int(b.get("decimals")), b.get("unit")
    if amount is None or decimals is None or not isinstance(unit, str) or not unit:
        return
    act.budget_unit, act.budget_amount = f"{unit}/{decimals}", amount
    rec = rt.get("budget_consumed")
    if isinstance(rec, dict):
        jti, consumed = rec.get("jti"), _budget_int(rec.get("consumed"))
        if isinstance(jti, str) and consumed is not None:
            act.consumed_jti, act.consumed = jti, consumed


def _decode_jwt_claims(token: Any) -> dict[str, Any]:
    """Read a forwarded JWT's claims. The PS verified it; the SS learns from it."""
    if not isinstance(token, str) or token.count(".") != 2:
        raise invalid_request("forwarded token is not a JWT")
    try:
        claims = json.loads(b64u_decode(token.split(".")[1]))
    except (ValueError, json.JSONDecodeError) as e:
        raise invalid_request("forwarded token payload is not JSON") from e
    if not isinstance(claims, dict):
        raise invalid_request("forwarded token payload is not an object")
    return claims


def _operations(proposal: dict[str, Any]) -> list[str]:
    ops: list[str] = []
    raw = proposal.get("operations")
    if not isinstance(raw, list):
        return ops
    for o in raw:
        if isinstance(o, dict):
            for k in ("tool", "operationId", "operation", "method", "name", "action"):
                if isinstance(o.get(k), str):
                    ops.append(o[k])
                    break
    return ops


class SupervisionServer:
    def __init__(self, config: ServerConfig, policy: SupervisionPolicy, resolver: KeyResolver,
                 signing_key: SigningKey | None = None, store: Store | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.cfg = config
        self.policy = policy
        self.resolver = resolver
        self.key = signing_key
        self.store = store or Store()
        self.clock = clock
        self._rate: dict[str, list[float]] = {}
        self._rate_lock = threading.Lock()
        self._operator_failures = 0

    # ================================================================ dispatch

    def handle(self, req: HttpRequest) -> Response:
        try:
            return self._route(req)
        except ProtocolError as e:
            return e.to_response()
        except Exception as e:  # defensive: an unexpected failure never leaks its detail
            return server_error(type(e).__name__).to_response()

    def _route(self, req: HttpRequest) -> Response:
        m, p = req.method.upper(), req.path.rstrip("/") or "/"
        if m == "GET" and p == "/.well-known/aauth-supervisor.json":
            return json_response(200, self.metadata(), {"Cache-Control": "max-age=300"})
        if m == "GET" and p == "/.well-known/jwks.json":
            keys = [self.key.public_jwk()] if self.key else []
            return json_response(200, {"keys": keys}, {"Cache-Control": "max-age=300"})
        if m == "GET" and p == "/health":
            return json_response(200, {"status": "ok"})
        if p == "/interaction":
            return self._interaction(req)
        if _normalize(req.authority) != self.cfg.authority:
            raise invalid_request(f"request addressed to {req.authority}, not this SS")
        if m == "POST" and p == "/connect":
            return self._with_signer(req, self._connect)
        if m == "POST" and p == "/mission":
            return self._with_signer(req, self._mission_proposal)
        if m == "POST" and p.startswith("/mission/"):
            return self._with_signer(req, lambda r, s, b: self._mission_action(
                r, s, b, p.split("/", 2)[2]))
        if m == "POST" and p == "/decision":
            return self._with_signer(req, self._decision)
        if m == "POST" and p == "/event":
            return self._with_signer(req, self._event)
        if p.startswith("/pending/") and m in ("GET", "POST", "DELETE"):
            return self._with_signer(req, lambda r, s, b: self._pending(r, s, b, p.split("/")[2]),
                                     body_required=(m == "POST"))
        raise ProtocolError(404, "invalid_request", f"no endpoint {m} {p}")

    def metadata(self) -> dict[str, Any]:
        i = self.cfg.issuer.rstrip("/")
        md: dict[str, Any] = {
            "issuer": self.cfg.issuer,
            "name": self.cfg.name,
            "connect_endpoint": f"{i}/connect",
            "mission_endpoint": f"{i}/mission",
            "decision_endpoint": f"{i}/decision",
            "event_endpoint": f"{i}/event",
        }
        if self.key:
            md["jwks_uri"] = f"{i}/.well-known/jwks.json"
        if self.cfg.documentation_uri:
            md["documentation_uri"] = self.cfg.documentation_uri
        return md

    # ================================================================ auth

    def _with_signer(self, req: HttpRequest,
                     fn: Callable[[HttpRequest, VerifiedSigner, dict[str, Any]], Response],
                     body_required: bool = True) -> Response:
        required = BASE_COMPONENTS + (BODY_COMPONENTS if req.body else [])
        signer = verify_request(req, self.resolver, required=required,
                                window=self.cfg.signature_window, now=self.clock())
        if req.query and "@query" not in signer.covered:
            raise invalid_request("a query on a signed endpoint must be covered by @query")
        if signer.id not in self.cfg.trusted_ps and not self.cfg.open_registration:
            raise unsupported_iss(f"{signer.id} is not a PS this SS accepts")
        self._throttle(signer.id)
        # Equivalent mutant: `{}` -> `None` is unobservable, the bodiless GET and DELETE
        # /pending/ handlers never read their body (docs/mutation-testing.md).
        body: dict[str, Any] = {}  # pragma: no mutate
        if req.body:
            ctype = (req.header("content-type") or "").partition(";")[0].strip().lower()
            if ctype != "application/json":
                raise invalid_request("body must be application/json")
            try:
                parsed = json.loads(req.body)
            except ValueError as e:
                raise invalid_request("body is not JSON") from e
            if not isinstance(parsed, dict):
                raise invalid_request("body is not a JSON object")
            _check_member_types(parsed)
            body = parsed
        elif body_required:  # only POST routes require a body (GET/DELETE /pending/ do not)
            raise invalid_request("missing body")
        with self.store.lock:
            resp = fn(req, signer, body)
            self.store.save()
        if resp.status == 200 and resp.body and "Signature" not in resp.headers:
            resp = self._sign(req, resp)  # connect answers too: one rule for the PS to check
        return resp

    def _throttle(self, iss: str) -> None:
        limit = self.cfg.rate_limit_per_minute
        if limit <= 0:
            return
        now = self.clock()
        with self._rate_lock:
            q = [t for t in self._rate.get(iss, []) if now - t < 60]
            if len(q) >= limit:
                raise rate_limited(max(1, int(60 - (now - q[0]))))
            q.append(now)
            self._rate[iss] = q

    def _require(self, body: dict[str, Any], *names: str) -> None:
        missing = [n for n in names if n not in body or body[n] in (None, "")]
        if missing:
            raise invalid_request(f"missing member(s): {', '.join(missing)}")
        # Member types (iat an integer, not a boolean) are checked once for every body by
        # _check_member_types before any handler runs, so they are not re-checked here.

    def _connected(self, signer: VerifiedSigner, sub: str) -> None:
        if Store.k(signer.id, sub) not in self.store.connections:
            raise unknown_sub(f"no connection for this sub from {signer.id}")

    def _prior(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]
               ) -> DecisionRecord | None:
        """The record for this sdi, if the request is a repeat of the one that opened it.

        An sdi reused for a different request is refused, never answered from the
        record: otherwise a PS could obtain one act's answer for another.
        """
        rec = self.store.decisions.get(Store.k(s.id, b["sdi"]))
        if rec is not None and rec.fp and rec.fp != _fingerprint(req.path, b):
            raise invalid_request("sdi already used for a different request")
        return rec

    def _mission(self, signer: VerifiedSigner, s256: str) -> Mission:
        m = self.store.missions.get(Store.k(signer.id, s256))
        if m is None:
            raise unknown_mission(f"no record of mission {s256}")
        return m

    # ================================================================ signing

    def _sign(self, req: HttpRequest, resp: Response) -> Response:
        if not self.key:
            return resp
        resp.headers["Content-Digest"] = content_digest(resp.body)
        names = ["@status", "content-type", "content-digest"]
        req_side = (["content-digest;req"] if req.body else []) + ["@authority;req", "@path;req"]
        accept = req.header("accept-signature")
        label = "sig"
        if accept:
            try:
                d = parse_dictionary(accept)
                label, member = next(iter(d.items()))
                if isinstance(member, InnerList):
                    for it in member.items:
                        n = str(it.value) + (";req" if it.params.get("req") else "")
                        if n not in names and n not in req_side:
                            req_side.append(n)
            except (SFVError, StopIteration):
                pass
        names += [n for n in req_side if n not in names]
        # A component the request lacks (content-digest on a bodiless poll) cannot be
        # covered; drop that one, keep the rest of what the PS asked for.
        names = [n for n in names if not (n.endswith(";req") and not n.startswith("@")
                                          and req.header(n.split(";")[0]) is None)]
        hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.body)
        sk = (f'{label}=jwks_uri;id="{self.cfg.issuer}";dwk="aauth-supervisor.json";'
              f'kid="{self.key.kid}"')
        try:
            h = sign_message(names, self.key, sk, req, hr, label=label, created=int(self.clock()))
        except SignatureError:
            names = ["@status", "content-type", "content-digest"]
            h = sign_message(names, self.key, sk, req, hr, label=label, created=int(self.clock()))
        resp.headers.update(h)
        return resp

    def _store_response(self, resp: Response) -> StoredResponse:
        return StoredResponse(resp.status, dict(resp.headers), resp.body.decode())

    def _replay(self, req: HttpRequest, stored: StoredResponse) -> Response:
        """Re-deliver a stored terminal answer, signed for THIS request.

        A response signature covers request components (`@path;req`,
        `content-digest;req`), so a stored answer delivered to a poll or a
        retry is signed against that delivery, never replayed with the
        signature of the request that first produced it.
        """
        resp = Response(stored.status, dict(stored.headers), stored.body.encode())
        if resp.status == 200 and resp.body:
            return self._sign(req, resp)
        return resp

    def _replay_record(self, req: HttpRequest, rec: DecisionRecord) -> Response:
        """Answer a retry at the endpoint that took the request (Idempotence, L316).

        The same request under the same `sdi` gets the same signed response: the
        signature's `;req` components are those of the retried request, which
        is the same request, so the stored signature still verifies. A retry that is
        the same request semantically but not byte for byte (members reordered, so a
        different `content-digest`) would not verify against the stored signature, so
        it gets the stored answer signed for this delivery instead.
        """
        if rec.signed is not None:
            stored = Response(rec.signed.status, dict(rec.signed.headers),
                              rec.signed.body.encode())
            if self.key is None or self._signature_binds(req, stored):
                return stored
        assert rec.response is not None
        resp = self._replay(req, rec.response)
        if rec.signed is None:
            rec.signed = self._store_response(resp)
        return resp

    def _signature_binds(self, req: HttpRequest, resp: Response) -> bool:
        """Whether a stored signed response verifies for this request (its age aside)."""
        assert self.key is not None
        hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()},
                          resp.body)
        try:
            verify_response(hr, req, key_from_jwk(self.key.public_jwk()), ["@status"],
                            window=None)
        except SignatureError:
            return False
        return True

    # ================================================================ connect

    def _connect(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]) -> Response:
        self._require(b, "action", "id", "iat", "sub")
        key = Store.k(s.id, b["sub"])
        # A connect or disconnect is acted on once per (iss, id): a retried or captured copy
        # reports the current state and changes nothing (no undoing a later disconnect).
        once = Store.k("connect", s.id, str(b["id"]))
        if once in self.store.events_seen:
            if key in self.store.connections:
                return json_response(200, {"status": "connected"})
            for p in self.store.pending.values():
                if p.kind == "connect" and p.iss == s.id and p.sub == b["sub"] and not p.resolved:
                    return self._connect_pending(p)
            return json_response(200, {"status": "disconnected"})
        if b["action"] not in ("connect", "disconnect"):
            raise invalid_request("action must be connect or disconnect")
        self.store.events_seen.add(once)
        if b["action"] == "disconnect":
            self.store.connections.pop(key, None)
            return json_response(200, {"status": "disconnected"})
        if key in self.store.connections:
            return json_response(200, {"status": "connected"})
        trust = self.cfg.trusted_ps.get(s.id)
        tenant = b.get("tenant")
        if trust and (trust.auto_connect or (tenant and tenant in trust.tenants)):
            self.store.connections[key] = {"iss": s.id, "sub": b["sub"], "tenant": tenant,
                                           "at": int(self.clock())}
            return json_response(200, {"status": "connected"})
        # The person confirms the pairing at the SS.
        for p in self.store.pending.values():
            if p.kind == "connect" and p.iss == s.id and p.sub == b["sub"] and not p.resolved:
                return self._connect_pending(p)
        code = "".join(secrets.choice(CROCKFORD) for _ in range(10))
        p = Pending(secrets.token_urlsafe(16), s.id, "", "connect",
                    dict(b) | {"_ps_name": self._ps_name(s.id)}, code=code, sub=b["sub"])
        self.store.pending[p.id] = p
        return self._connect_pending(p)

    def _ps_name(self, iss: str) -> str:
        """The PS's display `name` from its metadata, for the confirmation page (L655).

        Read from the metadata the resolver fetched to verify this very request, so a
        connect never makes a network call while holding the store lock.
        """
        cached = getattr(self.resolver, "cached_metadata", None)
        meta = cached(iss, "aauth-person.json") if callable(cached) else None
        name = meta.get("name") if isinstance(meta, dict) else None
        return name if isinstance(name, str) else ""

    def _connect_pending(self, p: Pending) -> Response:
        url = self.cfg.issuer.rstrip("/") + "/interaction"
        return json_response(202, {"status": "pending"}, {
            "AAuth-Requirement": f'requirement=interaction; url="{url}"; code="{p.code}"',
            "Location": f"/pending/{p.id}", "Retry-After": "5", "Cache-Control": "no-store"})

    def _interaction(self, req: HttpRequest) -> Response:
        """Development interaction page: an operator confirms a pending connect."""
        if req.method.upper() == "GET":
            code = (parse_qs(req.query).get("code") or [""])[0]
            p = next((x for x in self.store.pending.values()
                      if x.kind == "connect" and x.code == code and not x.resolved), None)
            if p is None:
                return Response(404, {"Content-Type": "text/plain"}, b"Unknown or used code.\n")
            name = str(p.request.get("_ps_name") or "(no name in its metadata)")
            page = (f"<!doctype html><meta charset=utf-8><title>Confirm person server</title>"
                    f"<h1>Confirm person server</h1><p>Person server: <b>{html.escape(p.iss)}</b>"
                    f"</p><p>Name: <b>{html.escape(name)}</b></p>"
                    f"<p>Code: <b>{html.escape(p.code)}</b></p><p>Confirm only if you started "
                    f"this connection and the code matches the one your person server shows."
                    f"</p><form method=post>"
                    f"<input type=hidden name=code value='{html.escape(p.code)}'>"
                    f"<label>Operator token <input type=password name=admin_token></label> "
                    f"<button>Confirm</button></form>")
            return Response(200, {"Content-Type": "text/html; charset=utf-8",
                                  "Cache-Control": "no-store",
                                  "X-Frame-Options": "DENY",
                                  "Content-Security-Policy": "frame-ancestors 'none'"}, page.encode())
        if req.method.upper() == "POST":
            form = parse_qs(req.body.decode(errors="replace"))
            code = (form.get("code") or [""])[0]
            token = (form.get("admin_token") or [""])[0]
            given, expected = (s.encode("utf-8", "surrogatepass") for s in (token, self.cfg.admin_token))
            if self._operator_failures >= MAX_OPERATOR_FAILURES:
                # Brute-forcing the operator token is bounded: after this many wrong tokens
                # the page refuses every confirmation until the process restarts.
                return Response(403, {"Content-Type": "text/plain"},
                                b"Locked after repeated wrong operator tokens; restart the SS.\n")
            if not self.cfg.admin_token or not hmac.compare_digest(given, expected):
                self._operator_failures += 1
                return Response(403, {"Content-Type": "text/plain"}, b"Not authorized.\n")
            self._operator_failures = 0
            with self.store.lock:
                p = next((x for x in self.store.pending.values()
                          if x.kind == "connect" and x.code == code and not x.resolved), None)
                if p is None:
                    return Response(404, {"Content-Type": "text/plain"}, b"Unknown code.\n")
                self.store.connections[Store.k(p.iss, p.sub)] = {
                    "iss": p.iss, "sub": p.sub, "tenant": p.request.get("tenant"),
                    "at": int(self.clock())}
                p.resolved = StoredResponse(200, {"Content-Type": "application/json"},
                                            '{"status":"connected"}')
                self.store.save()
            return Response(200, {"Content-Type": "text/plain"}, b"Connected.\n")
        return Response(405, {"Allow": "GET, POST"}, b"")

    # ================================================================ missions

    def _mission_proposal(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]
                          ) -> Response:
        self._require(b, "sdi", "iat", "sub", "agent", "agent_token", "description")
        for name in ("resources", "tools"):
            if name in b and not isinstance(b[name], list):
                raise ProtocolError(400, "invalid_request", f"{name} must be an array")
        self._connected(s, b["sub"])
        prior = self._prior(req, s, b)
        if prior and prior.response:
            return self._replay_record(req, prior)
        d = self.policy.decide_proposal(b, self.clock())
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.decision == "allow":
            body.update(d.narrow)
        elif d.decision == "ask":
            body["summary"] = d.summary
            if d.narrow.get("proposed"):
                body["proposed"] = d.narrow["proposed"]
        elif d.reason:
            body["reason"] = d.reason
        return self._terminal(req, s, b, "mission_proposal", d, body)

    def _mission_action(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any],
                        s256: str) -> Response:
        action = b.get("action")
        if action not in ("approved", "update", "completion", "terminated"):
            raise invalid_request("missing or unrecognized action")
        if action in ("approved", "terminated"):
            self._require(b, "id", "iat", "sub", "agent")
            self._connected(s, b["sub"])
            ek = Store.k(s.id, b["id"])
            if ek in self.store.events_seen:
                return Response(201)
            if action == "approved":
                self._require(b, "s256", "mission")
                if b["s256"] != s256:
                    raise invalid_request("s256 differs from the mission URL")
                try:
                    raw = b64u_decode(b["mission"])
                    blob = json.loads(raw)
                except (ValueError, json.JSONDecodeError) as e:
                    raise invalid_request("mission is not base64url JSON") from e
                if b64u(hashlib.sha256(raw).digest()) != s256:
                    raise invalid_request("s256 is not the digest of mission")
                key = Store.k(s.id, s256)
                if key not in self.store.missions:
                    self.store.missions[key] = Mission(s256, b["agent"], b["sub"], s.id, blob)
            else:
                m = self._mission(s, s256)
                m.state, m.reason = "terminated", str(b.get("reason", ""))
            self.store.events_seen.add(ek)
            return Response(201)
        self._require(b, "sdi", "iat", "sub", "agent")
        self._connected(s, b["sub"])
        prior = self._prior(req, s, b)
        if prior and prior.response:
            return self._replay_record(req, prior)
        m = self._mission(s, s256)
        if m.state != "active":
            d = Decision("deny", reason="The mission has terminated.")
        elif action == "update":
            self._require(b, "description")
            d = Decision("ask", summary="The agent reports a change to the mission: "
                         + str(b["description"])) if self.policy.ask_on_mission_update \
                else Decision("allow")
            if d.decision == "allow":
                m.blob.setdefault("_updates", []).append(b["description"])
        else:
            self._require(b, "summary")
            d = Decision("allow")
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.summary:
            body["summary"] = d.summary
        if d.reason:
            body["reason"] = d.reason
        return self._terminal(req, s, b, f"mission_{action}", d, body)

    # ================================================================ decisions

    def _act_from(self, s: VerifiedSigner, b: dict[str, Any]) -> Act:
        act = Act(b["act"], s.id, b["sub"], b["agent"], b.get("mission_s256") or "",
                  justification=str(b.get("justification") or ""))
        if act.act == "person_token":
            self._require(b, "resource", "agent_token")
            act.resource = _server_identifier(b["resource"], "resource")
        elif act.act == "permission":
            self._require(b, "action")
            act.tool = str(b["action"])
            params = b.get("parameters")
            act.parameters = params if isinstance(params, dict) else {}
            act.parameters_provenance = "agent"
            if b.get("description"):
                act.justification = (act.justification + " " + str(b["description"])).strip()
        else:
            self._require(b, "resource_token", "presented_token")
            rt = _decode_jwt_claims(b["resource_token"])
            act.resource = _server_identifier(rt.get("iss"), "resource token iss")
            act.scope = str(rt.get("scope", "") or "")
            _budget_claims(act, rt)
            member = self.policy.r3_member  # None: spec-only, the extension is off
            if member is not None and member in b:
                prop = self._proposal(b[member], rt)
                act.operations = _operations(prop)
                params = prop.get("parameters")
                act.parameters = params if isinstance(params, dict) else {}
                act.parameters_provenance = "resource"
                res = prop.get("result")
                act.result = res if isinstance(res, dict) else None
        return act

    @staticmethod
    def _proposal(value: Any, rt: dict[str, Any]) -> dict[str, Any]:
        """The forwarded R3 per-call proposal (the extension proposed in AAuth #256).

        A base64url string carries the exact bytes and is checked against the
        resource token's `r3_s256`; an object is taken on the PS's word.
        """
        if isinstance(value, str):
            try:
                raw = b64u_decode(value)
            except ValueError as e:
                raise invalid_request("R3 proposal is not base64url") from e
            if rt.get("r3_s256") and b64u(hashlib.sha256(raw).digest()) != rt["r3_s256"]:
                raise invalid_request("R3 proposal bytes do not match r3_s256")
            try:
                obj = json.loads(raw)
            except ValueError as e:  # JSONDecodeError, and UnicodeDecodeError for non-UTF-8
                raise invalid_request("R3 proposal is not JSON") from e
        else:
            obj = value
        if not isinstance(obj, dict):
            raise invalid_request("R3 proposal is not an object")
        return obj

    def _decision(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]) -> Response:
        self._require(b, "sdi", "act", "iat", "sub", "agent")
        if b["act"] not in ACTS:
            raise invalid_request(f"unrecognized act {b['act']!r}")
        self._connected(s, b["sub"])
        rec = self._prior(req, s, b)
        if rec is not None:
            if rec.response:
                return self._replay_record(req, rec)
            pend = next((p for p in self.store.pending.values()
                         if p.sdi == b["sdi"] and p.iss == s.id and p.resolved is None), None)
            if pend:
                return self._clarify_response(pend)
        return self._evaluate(req, s, b)

    def _evaluate(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any],
                  pending: Pending | None = None, clarify: bool = True) -> Response:
        act = self._act_from(s, b)
        mission = self._mission(s, act.mission_s256) if act.mission_s256 else None
        history = self.store.history_for(s.id, act.sub, act.agent, act.mission_s256)
        if act.consumed_jti:
            # Budgets: a record names a token the PS issued; a later record for the same
            # jti supersedes an earlier one, so reconciling is idempotent.
            for h in history:
                if h.jti == act.consumed_jti and h.resource == act.resource:
                    h.consumed = act.consumed
        d = self.policy.decide(act, mission, history, self.store.reach, self.clock(),
                               clarify=clarify)
        if d.decision == "clarify":
            rounds = pending.rounds if pending else 0
            if rounds >= self.cfg.clarification_rounds:
                d = Decision("ask", summary="The agent did not resolve the supervisor's question "
                             "within the round limit.", entry=d.entry, kind=d.kind)
            else:
                p = pending or Pending(secrets.token_urlsafe(16), s.id, b["sdi"], "clarify",
                                       dict(b), "/decision")
                p.request = dict(b)
                p.rounds = rounds + 1
                # Each round restates `timeout`, so each round gets the full time to answer.
                p.deadline = (self.clock() + self.cfg.clarification_timeout
                              if self.cfg.clarification_timeout > 0 else 0.0)
                self.store.pending[p.id] = p
                p.code = d.clarification
                rec = DecisionRecord(b["sdi"], s.id, act.sub, act.agent, act.act, "clarify",
                                     act.mission_s256, d.entry, d.kind, d.composition,
                                     fp=_fingerprint(req.path, b))
                self.store.decisions[Store.k(s.id, b["sdi"])] = rec
                return self._clarify_response(p)
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.decision == "allow":
            body.update({k: v for k, v in d.narrow.items() if k in ("scope", "exp")})
        elif d.decision == "deny":
            if d.reason:
                body["reason"] = d.reason
        else:
            body["summary"] = d.summary
            if d.recommendation:
                body["recommendation"] = d.recommendation
            if d.apply_options:
                body["apply_options"] = d.apply_options
        resp = self._terminal(req, s, b, act.act, d, body)
        if pending is not None:
            pending.resolved = self.store.decisions[Store.k(s.id, b["sdi"])].response
        return resp

    def _terminal(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any], act: str,
                  d: Decision, body: dict[str, Any]) -> Response:
        unsigned = json_response(200, body)
        stored = self._store_response(unsigned)
        resp = self._sign(req, unsigned)
        opened = self.store.decisions.get(Store.k(s.id, b["sdi"]))
        rec = DecisionRecord(b["sdi"], s.id, b["sub"], b["agent"], act, d.decision,
                             b.get("mission_s256") or "", d.entry, d.kind, d.composition,
                             stored,
                             fp=opened.fp if opened and opened.fp else _fingerprint(req.path, b))
        if not req.path.startswith("/pending/"):
            rec.signed = self._store_response(resp)
        self.store.decisions[Store.k(s.id, b["sdi"])] = rec
        if act == "permission" and d.decision == "allow" and d.entry is not None:
            # No issuance event follows a permission: the grant is the act.
            self.store.history_for(s.id, b["sub"], b["agent"], rec.mission_s256).append(
                _with_sdi(d.entry, b["sdi"]))
        return resp

    def _clarify_response(self, p: Pending) -> Response:
        body: dict[str, Any] = {"sdi": p.sdi, "status": "pending", "decision": "clarify",
                                "clarification": p.code}
        if self.cfg.clarification_timeout > 0:
            # Core, Clarification Required: "Seconds until the server times out the
            # request". Stated only because `_pending` enforces it.
            body["timeout"] = self.cfg.clarification_timeout
        return json_response(202, body,
                             {"Location": f"/pending/{p.id}", "Retry-After": "0",
                              "Cache-Control": "no-store",
                              "AAuth-Requirement": "requirement=clarification"})

    def _pending(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any],
                 pid: str) -> Response:
        p = self.store.pending.get(pid)
        if p is None or p.iss != s.id:
            raise unknown_pending()
        if p.cancelled:
            return Response(410)
        m = req.method.upper()
        if p.kind == "connect":
            if m != "GET":
                raise invalid_request("connect is polled with GET")
            if p.resolved:
                return self._replay(req, p.resolved)
            return self._connect_pending(p)
        if p.resolved is None and p.deadline and self.clock() >= p.deadline:
            # Core, Clarification Required: the recipient "MUST respond before this
            # deadline". Past it the request is over: polling error `expired` (408).
            rec = self.store.decisions.get(Store.k(s.id, p.sdi))
            if rec and rec.decision == "clarify":
                rec.decision = "expired"
            raise ProtocolError(408, "expired", "the clarification was not answered in time")
        if m == "GET":
            return self._replay(req, p.resolved) if p.resolved else self._clarify_response(p)
        if m == "DELETE":
            p.cancelled = True
            rec = self.store.decisions.get(Store.k(s.id, p.sdi))
            # Withdrawing abandons only an open question. Once answered, the decision
            # stands: rewriting it would drop the person's later decision.resolved.
            if rec and p.resolved is None:
                rec.decision = "abandoned"
            return Response(204)
        if p.resolved:
            return self._replay(req, p.resolved)
        action = b.get("action")
        merged = dict(p.request)
        if action == "clarification_response":
            text = str(b.get("clarification_response") or "")
            merged["justification"] = (str(merged.get("justification") or "") + " " + text).strip()
        elif action == "updated_request":
            self._require(b, "resource_token", "presented_token")
            self._same_resource_request(p.request, b["resource_token"])
            carried = ["resource_token", "presented_token", "justification"]
            if self.policy.r3_member is not None:
                carried.append(self.policy.r3_member)
            merged.update({k: b[k] for k in carried if k in b})
        else:
            raise invalid_request("missing or unrecognized action")
        # Clarification is answered: a high-impact act without resource evidence is put to
        # the person, it does not loop.
        return self._evaluate(req, s, merged, pending=p, clarify=False)

    # Core, Updated Request: the new resource token "MUST have the same `iss`, `ps`,
    # `sub`, `agent_jkt`, `mission_s256`, and `tenant` as the original".
    _SAME_IN_UPDATE = ("iss", "ps", "sub", "agent_jkt", "mission_s256", "tenant")

    @classmethod
    def _same_resource_request(cls, original: dict[str, Any], token: Any) -> None:
        """Refuse an updated request that is not the same request for a smaller grant.

        The PS checks this before relaying; the SS checks it too, because its decision
        is recorded under the original `sdi` and must be about the same resource.
        """
        if "resource_token" not in original:
            raise invalid_request("updated_request answers only a resource-token act")
        old = _decode_jwt_claims(original["resource_token"])
        new = _decode_jwt_claims(token)
        for k in cls._SAME_IN_UPDATE:
            if old.get(k) != new.get(k):
                raise invalid_request(f"updated resource token differs from the original in {k}")

    # ================================================================ events

    def _event(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]) -> Response:
        self._require(b, "event", "id", "iat", "sub", "agent")
        ev = b["event"]
        if ev not in EVENTS:
            raise invalid_request(f"unrecognized event {ev!r}")
        self._connected(s, b["sub"])
        ek = Store.k(s.id, b["id"])
        if ek in self.store.events_seen:
            return Response(201)
        ms = b.get("mission_s256") or ""
        if ms and ev != "agent.bound":
            self._mission(s, ms)
        handler = getattr(self, "_ev_" + ev.replace(".", "_"))
        handler(s, b)
        self.store.events_seen.add(ek)
        return Response(201)

    def _record(self, s: VerifiedSigner, b: dict[str, Any]) -> DecisionRecord | None:
        sdi = b.get("sdi")
        return self.store.decisions.get(Store.k(s.id, sdi)) if sdi else None

    def _commit(self, s: VerifiedSigner, rec: DecisionRecord) -> None:
        if rec.entry is not None and rec.decision in ("allow", "resolved_allow"):
            hist = self.store.history_for(s.id, rec.sub, rec.agent, rec.mission_s256)
            if not any(h.sdi == rec.sdi for h in hist):
                hist.append(_with_sdi(rec.entry, rec.sdi))

    def _ev_person_token_issued(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        return None

    def _ev_auth_token_issued(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        rec = self._record(s, b)
        if rec is not None and rec.entry is not None:
            # Issuance is a fact, whatever was decided: the act now counts for composition
            # and budgets, so a PS that issued past a deny cannot hide it from later acts.
            # It is not an answer: an `ask` stays unresolved until `decision.resolved`
            # says what the person decided, so issuance never stands in for the person.
            hist = self.store.history_for(s.id, rec.sub, rec.agent, rec.mission_s256)
            entry = next((h for h in hist if h.sdi == rec.sdi), None)
            if entry is None:
                entry = _with_sdi(rec.entry, rec.sdi)
                if rec.decision not in ("allow", "resolved_allow"):
                    entry.detail += f" (issued after {rec.decision})"
                hist.append(entry)
            if isinstance(b.get("jti"), str):
                # The token that carries this act's budget allocation: a later
                # `budget_consumed` names it (AAuth Budgets, The Consumption Record).
                entry.jti = b["jti"]
            return
        # No decision context for this sdi (replay to a new SS): classify from the event alone.
        aud = str(b.get("aud") or "")
        act = Act("auth_token", s.id, b["sub"], b["agent"], b.get("mission_s256") or "",
                  resource=aud, scope=str(b.get("scope") or ""))
        member = self.policy.r3_member
        raw = b.get(member) if member is not None else None
        forwarded = isinstance(raw, (dict, str))
        if forwarded:
            prop = self._proposal(raw, {})
            act.operations = _operations(prop)
            act.parameters = prop.get("parameters") if isinstance(prop.get("parameters"),
                                                                    dict) else {}
            act.parameters_provenance = "resource"
            act.result = prop.get("result") if isinstance(prop.get("result"), dict) else None
        c = self.policy.classify(act)
        hist = self.store.history_for(s.id, act.sub, act.agent, act.mission_s256)
        if not any(h.sdi == b.get("sdi") and h.sdi for h in hist):
            # A forwarded proposal is the resource's word for the act, whatever rule matched.
            hist.append(HistoryEntry(c.cls, aud, "resource" if forwarded else c.provenance,
                                     sdi=str(b.get("sdi") or ""), at=int(b["iat"]),
                                     amount=c.amount or 0,
                                     detail=("uncertain: " if c.uncertain else "") + "replayed"))

    def _ev_decision_resolved(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        self._require(b, "sdi", "answer")
        answer = b["answer"]
        if answer not in ("allow", "deny", "abandoned"):
            raise invalid_request("answer must be allow, deny or abandoned")
        rec = self._record(s, b)
        if rec is None:
            return
        if rec.decision != "ask":
            # Only an `ask` is put to the person. A resolution reported for an sdi the SS
            # allowed or denied (or already saw resolved) carries no authority: it must
            # not widen a deny into a standing reach.
            return
        rec.decision = "resolved_" + answer
        if answer != "allow":
            return
        if rec.act == "permission":
            self._commit(s, rec)
        apply = b.get("apply") or "once"
        if apply not in self._offered_reaches(rec):
            # The SS names the reaches (L586): a value it did not offer for this ask is
            # not one it recognizes, so the answer counts for this act only.
            apply = "once"
        if apply != "once" and rec.kind:
            self.store.reach.append(Reach(str(apply), s.id, rec.sub, rec.agent, rec.kind,
                                          rec.mission_s256 if apply != "always" else "",
                                          list(rec.composition)))

    @staticmethod
    def _offered_reaches(rec: DecisionRecord) -> set[str]:
        """The `apply_options` values the SS sent in this record's `ask`, plus `once`."""
        offered = {"once"}
        if rec.response is not None:
            try:
                sent = json.loads(rec.response.body)
            except ValueError:
                return offered
            for o in sent.get("apply_options", []) if isinstance(sent, dict) else []:
                if isinstance(o, dict) and isinstance(o.get("value"), str):
                    offered.add(o["value"])
        return offered

    def _ev_audit_recorded(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        # Agent-reported local actions: agent-asserted, so they can only tighten later decisions.
        act = Act("permission", s.id, b["sub"], b["agent"], b.get("mission_s256") or "",
                  tool=str(b.get("action") or ""),
                  parameters=b.get("parameters") if isinstance(b.get("parameters"), dict) else {},
                  parameters_provenance="agent")
        res = b.get("result")
        if isinstance(res, dict):
            act.result = res
        c = self.policy.classify(act)
        self.store.history_for(s.id, act.sub, act.agent, act.mission_s256).append(
            HistoryEntry(c.cls, act.tool, "agent", sdi="", at=int(b["iat"]), amount=c.amount or 0,
                         detail=("uncertain: " if c.uncertain else "") + "audit record"))

    def _ev_interaction_requested(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        return None

    def _ev_agent_bound(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        self.store.agents[Store.k(s.id, b["sub"], b["agent"])] = {
            "agent_iss": b.get("agent_iss"), "agent_sub": b.get("agent_sub"),
            "at": int(b["iat"])}

    def _ev_revocation_received(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        self.store.revoked.add(Store.k(str(b.get("iss") or ""), str(b.get("jti") or "")))


def _with_sdi(e: HistoryEntry, sdi: str) -> HistoryEntry:
    return dataclasses.replace(e, sdi=sdi)


def _fingerprint(path: str, b: dict[str, Any]) -> str:
    """What makes a request under an sdi "the same request" (Idempotence, L316).

    The whole body, canonically serialized, plus the endpoint. A retry is the same
    request (`iat` is unchanged on a retry, L198), so it matches; a different act
    reusing an sdi does not.
    """
    # Equivalent mutant, kept on purpose: `ensure_ascii` does not change what the
    # fingerprint distinguishes, but changing it would change every stored fingerprint, so
    # a retry across an upgrade would no longer match its sdi.
    canon = json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False)  # pragma: no mutate
    return b64u(hashlib.sha256(f"{path}\n{canon}".encode()).digest())


def _normalize(a: str) -> str:
    a = a.strip().lower()
    return a[: -len(":443")] if a.endswith(":443") else a
