"""The Supervision Server: protocol logic of AAuth Supervision -00.

`SupervisionServer.handle()` takes a parsed HTTP request and returns a
response. It has no socket code, so the whole protocol is testable in-process;
`http_server.py` adapts it to a real listener.
"""

from __future__ import annotations

import collections
import dataclasses
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeGuard
from urllib.parse import parse_qs, urlsplit

from . import markdown as md
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
from .policy import MAX_AMOUNT, PERSON_TOKEN_TOLD, SERVER_ID, Act, Decision, SupervisionPolicy
from .resolver import signer_domain
from .sfv import InnerList, SFVError, parse_dictionary, ser_bare
from .store import (
    PERSON_TOKEN,
    PERSON_TOKEN_LIFE,
    UNBOUNDED_EXP,
    WIDE_AFTER,
    DecisionRecord,
    HistoryEntry,
    Mission,
    Pending,
    Reach,
    Store,
    StoredResponse,
    iso_to_epoch,
)

# Unexpected failures, with their traceback, for the operator.
LOG = logging.getLogger("aauth_supervision_server")

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
EVENTS = {"person_token.issued", "auth_token.issued", "decision.resolved", "audit.recorded",
          "interaction.requested", "agent.bound", "revocation.received"}
ACTS = {"person_token", "auth_token", "permission"}
BASE_COMPONENTS = ["@method", "@authority", "@path", "signature-key"]
BODY_COMPONENTS = ["content-digest", "content-type"]
# Wrong operator tokens the development interaction page takes against one connect before
# that connect fails for good (Protocol L2398).
MAX_OPERATOR_FAILURES = 5
# Rate-limit rows kept before the inactive ones are dropped.
MAX_RATE_ROWS = 4096
# Open clarifications one person may have at once: each keeps its request (up to the
# body limit) to decide it again, so a further act goes to the person instead.
MAX_OPEN_CLARIFICATIONS = 100
# The largest request a clarification keeps (bytes); a larger one goes to the person.
MAX_CLARIFY_BODY = 64 * 1024
# A connect awaiting the person's confirmation, and its interaction code, expire this
# many seconds after the connect (Protocol L2400).
CONNECT_LIFETIME = 3600
# What a signer the SS does not trust (admitted by open registration) can hold: connect
# records per signer, and from all such signers together. A record is held for its
# lifetime and one more (to answer `expired`), then removed with the id that opened it.
MAX_UNCONFIRMED_PER_PS = 64
MAX_UNCONFIRMED = 1024
# The longest identifier the SS keeps. The drafts set no length; a `sub`, `sdi` or `id`
# the SS stores (an unconfirmed signer's too) is bounded.
MAX_ID_LEN = 512
# The most audiences an issued token's `aud` array may name: each is an act, decided as
# one, under the store lock.
MAX_AUD = 64
# The most entries of a proposal's `resources` and `tools` (and a clarification's
# `transcript`): each is read under the store lock.
MAX_LIST = 256
# The longest `description` (a mission's, an update's, an act's) and tool name the SS takes:
# each is kept with what it decided, and written with every snapshot.
MAX_DESCRIPTION = 64 * 1024
MAX_TOOL_NAME = 256
# A proposal's `tools`, as JSON, are bounded too (their descriptions are the agent's text,
# echoed in the answer): twice a `description`, room for an agent's whole tool list; an
# approved mission blob holds both and its resources (256, each up to an identifier's
# length), so it is at most eight times that: the blob of any proposal the SS allows fits.
MAX_TOOLS = 2 * MAX_DESCRIPTION
MAX_MISSION = 8 * MAX_DESCRIPTION
# A blob is kept parsed, and copied on every snapshot write: it holds at most this many
# JSON values. An allowed proposal's tools are echoed whole into it (Supervision L397), so
# a proposal's tools hold at most what leaves room for its resources and the blob's own
# members: the blob of any proposal the SS allows fits.
MAX_MISSION_VALUES = 10_000
MAX_TOOLS_VALUES = MAX_MISSION_VALUES - 2 * MAX_LIST
# The most identity resources an ask names one by one; the rest are counted.
MAX_NAMED = 20
# The most approval tokens one proposal has decided, each a decision under the store lock;
# the rest are put to the person undecided.
MAX_IDENTITY_TOKENS = 16
# The most characters of a PS's self-asserted `name` the confirmation page shows.
MAX_NAME = 64

# The methods each resource answers. HEAD is GET without the content (RFC 9110 9.3.2), for
# the resources a GET reads without a signature. Method names are case-sensitive (RFC 9110
# 9.1), so `post` is no POST: like any method no resource answers, it is not implemented.
_READ = ("GET", "HEAD")
_IMPLEMENTED = ("GET", "HEAD", "POST", "DELETE")
_METHODS = {"/.well-known/aauth-supervisor.json": _READ, "/.well-known/jwks.json": _READ,
            "/health": _READ, "/interaction": ("GET", "HEAD", "POST"), "/connect": ("POST",),
            "/mission": ("POST",), "/decision": ("POST",), "/event": ("POST",)}


def _methods(path: str) -> tuple[str, ...] | None:
    """The methods the resource at `path` answers; None for no resource."""
    if path in _METHODS:
        return _METHODS[path]
    if path.startswith("/mission/"):
        return ("POST",)
    if path.startswith("/pending/"):
        return ("GET", "POST", "DELETE")
    return None


@dataclass
class TrustedPS:
    auto_connect: bool = False
    tenants: list[str] = field(default_factory=list)


# The server settings that are seconds (`ServerConfig.__post_init__` bounds them).
_SECONDS = ("signature_window", "transit_allowance", "clarification_timeout")
MAX_CONFIG_SECONDS = 86_400


@dataclass
class ServerConfig:
    issuer: str
    name: str = "AAuth APC Supervisor"
    trusted_ps: dict[str, TrustedPS] = field(default_factory=dict)
    open_registration: bool = False  # accept unknown PSes, with person interaction at connect
    signature_window: int = 60
    # The longest the fastest of a PS's signed requests for a person may take from its
    # signature to this SS: what its clock's lead read from them may fall short by.
    transit_allowance: int = 2
    rate_limit_per_minute: int = 0
    clarification_rounds: int = 3
    clarification_timeout: int = 120
    admin_token: str = ""  # confirms connect interactions on the dev interaction page
    documentation_uri: str = ""

    def __post_init__(self) -> None:
        # Supervision L165: endpoint URLs MUST be HTTPS on the issuer's origin. Every
        # endpoint is built from `issuer`, so an HTTPS origin here is what guarantees it.
        # L157: the issuer conforms to the server identifier rules (a lowercase https host,
        # no port, path or trailing slash). It is also the `id` every signed answer names,
        # which the PS compares with the SS it registered (L342).
        if not SERVER_ID.fullmatch(self.issuer):
            raise ValueError(f"issuer must be an https URL that is a server identifier "
                             f"(lowercase host, no port, path, userinfo, query or fragment): "
                             f"{self.issuer!r}")
        # A PS signs with its `issuer` as `id` (Protocol L2187), so it is named by one.
        for ps in self.trusted_ps:
            if not SERVER_ID.fullmatch(ps):
                raise ValueError(f"trusted_ps: {ps!r} is not a server identifier")
        # Protocol L1994: `documentation_uri` "MUST use `https`" (it is published as is).
        if self.documentation_uri and not _https_url(self.documentation_uri):
            raise ValueError(f"documentation_uri must be an https URL: "
                             f"{self.documentation_uri!r}")
        # Seconds added to the clock: past a day is no window an operator means, and past
        # the float range every request that reads it would fail.
        for k in _SECONDS:
            if getattr(self, k) > MAX_CONFIG_SECONDS:
                raise ValueError(f"server config: {k} must be at most {MAX_CONFIG_SECONDS}")

    @property
    def authority(self) -> str:
        return (urlsplit(self.issuer).netloc or "").lower()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ServerConfig:
        """Build a config from its JSON form; a misspelt or mistyped member is an error,
        never silently ignored."""
        types: dict[str, type | tuple[type, ...]] = {
            "issuer": str, "name": str, "trusted_ps": dict, "open_registration": bool,
            "signature_window": int, "transit_allowance": int,
            "rate_limit_per_minute": int, "clarification_rounds": int,
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
_ID_MEMBERS = frozenset({"sdi", "id", "sub", "agent", "mission_s256", "tenant", "jti",
                         "s256", "agent_iss", "agent_sub"})
# Agent and PS text the SS keeps, bounded by the size it is kept at (`_kept_len`).
_TEXT_MEMBERS = frozenset({"description", "reason"})
_STR_MEMBERS = frozenset({
    "sdi", "id", "sub", "agent", "mission_s256", "action", "act", "event", "tenant",
    "resource", "resource_token", "presented_token", "agent_token", "upstream_token",
    "subagent_token", "justification", "description", "summary", "answer", "apply",
    "reason", "s256", "mission", "jti", "scope", "issuer", "iss", "agent_iss", "agent_sub",
    "token_type", "type", "url", "recommendation", "supervisor", "r3_proposal",
    "clarification_response"})
# I-JSON (RFC 7493 Section 2.2): the integers every JSON parser holds exactly. A time past
# them is no time, and one past the float range would fail where the SS compares it.
MAX_JSON_INT = 2 ** 53 - 1
# Times: any finite JSON number. `iat` is "seconds since the epoch" (Supervision L198), with
# no more said: a fraction or an exponent is seconds too, read as the whole second it falls
# in (`_iat`). The issued token's `exp`, copied from a JWT, is a NumericDate, which may
# have a fraction (RFC 7519 Section 2).
_TIME_MEMBERS = frozenset({"iat", "exp"})
_OBJ_MEMBERS = frozenset({"parameters", "proposed"})
_LIST_MEMBERS = frozenset({"tools", "resources", "transcript"})


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object whose member names are unique. The SS evaluates one value of a member;
    a reader of the signed exchange whose parser kept another would read a different act
    (RFC 8259 Section 4: names SHOULD be unique; I-JSON requires it)."""
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateMember(repr(k))
        out[k] = v
    return out


class _DuplicateMember(ValueError):
    pass


MAX_JSON_DEPTH = 64  # far deeper than any AAuth member; bounds what a record can hold


def _values(v: Any) -> int:
    """The number of JSON values in a parsed value, itself included."""
    n, stack = 0, [v]
    while stack:
        x = stack.pop()
        n += 1
        if isinstance(x, dict):
            stack += x.values()
        elif isinstance(x, list):
            stack += x
    return n


def _too_deep(v: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    """Whether a parsed JSON value nests deeper than `limit`. Kept in a record, a deeper
    value would make every later snapshot write fail (the copy recurses), so one request
    could put the SS out of service for every PS."""
    stack = [(v, 1)]
    while stack:
        x, d = stack.pop()
        if d > limit:
            return True
        if isinstance(x, dict):
            stack += [(y, d + 1) for y in x.values()]
        elif isinstance(x, list):
            stack += [(y, d + 1) for y in x]
    return False


def _check_member_types(b: dict[str, Any]) -> None:
    for k, v in b.items():
        if v is None:
            continue  # absent in effect; `_require` refuses it where the member is REQUIRED
        if k in _STR_MEMBERS:
            ok = isinstance(v, str)
        elif k in _TIME_MEMBERS:
            ok = _is_time(v) and abs(v) <= MAX_JSON_INT
        elif k in _OBJ_MEMBERS:
            ok = isinstance(v, dict)
        elif k in _LIST_MEMBERS:
            ok = isinstance(v, list) and len(v) <= MAX_LIST
        elif k == "aud":  # a JWT audience: a string or an array of strings
            ok = isinstance(v, str) or (isinstance(v, list) and len(v) <= MAX_AUD
                                        and all(isinstance(x, str) for x in v))
        else:
            continue
        if not ok:
            if k in _TIME_MEMBERS and isinstance(v, int | float) and not isinstance(v, bool):
                # A number, but no time: NaN or an infinity (Python's reader takes them,
                # and reads 1e400 as one), or past what every JSON parser holds exactly.
                raise invalid_request(f"member {k!r} must be a finite JSON number of at most "
                                      f"2**53 - 1 either way")
            raise invalid_request(f"member {k!r} has the wrong JSON type")
        if k in _ID_MEMBERS and len(v) > MAX_ID_LEN:
            raise invalid_request(f"member {k!r} is longer than {MAX_ID_LEN} characters")
        if k in _TEXT_MEMBERS and _kept_len(v) > MAX_DESCRIPTION:
            raise invalid_request(f"{k} is longer than {MAX_DESCRIPTION} bytes as kept")


def _kept_len(v: Any) -> int:
    """The size a value is kept and answered at: as JSON, every character past ASCII
    escaped (one outside the Basic Multilingual Plane is two escapes, 12 bytes)."""
    return len(json.dumps(v))


def _tool_name(value: Any, what: str) -> str:
    """A tool name, which rules, `ask_tools` and the mission's tools match as written and
    the person is shown: one with a character the person cannot see, or edge whitespace,
    would be decided as another name than the one the person reads."""
    if not isinstance(value, str) or not value or md.hides(value) \
            or len(value) > MAX_TOOL_NAME:
        raise invalid_request(f"{what} must be a name of at most {MAX_TOOL_NAME} characters "
                              f"with no character the person cannot see and no leading or "
                              f"trailing whitespace")
    return value


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


def _https_url(s: str) -> bool:
    """An https URL as it is published: ASCII with no whitespace or control character (RFC
    3986 has none), a host, no user information, and a port in range."""
    if not s.isascii() or any(c.isspace() or not c.isprintable() for c in s):
        return False
    try:
        parts = urlsplit(s)
        parts.port  # noqa: B018 - raises for a port out of range or not a number
    except ValueError:  # an unbalanced bracket, for one
        return False
    return parts.scheme == "https" and bool(parts.hostname) and "@" not in parts.netloc


def _loopback_origin(authority: str) -> str | None:
    """The confirmation page's own origin when it is opened on the listener itself, at a
    loopback address or `localhost` (`http://<authority>`); None for any other authority.
    A name that merely resolves to loopback (DNS rebinding) is not one."""
    try:
        host = urlsplit(f"//{authority}").hostname or ""
        loop = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return None
    return f"http://{authority}" if loop else None


def _approval_key(iss: str, sdi: str, resource: str) -> str:
    """The key of the record of an approval's person token for `resource`: three parts,
    so no sdi a PS mints (a two-part key, `Store.k` escaping `|`) can name it."""
    return Store.k(iss, sdi, resource)


# The detail of a person token booked in its mission at approval (`_approved_tokens`):
# what marks it, as no sdi a PS sends can.
APPROVAL_DETAIL = "uncertain: issued at approval, " + PERSON_TOKEN


def _decided(d: Decision) -> Decision:
    """A decision the PS can act on: `allow`, `deny` or `ask` (Supervision L262). A
    pluggable policy that answers anything else (`clarify` once the rounds are spent, or a
    value the protocol does not define) puts the act to the person."""
    if d.decision not in ("allow", "deny", "ask"):
        d.decision = "ask"
        d.summary = d.summary or "The supervisor's policy did not decide this act."
    return d


MAX_BUDGET = MAX_AMOUNT  # Budgets, Range Limits: at most 15 digits


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
    except RecursionError as e:  # a string, so the body's depth check never saw inside it
        raise invalid_request("forwarded token payload nests too deep") from e
    if not isinstance(claims, dict):
        raise invalid_request("forwarded token payload is not an object")
    return claims


def _act_mission(b: dict[str, Any]) -> str:
    """The mission an act belongs to: the request's `mission_s256` (Supervision L201), or,
    when it names none, the one the forwarded tokens carry. An intermediary in a call
    chain sends no mission of its own (Protocol L842): its upstream token carries it, and
    a resource token copies it unchanged (L755). A request whose tokens name another
    mission, or two, is refused: the act would be judged in the wrong history."""
    carried: set[str] = set()
    for member in ("resource_token", "upstream_token"):
        if member in b:
            try:
                claims = _decode_jwt_claims(b[member])
            except ProtocolError:
                if member == "resource_token":
                    raise
                continue  # one that does not decode is the PS's to refuse (L842): no mission
            m = claims.get("mission_s256")
            if m is not None and not isinstance(m, str):
                raise invalid_request(f"{member} mission_s256 is not a string")
            if m:
                carried.add(m)
    named = b.get("mission_s256") or ""
    if len(carried) > 1 or (named and carried and named not in carried):
        raise invalid_request("mission_s256 is not the mission the forwarded tokens carry")
    return named or next(iter(carried), "")


def _require_typ(token: str, typ: str) -> None:
    """Protocol L2896: "MUST check `typ` before acting on any AAuth JWT". A media type
    compared as RFC 7515 Section 4.1.9 has it: case-insensitive, `application/` implied
    when the value has no `/`."""
    try:
        header = json.loads(b64u_decode(token.split(".")[0]))
    except (ValueError, RecursionError):
        header = None
    got = header.get("typ") if isinstance(header, dict) else None
    got = got.lower() if isinstance(got, str) else ""
    if (got if "/" in got else "application/" + got) != "application/" + typ:
        raise invalid_request(f"forwarded token is not a {typ} (typ {got or 'absent'})")


def _scope(scope: str) -> str:
    """A space-separated scope, of at most `MAX_LIST` tokens: each is matched against the
    rules under the store lock."""
    if len(scope.split()) > MAX_LIST:
        raise invalid_request(f"scope names more than {MAX_LIST} tokens")
    return scope


def _operations(proposal: dict[str, Any]) -> list[str]:
    ops: list[str] = []
    raw = proposal.get("operations")
    if not isinstance(raw, list):
        return ops
    if len(raw) > MAX_LIST:  # each is matched against the rules under the store lock
        raise invalid_request(f"the proposal names more than {MAX_LIST} operations")
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
        self._no_write = False  # set under the store lock by `_unchanged`
        self._dirty = False  # set under the store lock by `_changed`

    # ================================================================ dispatch

    def handle(self, req: HttpRequest) -> Response:
        try:
            return self._route(req)
        except ProtocolError as e:
            return e.to_response()
        except Exception:  # defensive: an unexpected failure never leaks its detail
            # to the caller; the operator gets the traceback.
            LOG.exception("unexpected failure answering %s %r", req.method, req.path)
            return server_error().to_response()

    def _route(self, req: HttpRequest) -> Response:
        m, p = req.method, req.path.rstrip("/") or "/"
        if m not in _IMPLEMENTED:
            # RFC 9110 9.1: a method the server does not implement SHOULD be a 501, as the
            # listener answers one (an error past the table is `server_error`, L639).
            return json_response(501, {"error": "server_error",
                                       "detail": "method not implemented"},
                                 {"Content-Type": "application/problem+json"})
        allowed = _methods(p)
        if allowed is None:
            # Not a Supervision request: HTTP's 404 (RFC 9457 body), with no AAuth `error`,
            # since the table pairs `invalid_request` with 400 (Supervision L631).
            return json_response(404, {"type": "about:blank", "title": "Not Found",
                                       "status": 404},
                                 {"Content-Type": "application/problem+json"})
        if m not in allowed:
            # RFC 9110 15.5.6: a 405 names the methods the resource supports. In the Error
            # Response Format (L627), whose `error` is REQUIRED.
            return json_response(405, {"error": "invalid_request", "type": "about:blank",
                                       "title": "Method Not Allowed", "status": 405},
                                 {"Content-Type": "application/problem+json",
                                  "Allow": ", ".join(allowed)})
        if m == "HEAD":  # RFC 9110 9.3.2: GET without the content, which the listener drops
            m, req = "GET", dataclasses.replace(req, method="GET")
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
            raise invalid_request(f"request not addressed to this SS ({self.cfg.authority})")
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
        return self._with_signer(req, lambda r, s, b: self._pending(r, s, b, p.split("/")[2]),
                                 body_required=(m == "POST"))

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
        # A query is a component the SS requires, so it is required through the profile:
        # uncovered, it is `invalid_input` naming it, and a label that covers it is used.
        required = BASE_COMPONENTS + (BODY_COMPONENTS if req.body else []) + (
            ["@query"] if req.query else [])
        signer = verify_request(req, self.resolver, required=required,
                                window=self.cfg.signature_window, now=self.clock(),
                                admit=self._admit)
        self._throttle(signer.id, poll=req.method == "GET")
        # Equivalent mutant: `{}` -> `None` is unobservable, the bodiless GET and DELETE
        # /pending/ handlers never read their body (docs/mutation-testing.md).
        body: dict[str, Any] = {}  # pragma: no mutate
        if req.body:
            ctype = (req.header("content-type") or "").partition(";")[0].strip().lower()
            if ctype != "application/json":
                raise invalid_request("body must be application/json")
            # JSON between systems is UTF-8 with no byte order mark (RFC 8259 Section 8.1):
            # bytes another reader would refuse are not read here as another encoding.
            try:
                if req.body.startswith(b"\xef\xbb\xbf"):
                    raise UnicodeError("byte order mark")
                text = req.body.decode("utf-8")
            except UnicodeError as e:
                raise invalid_request("body must be UTF-8 JSON with no byte order mark") from e
            try:
                parsed = json.loads(text, object_pairs_hook=_unique_members)
            except _DuplicateMember as e:
                raise invalid_request(f"body names a member twice: {e}") from e
            except RecursionError as e:
                raise invalid_request(f"body nests deeper than {MAX_JSON_DEPTH} levels") from e
            except ValueError as e:
                raise invalid_request("body is not JSON") from e
            if not isinstance(parsed, dict):
                raise invalid_request("body is not a JSON object")
            if _too_deep(parsed):
                raise invalid_request(f"body nests deeper than {MAX_JSON_DEPTH} levels")
            _check_member_types(parsed)
            body = parsed
        elif body_required:  # only POST routes require a body (GET/DELETE /pending/ do not)
            raise invalid_request("missing body")
        with self.store.lock:
            # Writing the snapshot serializes the whole state, so an answer that changed
            # nothing (`_unchanged`) does not write it, nor does a refusal, unless it
            # follows a change (`_changed`: a question past its deadline is settled, then
            # answered `expired`). After a write that failed, every request writes: a
            # retry answered from memory would otherwise leave the change off disk.
            self._no_write = self._dirty = False
            # How far ahead of the SS's clock this PS's clocks run, as its stamp and its
            # signature show: where its acts took place against a token's end
            # (`Store.observe_lead`). A connection this request makes takes it too. A
            # stamp past the signature window says nothing a PS within it would.
            named = body.get("sub")
            sub = named if isinstance(named, str) else ""
            # The stamp as every act is read by it: its whole second (`_iat`).
            iat = math.floor(body["iat"]) if _is_time(body.get("iat")) else 0
            stamp = iat if iat <= signer.received + self.cfg.signature_window else 0
            lead = max(signer.created, stamp) - signer.received
            led = self.store.observe_lead(signer.id, sub, lead)
            try:
                resp = fn(req, signer, body)
            except ProtocolError:
                if self._dirty or led or self.store.unsaved:
                    self.store.save()
                raise
            except Exception:
                # Answered 500 (`handle`): whatever the request changed before it failed (a
                # handler may change state before the step that fails, and the lead it
                # noted), the next request writes.
                self.store.unsaved = True
                raise
            led = self.store.observe_lead(signer.id, sub, lead) or led
            if not self._no_write or led or self.store.unsaved:
                self.store.save()
        if resp.status == 200 and resp.body and "Signature" not in resp.headers:
            resp = self._sign(req, resp)  # connect answers too: one rule for the PS to check
        return resp

    def _unchanged(self, resp: Response) -> Response:
        """An answer that changed no state: the snapshot is not written for it."""
        self._no_write = True
        return resp

    def _changed(self) -> None:
        """State changed before a refusal: the snapshot is written all the same."""
        self._dirty = True

    def _admit(self, signer_id: str) -> None:
        """A PS this SS does not accept is refused before its keys are looked up, so an
        invented signer costs no fetch and no cache entry (Signature-Key -09 L2379). A PS
        signs with its `issuer` as `id` (Protocol L2187), a server identifier (L1948-L1969):
        any other `id` is no PS's, under open registration too."""
        if not SERVER_ID.fullmatch(signer_id):
            raise SignatureError("invalid_key", "Signature-Key id is not a server identifier")
        if signer_id not in self.cfg.trusted_ps and not self.cfg.open_registration:
            raise unsupported_iss(f"{signer_id} is not a PS this SS accepts")

    def _throttle(self, iss: str, poll: bool = False) -> None:
        limit = self.cfg.rate_limit_per_minute
        if limit <= 0:
            return
        now = self.clock()
        with self._rate_lock:
            q = [t for t in self._rate.get(iss, []) if now - t < 60]
            if len(q) >= limit:
                wait = max(1, int(60 - (now - q[0])))
                if poll:
                    # Supervision L639: "Polling a pending URL uses the polling error codes
                    # of the AAuth Protocol": `slow_down` (429, Protocol L2626).
                    raise ProtocolError(429, "slow_down", "polling too frequently",
                                        {"Retry-After": str(wait)})
                raise rate_limited(wait)
            q.append(now)
            self._rate[iss] = q
            if len(self._rate) > MAX_RATE_ROWS:
                # A signer with no request in the last minute has nothing left to count.
                self._rate = {k: v for k, v in self._rate.items() if now - v[-1] < 60}

    def _require(self, body: dict[str, Any], *names: str) -> None:
        missing = [n for n in names if n not in body or body[n] in (None, "")]
        if missing:
            raise invalid_request(f"missing member(s): {', '.join(missing)}")
        # Member types (iat a finite number, not a boolean) are checked once for every body
        # by _check_member_types before any handler runs, so they are not re-checked here.

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

    def _mission(self, signer: VerifiedSigner, s256: str, sub: str) -> Mission:
        """The mission, as a mission of the person the request names: `(iss, sub)` is one
        person (L199), and another person's mission is no mission of theirs."""
        m = self.store.missions.get(Store.k(signer.id, s256))
        if m is None or m.sub != sub:
            raise unknown_mission(f"no record of mission {s256}")
        return m

    # ================================================================ signing

    def _sign(self, req: HttpRequest, resp: Response) -> Response:
        if not self.key:
            return resp
        resp.headers["Content-Digest"] = content_digest(resp.body)
        # Supervision L340: MUST cover @status, content-type, content-digest; SHOULD cover the
        # request's content-digest, @authority and @path as `;req` components.
        base = ["@status", "content-type", "content-digest"] + (
            ["content-digest;req"] if req.body else []) + ["@authority;req", "@path;req"]
        extra: list[str] = []
        accept = req.header("accept-signature")
        label = "sig"
        if accept:
            try:
                d = parse_dictionary(accept)
                label, member = next(iter(d.items()))
                if isinstance(member, InnerList):
                    for it in member.items:
                        n = str(it.value) + (";req" if it.params.get("req") else "")
                        if n not in base and n not in extra:
                            extra.append(n)
            except (SFVError, StopIteration):
                pass
        # A component the request lacks (content-digest on a bodiless poll) cannot be
        # covered; drop that one, keep the rest of what the PS asked for.
        extra = [n for n in extra if not (n.endswith(";req") and not n.startswith("@")
                                          and req.header(n.split(";")[0]) is None)]
        hr = HttpResponse(resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.body)
        # The issuer is a server identifier, with nothing to escape; the kid is escaped.
        sk = (f'{label}=jwks_uri;id="{self.cfg.issuer}";dwk="aauth-supervisor.json";'
              f'kid={ser_bare(self.key.kid)}')
        try:
            h = sign_message(base + extra, self.key, sk, req, hr, label=label,
                             created=int(self.clock()))
        except SignatureError:
            # RFC 9421 Section 5.2: a requested component that does not apply fails that
            # request; the answer is still signed (L320), over what L340 asks for, so the
            # binding to the request is kept.
            h = sign_message(base, self.key, sk, req, hr, label=label, created=int(self.clock()))
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
                return self._unchanged(stored)
        assert rec.response is not None
        resp = self._replay(req, rec.response)
        if rec.signed is not None:
            return self._unchanged(resp)
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
        if b["action"] not in ("connect", "disconnect"):
            raise invalid_request("action must be connect or disconnect")
        # A connect or disconnect is acted on once per (iss, id): a retried or captured copy
        # reports the current state and changes nothing (no undoing a later disconnect).
        # The id names its action: under the other one it is no retry, and is refused. An
        # id kept without its action (an earlier version's snapshot) is a retry of either.
        other = "disconnect" if b["action"] == "connect" else "connect"
        if Store.k("connect", s.id, str(b["id"]), other) in self.store.events_seen:
            raise invalid_request(f"id was used for a {other}")
        once = Store.k("connect", s.id, str(b["id"]), b["action"])
        if once in self.store.events_seen or (
                Store.k("connect", s.id, str(b["id"])) in self.store.events_seen):
            if key in self.store.connections:
                return self._unchanged(json_response(200, {"status": "connected"}))
            for p in self.store.pendings_of(s.id, b["sub"]):
                if self._awaiting(p):
                    return self._unchanged(self._connect_pending(p))
            return self._unchanged(json_response(200, {"status": "disconnected"}))
        trust = self.cfg.trusted_ps.get(s.id)
        # A trusted PS's id is kept for good. A signer only open registration admits keeps
        # one only with a record it opens (below), removed with it, so nothing else it
        # sends grows the state.
        if trust is not None:
            self.store.events_seen.add(once)
        if b["action"] == "disconnect":
            changed = self.store.connections.pop(key, None) is not None
            # What was open for the pair ends with it (L249): a clarification is
            # abandoned, and a connect awaiting the person's confirmation (or one already
            # confirmed) can no longer be confirmed or report a connection.
            for p in self.store.pendings_of(s.id, b["sub"]):
                if p.cancelled:
                    continue
                if p.kind == "connect":
                    p.cancelled = changed = True
                    self.store.settle(p)
                elif p.resolved is None:
                    p.cancelled = changed = True
                    self.store.settle(p)
                    rec = self.store.decisions.get(Store.k(s.id, p.sdi))
                    if rec is not None:
                        rec.decision = "abandoned"
            resp = json_response(200, {"status": "disconnected"})
            return resp if changed or trust is not None else self._unchanged(resp)
        if key in self.store.connections:
            resp = json_response(200, {"status": "connected"})
            return resp if trust is not None else self._unchanged(resp)
        tenant = b.get("tenant")
        if trust and (trust.auto_connect or (tenant and tenant in trust.tenants)):
            self.store.connections[key] = {"iss": s.id, "sub": b["sub"], "tenant": tenant,
                                           "at": int(self.clock())}
            return json_response(200, {"status": "connected"})
        # The person confirms the pairing at the SS.
        for p in self.store.pendings_of(s.id, b["sub"]):
            if self._awaiting(p):
                resp = self._connect_pending(p)
                return resp if trust is not None else self._unchanged(resp)
        now = self.clock()
        if trust is None:
            self._room_for_unconfirmed(s.id, now)
            self.store.events_seen.add(once)
        code = "".join(secrets.choice(CROCKFORD) for _ in range(10))
        # Only what the confirmation needs: the page shows the PS's name (plain and cut,
        # as the page shows it), and confirming records the tenant. Kept until confirmed,
        # so nothing else of the body is kept.
        p = Pending(secrets.token_urlsafe(16), s.id, "", "connect",
                    {"tenant": b.get("tenant"),
                     "_ps_name": md.plain(self._ps_name(s.id), MAX_NAME)},
                    code=code, sub=b["sub"], deadline=now + CONNECT_LIFETIME, once=once)
        self.store.add_pending(p)
        return self._connect_pending(p)

    def _awaiting(self, p: Pending) -> bool:
        """A connect still awaiting the person: not confirmed, withdrawn or expired."""
        return p.kind == "connect" and not p.resolved and not p.cancelled and not (
            p.deadline and self.clock() >= p.deadline)

    def _room_for_unconfirmed(self, iss: str, now: float) -> None:
        """Room for one more connect record of a signer the SS does not trust: records of
        such signers past twice their lifetime are removed, and the signer may hold
        `MAX_UNCONFIRMED_PER_PS`. All of them together hold at most `MAX_UNCONFIRMED`: at
        that cap the oldest record of the domain (`signer_domain`) holding the most makes
        room, so that no group of names keeps every other signer out, and a signer of a
        domain holding as many as any is refused. A refusal is `rate_limited` (Supervision
        L637) until the oldest record it waits for is removed."""
        def held_until(p: Pending) -> float:
            return p.deadline + CONNECT_LIFETIME

        trusted = self.cfg.trusted_ps
        records = [p for p in self.store.pending.values()
                   if p.kind == "connect" and p.iss not in trusted]
        gone = [p.id for p in records if now >= held_until(p)]
        if gone:
            self.store.drop_pendings(gone)
            self._changed()
        # A connect the person answered is theirs, not the signer's: it counts no more. One
        # failed on wrong operator tokens still counts until its record goes, or failing
        # its own connects would let a signer open new ones, and guess, without end.
        held = [p for p in records if now < held_until(p)
                and (not p.resolved or p.failures >= MAX_OPERATOR_FAILURES)]
        own = [p for p in held if p.iss == iss]
        if len(own) >= MAX_UNCONFIRMED_PER_PS:
            raise rate_limited(max(1, math.ceil(min(map(held_until, own)) - now)))
        if len(held) < MAX_UNCONFIRMED:
            return
        domain = signer_domain(iss)
        mine = sum(1 for p in held if signer_domain(p.iss) == domain)
        top, most = collections.Counter(signer_domain(p.iss) for p in held).most_common(1)[0]
        if most <= mine:
            raise rate_limited(max(1, math.ceil(min(map(held_until, held)) - now)))
        self.store.drop_pendings([min((p for p in held if signer_domain(p.iss) == top),
                                      key=held_until).id])

    def _ps_name(self, iss: str) -> str:
        """The PS's display `name` from its metadata, for the confirmation page (L655).

        Read from the metadata the resolver fetched to verify this very request, so a
        connect never makes a network call while holding the store lock.
        """
        cached = getattr(self.resolver, "cached_metadata", None)
        meta = cached(iss, "aauth-person.json") if callable(cached) else None
        name = meta.get("name") if isinstance(meta, dict) else None
        return name if isinstance(name, str) else ""

    def _live_connect(self, code: str) -> Pending | None:
        """The connect awaiting confirmation under this interaction code, if any. A code
        whose connect has expired fails with `expired` (Protocol L2400)."""
        p = self.store.pending_by_code(code)
        if p is None or p.resolved or p.cancelled:
            return None
        if not self._awaiting(p):
            raise ProtocolError(408, "expired", "the code has expired")
        return p

    def _connect_pending(self, p: Pending) -> Response:
        url = self.cfg.issuer.rstrip("/") + "/interaction"
        return json_response(202, {"status": "interacting" if p.arrived else "pending"}, {
            "AAuth-Requirement": f'requirement=interaction; url="{url}"; code="{p.code}"',
            "Location": f"/pending/{p.id}", "Retry-After": "5", "Cache-Control": "no-store"})

    def _interaction(self, req: HttpRequest) -> Response:
        """Development interaction page: an operator confirms a pending connect."""
        if req.method == "GET":
            code = (parse_qs(req.query).get("code") or [""])[0]
            with self.store.lock:  # signed requests change `pending` on other threads
                p = self._live_connect(code)
                if p is not None and not p.arrived:
                    p.arrived = True  # the person is at the page (Protocol L2523)
                    self.store.save()
            if p is None:
                # Protocol L2396: a used code is rejected "with `invalid_code`"; L2625:
                # "Interaction code not recognized or already consumed", 410.
                raise ProtocolError(410, "invalid_code", "unknown or used code")
            # The name is the PS's own (its metadata): plain, cut, and after the code.
            name = md.plain(str(p.request.get("_ps_name") or ""), MAX_NAME)
            name = name or "(no name in its metadata)"
            page = (f"<!doctype html><meta charset=utf-8><title>Confirm person server</title>"
                    f"<h1>Confirm person server</h1><p>Code: <b>{html.escape(p.code)}</b></p>"
                    f"<p>Person server: <b>{html.escape(p.iss)}</b></p>"
                    f"<p>Name: <b>{html.escape(name)}</b></p><p>Confirm only if you started "
                    f"this connection and the code matches the one your person server shows."
                    f"</p><form method=post>"
                    f"<input type=hidden name=code value='{html.escape(p.code)}'>"
                    f"<label>Operator token <input type=password name=admin_token></label> "
                    f"<button>Confirm</button></form>")
            return Response(200, {"Content-Type": "text/html; charset=utf-8",
                                  "Cache-Control": "no-store",
                                  "X-Frame-Options": "DENY",
                                  "Content-Security-Policy": "frame-ancestors 'none'"}, page.encode())
        else:  # POST: `_route` admits no other method here
            origin, site = req.header("origin"), req.header("sec-fetch-site")
            if (origin is not None and origin not in (self.cfg.issuer,
                                                      _loopback_origin(req.authority))) or (
                    site is not None and site not in ("same-origin", "none")):
                # A form post a browser sends from another site (any page the operator
                # opened) is refused before it counts against a connect below.
                return Response(403, {"Content-Type": "text/plain"},
                                b"Refused: a form post from another site.\n")
            form = parse_qs(req.body.decode(errors="replace"))
            code = (form.get("code") or [""])[0]
            token = (form.get("admin_token") or [""])[0]
            given, expected = (s.encode("utf-8", "surrogatepass") for s in (token, self.cfg.admin_token))
            with self.store.lock:  # the check, the count and the connect are one step
                p = self._live_connect(code)
                if p is None:
                    raise ProtocolError(410, "invalid_code", "unknown or used code")  # L2396
                if not self.cfg.admin_token or not hmac.compare_digest(given, expected):
                    # A wrong token counts against this connect only, so guessing the token
                    # costs a live code every few tries, and no one can stop the operator
                    # confirming the others. After a few, the connect fails for good and its
                    # code is `invalid_code` (Protocol L2398); the PS is told `denied`. The
                    # count is saved by the next write: a wrong token alone writes nothing.
                    p.failures += 1
                    if p.failures >= MAX_OPERATOR_FAILURES:
                        p.resolved = StoredResponse(
                            403, {"Content-Type": "application/problem+json"},
                            '{"error":"denied","detail":"the connection was not confirmed"}')
                        self.store.save()
                    return Response(403, {"Content-Type": "text/plain"}, b"Not authorized.\n")
                self.store.connections[Store.k(p.iss, p.sub)] = {
                    "iss": p.iss, "sub": p.sub, "tenant": p.request.get("tenant"),
                    "at": int(self.clock())}
                p.resolved = StoredResponse(200, {"Content-Type": "application/json"},
                                            '{"status":"connected"}')
                self.store.save()
            return Response(200, {"Content-Type": "text/plain"}, b"Connected.\n")

    # ================================================================ missions

    def _mission_proposal(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any]
                          ) -> Response:
        self._require(b, "sdi", "iat", "sub", "agent", "agent_token", "description")
        for name in ("resources", "tools"):
            if name in b and not isinstance(b[name], list):
                raise ProtocolError(400, "invalid_request", f"{name} must be an array")
        # Approved resources are matched against policy patterns as exact strings, as the
        # decision endpoint's are (`_server_identifier`): `https://EXFIL.example` would
        # otherwise pass a deny written for `https://exfil.example`.
        for r in b.get("resources", []):
            _server_identifier(r, "resources entry")
        for t in b.get("tools", []):
            if isinstance(t, dict) and "name" in t:
                _tool_name(t["name"], "tool name")
        if _kept_len(b.get("tools", [])) > MAX_TOOLS:
            raise invalid_request(f"tools are longer than {MAX_TOOLS} bytes as kept")
        if _values(b.get("tools", [])) > MAX_TOOLS_VALUES:
            raise invalid_request(f"tools hold more than {MAX_TOOLS_VALUES} values")
        self._connected(s, b["sub"])
        prior = self._prior(req, s, b)
        if prior and prior.response:
            return self._replay_record(req, prior)
        d = self._approval_person_tokens(s, b, _decided(self.policy.decide_proposal(
            b, self.clock())))
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.decision == "allow":
            # The approved mission's members (L397), under the answer's own `sdi` and
            # `decision`; `description` is REQUIRED (L415): the proposal's, unless the
            # policy refined it.
            body = {**d.narrow, **body}
            if not isinstance(body.get("description"), str):
                body["description"] = b["description"]
        elif d.decision == "ask":
            body["summary"] = d.summary
            if d.narrow.get("proposed"):
                body["proposed"] = d.narrow["proposed"]
            # No reach is kept for a proposal, so the one the SS applies is named: with
            # none, the PS may offer `mission` and `always` (L599).
            body["apply_options"] = [{"value": "once", "label": "This proposal only"}]
        elif d.reason:
            body["reason"] = d.reason
        return self._terminal(req, s, b, "mission_proposal", d, body)

    def _approval_person_tokens(self, s: VerifiedSigner, b: dict[str, Any],
                                d: Decision) -> Decision:
        """Supervision L417, L420: the PS issues a person token at approval for each
        approved resource (Protocol L1415), whoever approved: so on an `allow`, and on an
        `ask`, whose refinement the person may approve. Where the resource serves on it
        alone (Person Identity Access), that token is an act, decided as a `person_token`
        decision would be. They are issued together, so each is decided with those before
        it it allows counting as open; and only `always` answers reach them (the token
        carries the new mission's `s256`: an answer for a mission, or for acts outside
        missions, is about other acts). One the policy would not allow outright is left
        out of the refinement put to the person and named; one it allows is an open act
        until `person_token.issued` reports it."""
        if d.decision == "allow":
            refinement = d.narrow
        elif d.decision == "ask" and isinstance(d.narrow.get("proposed"), dict):
            refinement = d.narrow["proposed"]
        else:
            return d
        approved = [r for r in refinement.get("approved_resources", []) if isinstance(r, str)]
        identity = list(dict.fromkeys(r for r in approved if self.policy.serves_on_identity(r)))
        if not identity:
            return d
        now = self.clock()
        history = self.store.composition_history(s.id, b["sub"], b["agent"], "",
                                                 exclude_sdi=b["sdi"], now=now)
        reach = [r for r in self.store.reach_of(s.id, b["sub"]) if r.value == "always"]
        held: list[tuple[str, Decision]] = []
        for i, r in enumerate(identity):
            if i >= MAX_IDENTITY_TOKENS:
                held.append((r, Decision("ask", summary=f"At most {MAX_IDENTITY_TOKENS} "
                                         "such tokens are decided for one approval.")))
                continue
            pd = self.policy.decide(Act("person_token", s.id, b["sub"], b["agent"],
                                        resource=r, ps_lead=self._lead(s.id, b["sub"])),
                                    None, history,
                                    reach, now, clarify=False)
            if pd.decision != "allow" or pd.entry is None:
                held.append((r, pd))
                continue
            pd.entry.unplaced = True  # where it will stand is not worked out, but
            pd.entry.after_n = self.store.recorded_count() + 1  # never before this answer
            self.store.record_decision(_approval_key(s.id, b["sdi"], r), DecisionRecord(
                b["sdi"], s.id, b["sub"], b["agent"], "person_token", "allow", "", pd.entry,
                pd.kind))
            history = history + [dataclasses.replace(
                pd.entry, sdi=b["sdi"], borrowed=True, token_exp=UNBOUNDED_EXP, open="own",
                detail=f"uncertain: allow not yet settled: {pd.entry.detail}")]
        if not held:
            return d
        names = ", ".join(r for r, _ in held[:MAX_NAMED]) + (
            f" and {len(held) - MAX_NAMED} more" if len(held) > MAX_NAMED else "")
        one = len(held) == 1
        # What the policy says of the act it decided is said here of the token the
        # approval would issue, naming it where several are held (tokens told the same,
        # once); the opening says the resource may serve on it.
        told: dict[str, list[str]] = {}
        for r, pd in held[:MAX_NAMED]:
            told.setdefault((pd.summary or pd.reason).replace(f" {PERSON_TOKEN_TOLD}", ""),
                            []).append(r)

        def of(text: str, rs: list[str]) -> str:
            name = ("that token" if one else f"the token for {rs[0]}" if len(rs) == 1
                    else f"each of the tokens for {', '.join(rs)}")
            return text.replace("not of this one", "not of " + (
                "those tokens" if len(rs) > 1 else name)).replace(
                "This act", name[0].upper() + name[1:]).replace("this act", name)

        why = " ".join(of(text, rs) for text, rs in told.items())
        refined = dict(refinement, approved_resources=[
            r for r in approved if r not in {h for h, _ in held}])
        first = f"{d.summary} " if d.decision == "ask" and d.summary else ""
        return Decision("ask", summary=f"{first}Approving the mission as proposed would have "
                        f"the person server issue a person token for {names}, on which "
                        f"{'that resource' if one else 'each'} may serve requests with no "
                        f"other token. {why} The proposed refinement leaves "
                        f"{'it' if one else 'them'} out.",
                        narrow={"proposed": refined})

    def _approval_tokens(self, s: VerifiedSigner, sub: str, sdi: str) -> list[DecisionRecord]:
        """The approval tokens still open of the proposal decided under `sdi`."""
        out = []
        for k in self.store.open_records(s.id, sub):
            t = self.store.decisions[k]
            if t.act == "person_token" and t.entry is not None and t.sdi == sdi and k in (
                    _approval_key(s.id, sdi, t.entry.resource),
                    Store.k(s.id, sdi, t.entry.resource, t.entry.jti)):
                out.append(t)
        return out

    def _approved_tokens(self, s: VerifiedSigner, b: dict[str, Any], blob: dict[str, Any],
                         s256: str) -> None:
        """The person tokens the PS issued at approval (Supervision L420; Protocol L1415)
        for the resources the mission names, as the person approved them (L417, L422:
        they may have edited the refinement), booked in the mission when it is first
        reported. Each of a resource that serves on it alone is an act of the approval,
        uncertain (what the resource served on it is not seen), usable for at most the
        hour Protocol L863 allows, and not past the mission's `expires_at`: what any
        reported person token is. A report refines it (`_ev_person_token_issued`); a PS
        may decline to issue one (L1415), which no event says, so it is booked all the
        same. Past `MAX_LIST` resources, one for each class: they share one window.

        Where such a token stood among the person's acts is not worked out from when the
        approval or a report arrived (a retry, a routing change, Supervision L619, L621,
        or a clock off can each misplace it): every one is `unplaced`, usable from the
        SS's answer to its proposal on (`after_n`), the earliest it can have been issued.
        Being uncertain, it only ever makes an act be asked."""
        sdi = b["sdi"] if isinstance(b.get("sdi"), str) and b["sdi"] else ""
        at = min(_iat(b), self.clock())  # a time the PS's clock cannot move on
        # The `exp` the PS writes on the token, from its own clock, is what the resource
        # reads: the hour from the approval's stamp, which the signature window bounds. From
        # the stamp as sent, rounded up below: an end is never read as earlier than it is.
        exp = min(float(b["iat"]), self.clock() + self.cfg.signature_window) + \
            PERSON_TOKEN_LIFE
        end = iso_to_epoch(blob.get("expires_at"))
        if end is not None and math.isfinite(end):
            exp = min(exp, end)
        identity = list(dict.fromkeys(
            r for r in blob.get("approved_resources", [])
            if isinstance(r, str) and SERVER_ID.fullmatch(r) and self.policy.serves_on_identity(r)))
        held: list[HistoryEntry] = []  # tokens reported before this report
        prop = self._approved_proposal(s, b, sdi)
        if prop is not None:
            self.store.settle_open(s.id, b["sub"], self.clock())  # as any decision reads it
            prop.mission_s256 = s256  # approved: its tokens are this mission's
            for t in self._approval_tokens(s, b["sub"], prop.sdi):
                if t.decision == "reported" and t.entry is not None:
                    held.append(t.entry)
                t.entry = None  # an act of the mission now, booked below
        hist = self.store.history_for(s.id, b["sub"], b["agent"], s256)
        # Issued at approval, after the SS answered the proposal: never before an act
        # recorded by then (with no proposal named, no such bound is known).
        floor = prop.recorded_n if prop is not None else 0
        # Past the bound, one token for each kind of act: its class and the others it may have.
        kinds: set[tuple[str, ...]] = set()
        for i, r in enumerate(identity):
            c = self.policy.classify(Act("person_token", s.id, b["sub"], b["agent"],
                                         resource=r))
            kind = (c.cls, *sorted(a.cls for a in c.blind))
            if i >= MAX_LIST and kind in kinds:
                continue
            kinds.add(kind)
            entry = HistoryEntry(c.cls, r, c.provenance, at=int(at), detail=APPROVAL_DETAIL,
                                 token_exp=math.ceil(exp), unplaced=True, after_n=floor,
                                 iat=_iat(b), blind=list(c.blind))
            early = next((e for e in held if e.resource == r), None)
            if early is not None:
                held.remove(early)
                entry.jti = early.jti
                entry.token_exp = max(entry.token_exp or 0, early.token_exp or 0)
            self.store.add_history(hist, entry, b["agent"])
        for early in held:  # another token for a resource, or one the blob does not name
            self.store.add_history(hist, early, b["agent"])

    def _approved_proposal(self, s: VerifiedSigner, b: dict[str, Any], sdi: str
                           ) -> DecisionRecord | None:
        """The proposal an `approved` report follows: the one its `sdi` names (L443), of
        this PS, person and agent. With none named, none is guessed: the mission's tokens
        are booked from its blob, and no proposal's records are touched."""
        rec = self.store.decisions.get(Store.k(s.id, sdi)) if sdi else None
        if rec is not None and rec.act == "mission_proposal" and (
                (rec.sub, rec.agent) == (b["sub"], b["agent"])):
            return rec
        return None

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
                return self._unchanged(Response(201))
            if action == "approved":
                self._require(b, "s256", "mission")
                if b["s256"] != s256:
                    raise invalid_request("s256 differs from the mission URL")
                try:
                    raw = b64u_decode(b["mission"])
                    if len(raw) > MAX_MISSION:
                        raise invalid_request(f"mission is longer than {MAX_MISSION} bytes")
                    blob = json.loads(raw)
                except (ValueError, json.JSONDecodeError, RecursionError) as e:
                    raise invalid_request("mission is not base64url JSON") from e
                if _too_deep(blob):
                    raise invalid_request(f"mission nests deeper than {MAX_JSON_DEPTH} levels")
                # Protocol, Mission Approval: the blob is a JSON object, and the members the
                # policy reads are arrays (L1426, L1427). Stored as anything else, a blob
                # would make decisions in the mission server errors, and a member would
                # fail or be misread wherever it is read.
                if not isinstance(blob, dict):
                    raise invalid_request("mission is not a JSON object")
                if _kept_len(blob) > MAX_MISSION:
                    raise invalid_request(f"mission is longer than {MAX_MISSION} bytes as kept")
                if _values(blob) > MAX_MISSION_VALUES:
                    raise invalid_request(f"mission holds more than {MAX_MISSION_VALUES} values")
                for name in ("approved_tools", "approved_resources"):
                    if name in blob and not isinstance(blob[name], list):
                        raise invalid_request(f"mission {name} is not an array")
                if b64u(hashlib.sha256(raw).digest()) != s256:
                    raise invalid_request("s256 is not the digest of mission")
                key = Store.k(s.id, s256)
                if key not in self.store.missions:
                    self.store.add_mission(key, Mission(s256, b["agent"], b["sub"], s.id, blob))
                    self._approved_tokens(s, b, blob, s256)
            else:
                m = self._mission(s, s256, b["sub"])
                m.state, m.reason = "terminated", str(b.get("reason", ""))
            self.store.events_seen.add(ek)
            return Response(201)
        self._require(b, "sdi", "iat", "sub", "agent")
        self._connected(s, b["sub"])
        prior = self._prior(req, s, b)
        if prior and prior.response:
            return self._replay_record(req, prior)
        m = self._mission(s, s256, b["sub"])
        end = iso_to_epoch(m.blob.get("expires_at"))
        if m.state != "active":
            d = Decision("deny", reason="The mission has terminated.")
        elif end is not None and self.clock() >= end:
            # Protocol L1425: a mission past its `expires_at` is treated as terminated on
            # every decision path that acts on it, as the policy does for its acts.
            d = Decision("deny", reason="The mission has expired.")
        elif action == "update":
            self._require(b, "description")
            # The update is the agent's Markdown: the person sees it as written, fenced.
            d = Decision("ask", summary="The agent reports a change to the mission:\n\n"
                         + md.block(str(b["description"]))) \
                if self.policy.ask_on_mission_update else Decision("allow")
            if d.decision == "allow":
                # Kept beside the blob: its members are the PS's (Protocol L1429).
                m.updates.append(b["description"])
        else:
            self._require(b, "summary")
            d = Decision("allow")
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.summary:
            body["summary"] = d.summary
        if d.reason:
            body["reason"] = d.reason
        if d.decision == "ask":  # no reach is kept for an update: the one applied is named
            body["apply_options"] = [{"value": "once", "label": "This change only"}]
        resp = self._terminal(req, s, b, f"mission_{action}", d, body)
        if d.decision == "ask":  # an update put to the person: kept if they allow it
            rec = self.store.decisions[Store.k(s.id, b["sdi"])]
            rec.mission_s256, rec.update = s256, str(b["description"])
        return resp

    # ================================================================ decisions

    def _act_from(self, s: VerifiedSigner, b: dict[str, Any]) -> Act:
        act = Act(b["act"], s.id, b["sub"], b["agent"], _act_mission(b),
                  justification=str(b.get("justification") or ""))
        if act.act == "person_token":
            self._require(b, "resource", "agent_token")
            act.resource = _server_identifier(b["resource"], "resource")
        elif act.act == "permission":
            self._require(b, "action")
            act.tool = _tool_name(b["action"], "action")
            params = b.get("parameters")
            act.parameters = params if isinstance(params, dict) else {}
            act.parameters_provenance = "agent"
            if b.get("description"):
                act.justification = (act.justification + " " + str(b["description"])).strip()
        else:
            self._require(b, "resource_token", "presented_token")
            rt = _decode_jwt_claims(b["resource_token"])
            _require_typ(b["resource_token"], "aa-resource+jwt")
            act.resource = _server_identifier(rt.get("iss"), "resource token iss")
            scope = rt.get("scope")
            if scope is not None and not isinstance(scope, str):
                # A space-separated string (Protocol, scope); any other JSON type would be
                # read as some other scope, or none, and miss the rules written for it.
                raise invalid_request("resource token scope is not a string")
            act.scope = _scope(scope or "")
            _budget_claims(act, rt)
            member = self.policy.r3_member  # None: spec-only, the extension is off
            raw = b.get(member) if member is not None else None
            prop = self._proposal(raw, rt) if member is not None and member in b else None
            # Bytes are the resource's word only against the `r3_s256` it signed into the
            # resource token (R3 L503); without one they are bound to nothing, and unused.
            if prop is not None and (not isinstance(raw, str) or rt.get("r3_s256")):
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
            except RecursionError as e:  # bytes in a string: the body's depth check is blind
                raise invalid_request("R3 proposal nests too deep") from e
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
            pend = self.store.pending_by_sdi(s.id, b["sdi"])
            if pend is not None and self._open_question(pend):
                return self._unchanged(self._clarify_response(pend))
            # A question that is over (withdrawn, abandoned, timed out) answered nothing:
            # the request is decided again, under the same sdi it is bound to.
        return self._evaluate(req, s, b)

    def _open_question(self, p: Pending) -> bool:
        # A question is over once answered (`resolved`), withdrawn, or past its deadline;
        # every way a clarification becomes `gone` is one of these.
        return p.resolved is None and not p.cancelled and not (
            p.deadline and self.clock() >= p.deadline)

    def _open_questions(self, iss: str, sub: str) -> int:
        """The person's open clarifications. One that is over (past its deadline, or
        answered) and still holds its request is settled on the way, so a person's
        expired questions keep no bodies past their next question, whoever asks it."""
        n = 0
        for x in self.store.pendings_of(iss, sub):
            if x.kind != "clarify":
                continue
            if self._open_question(x):
                n += 1
            elif x.request:
                self.store.settle(x)
        return n

    def _evaluate(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any],
                  pending: Pending | None = None, clarify: bool = True) -> Response:
        act = self._act_from(s, b)
        act.ps_lead = self._lead(s.id, act.sub)
        mission = self._mission(s, act.mission_s256, act.sub) if act.mission_s256 else None
        history = self.store.history_for(s.id, act.sub, act.agent, act.mission_s256)
        if act.consumed_jti:
            # Budgets: a record names a token the PS issued; a later record for the same
            # jti supersedes an earlier one, so reconciling is idempotent.
            # The record is in its own token's scale (L459): it applies only to an
            # allocation in that scale, and a token's metered total never decreases, so a
            # stale record arriving last does not roll the figure back.
            for h in history:
                if h.jti == act.consumed_jti and h.resource == act.resource \
                        and h.unit == act.budget_unit:
                    h.consumed = max(h.consumed or 0, act.consumed or 0)
        now = self.clock()
        d = self.policy.decide(act, mission,
                               self.store.composition_history(s.id, act.sub, act.agent,
                                                              act.mission_s256,
                                                              exclude_sdi=b["sdi"], now=now),
                               self.store.reach_of(s.id, act.sub), now, clarify=clarify)
        if d.decision == "clarify":
            rounds = pending.rounds if pending else 0
            room = pending is not None or (
                self._open_questions(s.id, act.sub) < MAX_OPEN_CLARIFICATIONS
                and len(req.body) <= MAX_CLARIFY_BODY)
            if rounds >= self.cfg.clarification_rounds or not room:
                # No question (the rounds are spent, or the person has too many open): the
                # act goes to the person, with the reasons the policy gives for it.
                d = self.policy.decide(act, mission, self.store.composition_history(
                    s.id, act.sub, act.agent, act.mission_s256, exclude_sdi=b["sdi"], now=now),
                    self.store.reach_of(s.id, act.sub), now, clarify=False)
                if rounds:
                    d.summary = ("The agent did not resolve the supervisor's question within "
                                 "the round limit. " + d.summary).strip()
            else:
                p = pending or Pending(secrets.token_urlsafe(16), s.id, b["sdi"], "clarify",
                                       dict(b), "/decision", sub=act.sub)
                p.request = dict(b)
                p.rounds = rounds + 1
                # Each round restates `timeout`, so each round gets the full time to answer.
                p.deadline = (self.clock() + self.cfg.clarification_timeout
                              if self.cfg.clarification_timeout > 0 else 0.0)
                if pending is None:
                    self.store.add_pending(p)
                p.code = d.clarification
                # A further round keeps the sdi bound to the request that opened it, so the
                # PS's retry of that request still finds its pending URL (L211, L316).
                opened = self.store.decisions.get(Store.k(s.id, b["sdi"]))
                rec = DecisionRecord(b["sdi"], s.id, act.sub, act.agent, act.act, "clarify",
                                     act.mission_s256, d.entry, d.kind, d.composition,
                                     fp=opened.fp if opened and opened.fp
                                     else _fingerprint(req.path, b))
                self.store.record_decision(Store.k(s.id, b["sdi"]), rec)
                return self._clarify_response(p)
        d = _decided(d)
        body: dict[str, Any] = {"sdi": b["sdi"], "decision": d.decision}
        if d.decision == "allow":
            # Supervision defines `exp` (and `scope`) on a token's allow (L485, L508); a
            # permission allow becomes `permission: granted` (L531), which has neither.
            if act.act != "permission":
                body.update({k: v for k, v in d.narrow.items() if k in ("scope", "exp")})
            if act.act == "auth_token" or (act.act == "person_token" and d.entry is not None):
                # Supervision L508 (L485 for a person token that is an act): an allow MAY
                # carry `exp`, and the PS applies it. Capped at the end of the window the SS
                # counts the allow as open (Store.open_acts), a token the PS issues later is
                # already spent, so no request decided after that window can compose with
                # it unseen.
                cap = int(now) + Store.OPEN_ISSUANCE
                body["exp"] = min(int(body.get("exp", cap)), cap)
        elif d.decision == "deny":
            if d.reason:
                body["reason"] = d.reason
        else:
            body["summary"] = d.summary
            if act.act == "person_token" and not d.summary.startswith("The agent asks to "
                                                                       "identify you"):
                # The person is told what is asked before what it may complete.
                body["summary"] = (f"The agent asks to identify you to {act.resource}, which "
                                   f"may serve a request on that alone. "
                                   f"{d.summary.replace(f' {PERSON_TOKEN_TOLD}', '')}")
            if d.recommendation:
                body["recommendation"] = d.recommendation
            if d.apply_options:
                body["apply_options"] = d.apply_options
        resp = self._terminal(req, s, b, act.act, d, body, mission=act.mission_s256)
        if pending is not None:
            pending.resolved = self.store.decisions[Store.k(s.id, b["sdi"])].response
        return resp

    def _terminal(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any], act: str,
                  d: Decision, body: dict[str, Any], mission: str | None = None) -> Response:
        unsigned = json_response(200, body)
        stored = self._store_response(unsigned)
        resp = self._sign(req, unsigned)
        opened = self.store.decisions.get(Store.k(s.id, b["sdi"]))
        rec = DecisionRecord(b["sdi"], s.id, b["sub"], b["agent"], act, d.decision,
                             b.get("mission_s256") or "" if mission is None else mission,
                             d.entry, d.kind, d.composition, stored,
                             fp=opened.fp if opened and opened.fp else _fingerprint(req.path, b),
                             plain=d.plain, certain=d.certain, gates=list(d.gates))
        if not req.path.startswith("/pending/"):
            rec.signed = self._store_response(resp)
        self.store.record_decision(Store.k(s.id, b["sdi"]), rec)
        if act == "permission" and d.decision == "allow":
            # No issuance event follows a permission: the grant is the act, at its delivery
            # (the signature's `created`, the PS's clock): a retried request keeps the
            # `iat` of the act it asks about (Supervision L198), which may be long before.
            self._grant(s, rec, int(self.clock()) + 2, iat=max(_iat(b), s.created))
        return resp

    def _clarify_response(self, p: Pending) -> Response:
        body: dict[str, Any] = {"sdi": p.sdi, "status": "pending", "decision": "clarify",
                                "clarification": p.code}
        if self.cfg.clarification_timeout > 0:
            # Core, Clarification Required: "Seconds until the server times out the
            # request" (Protocol L1071): the time left, which a poll or a retry restates.
            # Stated only because `_pending` enforces it, and rounded down: the recipient
            # "MUST respond before this deadline", so it is never later than the enforced one.
            left = p.deadline - self.clock() if p.deadline else self.cfg.clarification_timeout
            body["timeout"] = max(0, int(left))
        return json_response(202, body,
                             {"Location": f"/pending/{p.id}", "Retry-After": "0",
                              "Cache-Control": "no-store",
                              "AAuth-Requirement": "requirement=clarification"})

    def _pending(self, req: HttpRequest, s: VerifiedSigner, b: dict[str, Any],
                 pid: str) -> Response:
        p = self.store.pending.get(pid)
        if p is None or p.iss != s.id:
            raise unknown_pending()
        if p.kind == "clarify":
            # Supervision L249: a request after disconnect is answered `unknown_sub`, so
            # the PS connects and resends (L633), before anything about the URL itself.
            self._connected(s, p.sub or str(p.request.get("sub") or ""))
        if p.cancelled or p.gone or (p.kind == "clarify" and p.resolved is not None):
            # Protocol L2840: "Once a terminal response is returned, the pending URL MUST
            # return `410 Gone`"; L1121 the same after a DELETE. An answered clarification
            # returned its answer as the response to the reply, so it is gone even in a
            # snapshot written before `gone` was kept.
            return self._unchanged(Response(410))
        m = req.method
        if p.kind == "connect":
            if m != "GET":
                raise invalid_request("connect is polled with GET")
            if p.resolved:
                p.gone = True
                return self._replay(req, p.resolved)
            if not self._awaiting(p):
                # Past its lifetime (Protocol L2400): `expired` (408), a terminal response,
                # so the URL is gone after it.
                p.gone = True
                self.store.settle(p)
                self._changed()
                raise ProtocolError(408, "expired", "the connection was not confirmed in time")
            return self._unchanged(self._connect_pending(p))
        # From here the clarification is still open (an answered one is gone above).
        if p.deadline and self.clock() >= p.deadline:
            # Core, Clarification Required: the recipient "MUST respond before this
            # deadline". Past it the request is over: polling error `expired` (408), a
            # terminal response (L2414), so the URL is gone after it.
            rec = self.store.decisions.get(Store.k(s.id, p.sdi))
            if rec and rec.decision == "clarify":
                rec.decision = "expired"
            p.gone = True
            self.store.settle(p)
            self._changed()
            raise ProtocolError(408, "expired", "the clarification was not answered in time")
        if m == "GET":
            return self._unchanged(self._clarify_response(p))
        if m == "DELETE":
            # Withdrawing abandons the open question (SUP-P17: a DELETE after the answer
            # finds the URL gone and leaves the answer as it is).
            p.cancelled = True
            self.store.settle(p)
            rec = self.store.decisions.get(Store.k(s.id, p.sdi))
            if rec:
                rec.decision = "abandoned"
            return Response(204)
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
        resp = self._evaluate(req, s, merged, pending=p, clarify=False)
        if resp.status != 202:
            p.gone = True  # the answer is the terminal response (L2840)
            self.store.settle(p)
        return resp

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
            return self._unchanged(Response(201))
        ms = b.get("mission_s256") or ""
        if ms and ev != "agent.bound":
            self._mission(s, ms, b["sub"])
        handler = getattr(self, "_ev_" + ev.replace(".", "_"))
        handler(s, b)
        self.store.events_seen.add(ek)
        return Response(201)

    def _record(self, s: VerifiedSigner, b: dict[str, Any]) -> DecisionRecord | None:
        sdi = b.get("sdi")
        return self.store.decisions.get(Store.k(s.id, sdi)) if sdi else None

    def _grant(self, s: VerifiedSigner, rec: DecisionRecord, at: int, note: str = "",
               iat: int = 0, reported: bool = False, wide: bool = False) -> None:
        """A permission the PS granted under `rec` joins the history, once per sdi, at the
        moment it was granted. A grant has no lifetime (core, Permission Response: the
        agent "MAY proceed with the action", at no stated time), so it can take effect at
        any later moment, like a token that never expires. It may already be history, if
        the person granted it while the SS's own answer was pending."""
        if rec.entry is None:
            return
        hist = self.store.history_for(s.id, rec.sub, rec.agent, rec.mission_s256)
        if any(h.sdi == rec.sdi for h in hist):
            return
        entry = _with_sdi(rec.entry, rec.sdi)
        entry.at, entry.token_exp, entry.wide = max(entry.at, at), UNBOUNDED_EXP, wide
        entry.iat = iat or at
        entry.detail += note
        if reported:
            # Granted by the person's answer, reported after acts it may have preceded.
            entry.after_n, late = self._since_decision(s, rec, entry.iat,
                                                       rec.recorded_n or 1)
            entry.unplaced = entry.unplaced or late
        self.store.add_history(hist, entry, rec.agent)

    def _ev_person_token_issued(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        """A person token is an act where its resource may serve on it alone (Protocol,
        Person Identity Access: "No resource token, no auth token"), which the policy says
        (`serves_on_identity`). The SS never sees it used, so it joins history as an
        uncertain act of the resource's class, usable until its `exp`; elsewhere it is an
        identity check and changes nothing. The PS issues one for each approved resource
        at mission approval too (Protocol L1415), reported under the proposal's sdi."""
        raw = b.get("aud")
        if isinstance(raw, list) and not raw:
            raise invalid_request("aud is an empty array")
        auds = [] if raw is None or raw == "" else [
            _server_identifier(a, "aud") for a in (raw if isinstance(raw, list) else [raw])]
        jti = str(b.get("jti") or "")
        rec = self._record(s, b)
        if rec is not None and rec.entry is not None and rec.act == "person_token":
            # The token the SS decided as an act: that act, once, whatever `aud` repeats.
            if (b["sub"], b["agent"]) != (rec.sub, rec.agent) or (
                    b.get("mission_s256") and b["mission_s256"] != rec.mission_s256):
                raise invalid_request("person_token.issued names another person, agent or "
                                      "mission than the decision under its sdi")
            hist = self.store.history_for(s.id, rec.sub, rec.agent, rec.mission_s256)
            entry = next((h for h in hist if h.sdi == rec.sdi
                          and (not jti or h.jti in ("", jti))), None)
            if entry is None:
                entry = _with_sdi(rec.entry, rec.sdi)
                entry.at = max(entry.at, self._took_place(s, b["iat"]))
                entry.wide = self._wide(s, b["iat"])
                entry.iat = _iat(b)
                entry.after_n, late = self._since_decision(s, rec, entry.iat)
                entry.unplaced = entry.unplaced or late
                self.store.add_history(hist, entry, rec.agent)
            entry.jti = jti or entry.jti
            entry.token_exp = max(entry.token_exp or 0, _token_exp(b, _allowed_cap(rec)))
            auds = [a for a in auds if a != rec.entry.resource]
        elif not auds and (rec is None or rec.act != "person_token"):
            # With no decision, `aud` is all the SS knows of where the token goes (one on
            # record says it: an identity check, which books nothing).
            raise invalid_request("person_token.issued without a decision on record needs aud")
        hist = self.store.history_for(s.id, b["sub"], b["agent"], b.get("mission_s256") or "")
        # The audiences this token is already booked at, in one pass over the history.
        booked = {h.resource for h in hist
                  if jti and h.jti == jti and h.detail.endswith(PERSON_TOKEN)}
        for aud in auds:
            if not self.policy.serves_on_identity(aud):
                continue
            if aud in booked:
                continue  # the same token reported again, or the audience named twice
            if self._approval_report(s, b, aud, jti):
                continue
            c = self.policy.classify(Act("person_token", s.id, b["sub"], b["agent"],
                                         b.get("mission_s256") or "", resource=aud))
            self.store.add_history(hist, HistoryEntry(
                c.cls, aud, c.provenance, at=self._took_place(s, b["iat"]), jti=jti,
                detail="uncertain: " + PERSON_TOKEN, token_exp=_token_exp(b), unplaced=True,
                iat=_iat(b), wide=self._wide(s, b["iat"]), blind=list(c.blind)),
                b["agent"])
            if jti:
                booked.add(aud)

    def _approval_report(self, s: VerifiedSigner, b: dict[str, Any], aud: str,
                         jti: str) -> bool:
        """The report of a token an approval issued (Supervision L539: under the proposal's
        `sdi`): it refines the act booked in the mission at approval, wherever the report
        says it is (Protocol L1415: the token carries the mission's `s256`); reported before
        the SS has the mission, it is held as an open act until `approved` books it. False
        for any other token."""
        sdi = str(b.get("sdi") or "")
        prop = self.store.decisions.get(Store.k(s.id, sdi)) if sdi else None
        if prop is not None and (prop.act != "mission_proposal" or (
                (prop.sub, prop.agent) != (b["sub"], b["agent"]))):
            prop = None
        if prop is not None and prop.decision in ("resolved_deny", "resolved_abandoned"):
            return False  # no approval followed: a token issued all the same is a fact
        early = self.store.decisions.get(_approval_key(s.id, sdi, aud)) if sdi else None
        if early is not None and (prop is None or early.act != "person_token"):
            early = None
        # The proposal's mission once it is approved (the approval links them, Supervision
        # L443), else the mission the report names; before its approval, held for it.
        mission = prop.mission_s256 if prop is not None else str(b.get("mission_s256") or "")
        booked = self._approval_booked(s, b, aud, mission, jti) if mission else None
        if booked is not None:
            booked.jti = booked.jti or jti
            booked.token_exp = max(booked.token_exp or 0, _token_exp(b))
            if early is not None:
                early.entry = None
            return True
        if prop is None:
            return False
        # Approved, but this report refines no act of the approval (past the bound, or a
        # second token for the resource): still the mission's token.
        where = prop.mission_s256
        if where:
            m_hist = self.store.history_for(s.id, b["sub"], b["agent"], where)
            if jti and any(h.resource == aud and h.jti == jti for h in m_hist):
                return True  # the same token reported again
            c = self.policy.classify(Act("person_token", s.id, b["sub"], b["agent"],
                                         resource=aud))
            self.store.add_history(m_hist, HistoryEntry(
                c.cls, aud, c.provenance, at=self._took_place(s, b["iat"]), jti=jti,
                detail="uncertain: " + PERSON_TOKEN, token_exp=_token_exp(b), unplaced=True,
                after_n=prop.recorded_n, iat=_iat(b),
                wide=self._wide(s, b["iat"]), blind=list(c.blind)), b["agent"])
            return True
        c = self.policy.classify(Act("person_token", s.id, b["sub"], b["agent"], resource=aud))
        own = self.store.decisions.get(Store.k(s.id, sdi, aud, jti)) if jti else None
        if own is not None and own.decision == "reported" and own.entry is not None:
            # A token held in a record of its own (another came after it), reported again:
            # that one act widens, from its first report to its latest `exp`.
            self._held_again(own.entry, s, b)
            own.entry.token_exp = max(own.entry.token_exp or 0, _token_exp(b))
            return True
        if early is not None and early.decision == "reported" and early.entry is not None and (
                early.entry.jti == jti):
            # The same token reported again, or two that name no `jti` and so cannot be told
            # apart: one held act, from the earliest report to the latest `exp`.
            self._held_again(early.entry, s, b)
            early.entry.token_exp = max(early.entry.token_exp or 0, _token_exp(b))
            return True
        if early is not None and early.decision == "reported" and early.entry is not None and (
                early.entry.jti != jti):
            # Another token for the resource: the first is held in a record of its own.
            first = dataclasses.replace(early)
            self.store.record_decision(Store.k(s.id, sdi, aud, early.entry.jti), first)
            early = None
        rec = early or DecisionRecord(sdi, s.id, b["sub"], b["agent"], "person_token",
                                      "reported")
        rec.decision = "reported"
        # It exists from its report and may have served before acts recorded after it.
        rec.entry = HistoryEntry(c.cls, aud, c.provenance, at=self._took_place(s, b["iat"]),
                                 jti=jti, detail="uncertain: " + PERSON_TOKEN,
                                 token_exp=_token_exp(b),
                                 unplaced=True, after_n=prop.recorded_n, iat=_iat(b),
                                 wide=self._wide(s, b["iat"]), blind=list(c.blind))
        self.store.record_decision(_approval_key(s.id, sdi, aud), rec)
        return True

    def _lead(self, iss: str, sub: str) -> float:
        """How far ahead of the SS's clock the PS's clocks may run: the most its requests
        for its connected people showed (`Store.observe_lead`: their stamps or
        signatures), which falls short by their fastest transit, so with
        `transit_allowance` added; before any, as far as the signature window lets it.
        By PS: `sub` names no clock of its own."""
        seen = self.store.lead_of(iss)
        base = float(self.cfg.signature_window) if seen is None else seen
        return base + self.cfg.transit_allowance

    def _stamp(self, s: VerifiedSigner, iat: Any) -> int:
        """The PS's stamp on an act, never after the signature of the request reporting it
        (`created`): an act precedes its report (Supervision L198), and a PS whose stamp
        says otherwise stamps on another clock than it signs with. Read where the act took
        place by at the latest (`_took_place`); acts are ordered by their own stamps. As
        its whole second (`_iat`), as `created` is one."""
        return min(math.floor(iat), s.created)

    def _held_again(self, entry: HistoryEntry, s: VerifiedSigner, b: dict[str, Any]) -> None:
        """A held token reported again: from its earliest report; placed by the window
        around its stamp once any report of it came long after (`_wide`)."""
        entry.at = min(entry.at, self._took_place(s, b["iat"]))
        if self._wide(s, b["iat"]):
            entry.wide = True
        if entry.wide:
            entry.at = max(entry.at, entry.iat + self.cfg.signature_window +
                           self.cfg.transit_allowance + 2)

    def _wide(self, s: VerifiedSigner, iat: Any, replay: bool = False) -> bool:
        """Whether a report came long after the act it reports, by the PS's own clock
        (`WIDE_AFTER`), or is a replay to this SS (Supervision L619): the PS's clock then
        may not be its clock now."""
        return replay or s.created - self._stamp(s, iat) > WIDE_AFTER

    def _took_place(self, s: VerifiedSigner, iat: Any, replay: bool = False) -> int:
        """When an act the PS stamped `iat` took place, at the latest, on the SS's clock:
        the stamp moved by the offset the signature of the request reporting it shows
        (`created` against the SS's clock on its arrival: a PS clock behind or ahead; the
        transit only makes it later), and two seconds for whole-second stamps and
        signatures; for one reported long after it or replayed (`_wide`), as late as the
        window allows past its stamp."""
        if self._wide(s, iat, replay):
            # Anywhere the window allows around the PS's own stamp, which places the act
            # (`HistoryEntry.iat`), never one clamped to a replay's later signature.
            return math.floor(iat) + self.cfg.signature_window + \
                self.cfg.transit_allowance + 2
        received = s.received or self.clock()
        return self._stamp(s, iat) + int(received) - s.created + 2

    def _since_decision(self, s: VerifiedSigner, rec: DecisionRecord, iat: int,
                        n0: int = 0) -> tuple[int, bool]:
        """For an act stamped `iat` and reported after an act of its person recorded since
        its decision (`n0`; by default the person's answer, for an ask, which it cannot
        precede) that the PS stamped no earlier: the position of the first such act, from
        which it may have been used at any moment (`after_n`: every act recorded between
        its decision and that one was stamped earlier, so it came first), and whether one
        was stamped strictly later (out of the order Supervision L211 asks for: the act
        then floats, `unplaced`, its own stamp placing it for certain). In the same second
        only, which came first is not settled: it is floored, but stands where it is
        reported for certain. (0, False) otherwise. Only the PS's stamps are compared
        (`HistoryEntry.iat`), never with the SS's clock."""
        # A record from a snapshot that kept no position (0): from the start, then.
        n0 = n0 or rec.resolved_n or rec.recorded_n or 1
        first, latest = self.store.stamped_since(s.id, rec.sub, n0, iat)
        return first, latest > iat

    def _approval_booked(self, s: VerifiedSigner, b: dict[str, Any], aud: str, mission: str,
                         jti: str) -> HistoryEntry | None:
        """The act booked at `mission`'s approval for `aud` that this report refines: the
        agent's own, no report has refined yet, or this one."""
        m = self.store.missions.get(Store.k(s.id, mission))
        for h in m.history if m is not None else []:
            # The approval's token is its agent's: a report for another agent is not it.
            if h.resource == aud and h.detail == APPROVAL_DETAIL and h.jti in ("", jti) and (
                    h.agent == b["agent"]):
                return h
        return None

    def _ev_auth_token_issued(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        rec = self._record(s, b)
        if rec is not None and rec.entry is not None:
            if (b["sub"], b["agent"]) != (rec.sub, rec.agent) or (
                    b.get("mission_s256") and b["mission_s256"] != rec.mission_s256):
                # The token was issued under the decision this sdi names, for its person and
                # agent: a report that names others would book the act in the wrong history.
                raise invalid_request("auth_token.issued names another person, agent or "
                                      "mission than the decision under its sdi")
            # Issuance is a fact, whatever was decided: the act now counts for composition
            # and budgets, so a PS that issued past a deny cannot hide it from later acts.
            # It is not an answer: an `ask` stays unresolved until `decision.resolved`
            # says what the person decided, so issuance never stands in for the person.
            hist = self.store.history_for(s.id, rec.sub, rec.agent, rec.mission_s256)
            jti = b.get("jti") if isinstance(b.get("jti"), str) else ""
            mine = [h for h in hist if h.sdi == rec.sdi]
            # Another token under the same decision (another `jti`) is another act, and
            # another allocation, as much a fact as the first.
            entry = next((h for h in mine if not jti or h.jti in ("", jti)), None)
            if entry is None:
                entry = _with_sdi(rec.entry, rec.sdi)
                # The act counts from its issuance, which can be long after the decision
                # (an ask the person took hours to answer).
                entry.at = max(entry.at, self._took_place(s, b["iat"]))
                entry.wide = self._wide(s, b["iat"])
                entry.iat = _iat(b)
                entry.after_n, late = self._since_decision(s, rec, entry.iat)
                entry.unplaced = entry.unplaced or late
                if rec.decision not in ("allow", "resolved_allow"):
                    entry.detail += f" (issued after {rec.decision})"
                self.store.add_history(hist, entry, rec.agent)
            if jti:
                # The token that carries this act's budget allocation: a later
                # `budget_consumed` names it (AAuth Budgets, The Consumption Record).
                entry.jti = jti
            # A second report under the sdi (a reissue, or the same token reported again)
            # never shortens the time the act can take effect.
            entry.token_exp = max(entry.token_exp or 0, _token_exp(b, _allowed_cap(rec)))
            return
        # No decision context for this sdi (replay to a new SS): classify from the event alone.
        # The resource is `aud`, held to the server identifier rule a decision request is
        # held to (a non-conforming one would slip past rules written for the identifier).
        # A JWT audience may be an array: a token for several audiences can be presented
        # at each, so it is one act per audience.
        # Without a decision, `aud` is all the SS knows of where the token is presented
        # (L539-L540 list it): a token of unknown audience cannot be classified, and booked
        # as unclassified it would compose with nothing.
        raw_aud = b.get("aud")
        if not raw_aud:
            raise invalid_request("auth_token.issued without a decision on record needs aud")
        auds = [_server_identifier(a, "aud")
                for a in (raw_aud if isinstance(raw_aud, list) else [raw_aud])]
        member = self.policy.r3_member
        raw = b.get(member) if member is not None else None
        forwarded = isinstance(raw, (dict, str))
        prop = self._proposal(raw, {}) if forwarded else {}
        hist = self.store.history_for(s.id, b["sub"], b["agent"], b.get("mission_s256") or "")
        sdi, jti = str(b.get("sdi") or ""), str(b.get("jti") or "")
        # A token reported again (or replayed after its first report) is the same act: its
        # `exp` only widens. Another `jti` under the sdi is another token, another act
        # (L540: the PS or an AS may issue under one decision). One pass over the history
        # finds them, whatever the number of audiences.
        held: dict[str, HistoryEntry] = {}
        for h in hist:
            if sdi and h.sdi == sdi and (not jti or h.jti in ("", jti)):
                held.setdefault(h.resource, h)
        # Checked before any audience is booked: a refused report changes nothing.
        scope = _scope(str(b.get("scope") or ""))
        operations = _operations(prop) if forwarded else []
        for aud in auds:
            same = held.get(aud)
            if same is not None:
                same.jti = jti or same.jti
                same.token_exp = max(same.token_exp or 0, _token_exp(b))
                continue
            act = Act("auth_token", s.id, b["sub"], b["agent"], b.get("mission_s256") or "",
                      resource=aud, scope=scope)
            if forwarded:
                act.operations = list(operations)
                act.parameters = prop.get("parameters") if isinstance(prop.get("parameters"),
                                                                        dict) else {}
                act.parameters_provenance = "resource"
                act.result = prop.get("result") if isinstance(prop.get("result"),
                                                              dict) else None
            c = self.policy.classify(act)
            # A forwarded proposal is the resource's word for the act, whatever rule matched.
            entry = HistoryEntry(
                c.cls, aud, "resource" if forwarded else c.provenance,
                sdi=sdi, jti=jti, at=self._took_place(s, b["iat"], replay=True), wide=True,
                amount=c.amount or 0,
                amount_known=c.amount is not None, blind=list(c.blind),
                detail=("uncertain: " if c.uncertain else "") + "replayed",
                token_exp=_token_exp(b), unplaced=True, iat=_iat(b))
            self.store.add_history(hist, entry, b["agent"])
            if sdi:
                held[aud] = entry  # an audience named twice in the array is one act

    def _ev_decision_resolved(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        self._require(b, "sdi", "answer")
        answer = b["answer"]
        if answer not in ("allow", "deny", "abandoned"):
            raise invalid_request("answer must be allow, deny or abandoned")
        rec = self._record(s, b)
        if rec is None:
            return
        if (b["sub"], b["agent"]) != (rec.sub, rec.agent) or (
                b.get("mission_s256") and rec.mission_s256
                and b["mission_s256"] != rec.mission_s256):
            # The answer is about the act decided under this sdi, for its person and agent.
            raise invalid_request("decision.resolved names another person, agent or mission "
                                  "than the decision under its sdi")
        if rec.decision != "ask":
            # Only an `ask` is put to the person. A resolution reported for an sdi the SS
            # allowed or denied (or already saw resolved) carries no authority: it must
            # not widen a deny into a standing reach. But a permission the person allowed
            # after the PS could not use the SS's answer (L611) was granted, and no
            # issuance event will say so: like an issuance past a deny, it is a fact, and
            # it joins the history so that later acts compose with it.
            if answer == "allow" and rec.act == "permission":
                self._grant(s, rec, self._took_place(s, b["iat"]),
                            f" (granted after {rec.decision})", iat=_iat(b),
                            reported=True, wide=self._wide(s, b["iat"]))
            return
        rec.decision = "resolved_" + answer
        # Given by its arrival at the latest: its token is awaited from then (the PS's
        # stamp, behind or ahead, would cut that short or stretch it).
        rec.resolved_at = self.clock()
        # The answer's own place: where it is reported, unless an act recorded since the
        # ask was stamped by the PS no earlier (the answer delivered out of L211's order):
        # then its token may follow the ask only (`resolved_n` 0, `recorded_n` stands).
        late = self.store.latest_since(s.id, rec.sub, rec.recorded_n or 1) >= _iat(b)
        rec.resolved_n = 0 if late else self.store.recorded_count() + 1
        if rec.act == "mission_proposal":
            # Its approval tokens are issued at approval, which follows the answer; a
            # proposal declined or abandoned has no approval, so none of them.
            for t in self._approval_tokens(s, rec.sub, rec.sdi):
                if answer == "allow":
                    t.resolved_at = max(t.resolved_at, rec.resolved_at)
                elif t.decision == "reported" and t.entry is not None:
                    # Issued and reported, with no mission to book it in: a fact all the
                    # same, outside missions, after acts it may have preceded.
                    t.entry.unplaced = True
                    self.store.add_history(self.store.history_for(s.id, t.sub, t.agent, ""),
                                           t.entry, t.agent)
                    t.entry = None
                else:  # withdrawn: an approval reported after all opens it again
                    t.entry, t.decision = None, "withdrawn"
        if answer == "abandoned":
            return
        if answer == "allow" and rec.act == "mission_update":
            # The record was made for a mission the SS holds, and missions are kept.
            self.store.missions[Store.k(s.id, rec.mission_s256)].updates.append(rec.update)
        if answer == "allow" and rec.act == "permission":
            self._grant(s, rec, self._took_place(s, b["iat"]), iat=_iat(b),
                        reported=True, wide=self._wide(s, b["iat"]))
        apply = b.get("apply") or "once"
        if apply not in self._offered_reaches(rec):
            # The SS names the reaches (L584): a value it did not offer for this ask is
            # not one it recognizes, so the answer counts for this act only.
            apply = "once"
        if apply != "once" and rec.kind:
            # The SS remembers the answer, allow or deny, and applies it (L582). It covers
            # what the offered reach named: the composition, and each plain gate (intent,
            # high impact) the ask named too. An ask that named neither was about acts of
            # this kind. A later answer for a scope replaces an earlier.
            scope = rec.mission_s256 if apply != "always" else ""
            rows = ([(list(rec.composition), "")] if rec.composition else []) + [
                ([], g) for g in rec.gates] + (
                [([], "")] if not rec.composition and not rec.plain else [])
            new = [Reach(str(apply), s.id, rec.sub, rec.agent, rec.kind, scope, comp, answer,
                         certain=rec.certain, gate=g) for comp, g in rows]
            # An `always` answer is about every mission, so it also replaces the
            # mission answers given for the same kind and composition.
            same = {_reach_scope(r, apply == "always") for r in new}
            # A scope names the person, so only their rows (`reach_of`) can be replaced;
            # the table is rebuilt only when one is.
            if any(_reach_scope(r, apply == "always") in same
                   for r in self.store.reach_of(s.id, rec.sub)):
                self.store.reach = [r for r in self.store.reach
                                    if _reach_scope(r, apply == "always") not in same]
            self.store.reach.extend(new)

    @staticmethod
    def _offered_reaches(rec: DecisionRecord) -> set[str]:
        """The `apply_options` values the SS sent in this record's `ask`, plus `once`. An
        ask sent with no `apply_options` leaves the PS the three reaches whose meaning is
        fixed (L599): `once`, `mission` and `always`."""
        offered = {"once"}
        if rec.response is not None:
            try:
                sent = json.loads(rec.response.body)
            except ValueError:
                return offered
            if isinstance(sent, dict) and "apply_options" not in sent:
                return offered | {"mission", "always"}
            for o in sent.get("apply_options", []) if isinstance(sent, dict) else []:
                if isinstance(o, dict) and isinstance(o.get("value"), str):
                    offered.add(o["value"])
        return offered

    def _ev_audit_recorded(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        # Agent-reported local actions: agent-asserted, so they can only tighten later decisions.
        act = Act("permission", s.id, b["sub"], b["agent"], b.get("mission_s256") or "",
                  tool=_tool_name(b.get("action"), "action"),
                  parameters=b.get("parameters") if isinstance(b.get("parameters"), dict) else {},
                  parameters_provenance="agent")
        res = b.get("result")
        if isinstance(res, dict):
            act.result = res
        c = self.policy.classify(act)
        self.store.add_history(
            self.store.history_for(s.id, act.sub, act.agent, act.mission_s256),
            HistoryEntry(c.cls, act.tool, c.provenance, sdi="", at=self._took_place(s, b["iat"]),
                         amount=c.amount or 0,
                         detail=("uncertain: " if c.uncertain else "") + "audit record",
                         amount_known=c.amount is not None, blind=list(c.blind),
                         iat=_iat(b), wide=self._wide(s, b["iat"])),
            b["agent"])

    def _ev_interaction_requested(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        return None

    def _ev_agent_bound(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        self.store.agents[Store.k(s.id, b["sub"], b["agent"])] = {
            "agent_iss": b.get("agent_iss"), "agent_sub": b.get("agent_sub"),
            "at": _iat(b)}

    def _ev_revocation_received(self, s: VerifiedSigner, b: dict[str, Any]) -> None:
        # Acknowledged, not kept: the SS "has no part in the cascade" (Supervision L545),
        # and nothing it decides reads a revocation.
        return None


def _reach_scope(r: Reach, any_mission: bool = False) -> tuple[str, ...]:
    return (r.iss, r.sub, r.agent, r.kind, "" if any_mission else r.mission_s256, r.gate,
            *r.composition_override)


def _with_sdi(e: HistoryEntry, sdi: str) -> HistoryEntry:
    return dataclasses.replace(e, sdi=sdi)


def _allowed_cap(rec: DecisionRecord) -> tuple[float, int] | None:
    """When the SS's own `allow` for this auth token, or person token that is an act,
    carried `exp` (Supervision L508, L485),
    the decision time and that cap; None otherwise (an ask the person allowed, a deny the
    PS issued past, or no stored answer)."""
    if rec.act not in ("auth_token", "person_token") or rec.decision != "allow" \
            or rec.response is None or rec.entry is None:
        return None
    sent = json.loads(rec.response.body)
    cap = sent.get("exp")
    return (rec.entry.at, cap) if isinstance(cap, int) else None


def _token_exp(b: dict[str, Any], allowed: tuple[float, int] | None = None) -> int:
    """The issued token's `exp` (Events, `auth_token.issued`), rounded up to a whole second
    (a NumericDate may have a fraction, RFC 7519 Section 2). A token whose lifetime the
    PS did not report as a positive number is treated as never expiring, so it can
    never be read as spent before a later act. So is one whose `exp` is not after the
    event's own `iat`: a token expired when issued is not what was issued (a lifetime sent
    as `exp`, or a slip), and reading it as spent would reopen the order it guards. The
    `iat` as sent, not its whole second (`_iat`): an `exp` within the stamp's second but
    before it was spent when issued.

    Except where the SS capped the allow itself (`allowed`: decision time, cap): an `exp`
    from the decision to the cap is the cap applied (L508), and a token issued after that
    time (the event's `iat` is the time of the act, L198) is already spent, not a slip.
    Read as never expiring, it would deny honest acts for good merely because the PS
    issued late."""
    v, iat = b.get("exp"), b.get("iat")
    if not _is_time(v) or v <= 0:
        return UNBOUNDED_EXP
    exp = math.ceil(v)
    if allowed is not None and allowed[0] <= v <= allowed[1]:
        return exp
    if _is_time(iat) and v <= iat:
        return UNBOUNDED_EXP
    return exp


def _is_time(v: Any) -> TypeGuard[float]:
    """A time in seconds since the epoch: a JSON number, finite, not a boolean."""
    return (isinstance(v, int) and not isinstance(v, bool)) or (
        isinstance(v, float) and math.isfinite(v))


def _iat(b: dict[str, Any]) -> int:
    """The PS's stamp on a request or event (`iat`, seconds since the epoch, Supervision
    L198; a time `_check_member_types` let through) as the whole second it falls in,
    rounded down: `1790600000.9` is `1790600000`. Every stamp the SS compares, keeps, or
    places an act by is read so, as stamps kept are whole seconds: an act stamped in the
    same second as another is in no settled order with it, a fraction or not. Read as sent
    only where that is the cautious reading: the fingerprint of a request (`_fingerprint`),
    an `exp` before the stamp (`_token_exp`), and the end of a token an hour from it."""
    return math.floor(b["iat"])


def _fingerprint(path: str, b: dict[str, Any]) -> str:
    """What makes a request under an sdi "the same request" (Idempotence, L316).

    The whole body, canonically serialized, plus the endpoint. A retry is the same
    request (`iat` is unchanged on a retry, L198), so it matches; a different act
    reusing an sdi does not. `iat` counts as the number sent, not as its whole second
    (`_iat`): one that differs below the second has changed. JSON has one number type
    (RFC 8259 Section 6), so a whole number is the same however it is written
    (`1790600000`, `1790600000.0`, `1.7906e9`).
    """
    iat = b.get("iat")
    if isinstance(iat, float) and iat.is_integer():
        b = b | {"iat": int(iat)}
    # Equivalent mutant, kept on purpose: `ensure_ascii` does not change what the
    # fingerprint distinguishes, but changing it would change every stored fingerprint, so
    # a retry across an upgrade would no longer match its sdi.
    canon = json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False)  # pragma: no mutate
    # `surrogatepass`: a lone surrogate the agent put in its text (valid JSON) must not make
    # a decided request a server error; for any other text the bytes are unchanged.
    return b64u(hashlib.sha256(f"{path}\n{canon}".encode("utf-8", "surrogatepass")).digest())


def _normalize(a: str) -> str:
    a = a.strip().lower()
    return a[: -len(":443")] if a.endswith(":443") else a
