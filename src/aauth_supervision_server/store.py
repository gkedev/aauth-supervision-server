"""SS state: connections, missions, decisions, pending requests, history and reach.

The store is in memory with an optional JSON snapshot. PS replay (Supervision, Replay and
Recovery) rebuilds missions, their logs and outstanding tokens; it does not bring back
connections, the reach of earlier answers, permission grants, or acts outside missions
that are not outstanding tokens (README, Limitations).
"""

from __future__ import annotations

import contextlib
import dataclasses
import heapq
import importlib
import importlib.util
import itertools
import json
import math
import os
import re
import secrets
import threading
import time
import types
import typing
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Alias:
    """Another class an act has: one a further rule gives it, where the agent's data
    raised its class, or where its class was assumed for data a rule needs and does not
    have, or for what a resource served on a person token (`assumed`: a class it may have
    otherwise) (`HistoryEntry.blind`). Whether that class is certain (the act itself may
    still be uncertain), and the amount that
    class's rule reads (`amount_known` False where it reads none). `set_aside`: assumed
    only in the reading with the agent's data set aside (the request showed what the rules
    read; the class rests on that data being false)."""

    cls: str
    certain: bool = False
    amount: int = 0
    amount_known: bool = False
    assumed: bool = False
    set_aside: bool = False


@dataclass
class HistoryEntry:
    """One act the SS knows happened, as composition state."""

    action_class: str
    resource: str
    provenance: str  # "resource" | "agent" | "configured"
    sdi: str = ""
    # The latest the SS knows the act took place by, on its own clock: the PS's stamp
    # moved by the offset its report's signature shows (`created` against the report's
    # arrival), and never before the SS's decision. A snapshot written before it was kept
    # holds the PS's stamp, or the SS's time of the decision.
    at: int = 0
    amount: int = 0
    detail: str = ""
    # Whether `amount` is what the act was: False when the SS never saw it (an amount
    # budget cannot count such an act as 0).
    amount_known: bool = True
    # AAuth Budgets. When the resource token carried a `budget` offer, the act's allocation
    # at that resource: `unit` is "<unit>/<decimals>" (compared exactly, never converted),
    # `allocated` the offer the PS may have granted in full, `jti` the auth token that
    # carries it (from `auth_token.issued`), and `consumed` the latest resource-signed
    # `budget_consumed` for that token. The allocation counts as fully consumed (Budgets,
    # Unreported Allocations), and a record only raises it (L841: it settles nothing).
    unit: str = ""
    allocated: int = 0
    jti: str = ""
    consumed: int | None = None
    # A token's act is not a moment: the token can be presented until its `exp`, so its
    # effect may land after acts the SS decides later. `None` for an act that happens once
    # (an audited action); for an issued token the `exp` reported for it, or UNBOUNDED_EXP
    # when the PS did not report a usable one. A permission grant has no lifetime, so it
    # is UNBOUNDED_EXP too.
    token_exp: int | None = None
    # The order in which the SS recorded the entry, across every history it keeps, so
    # entries from two histories can be put in one order (0 for an entry recorded before
    # this was kept: such entries all predate any numbered one).
    n: int = 0
    # Set only on the copies the SS hands the policy from another history (of the same
    # chain, another mission, or another agent of the same provider). They count for
    # composition, never for the act's budgets. Never stored as True.
    borrowed: bool = False
    # On a copy from another history: the mission it comes from, or `agent:<id>` for the
    # acts outside missions of another agent. The policy composes the act with all of them
    # together, every act of another scope uncertain, and with each mission of the act's
    # own agent on its own, certain where the evidence is.
    scope: str = ""
    # The agent whose act it is. In a mission it need not be the mission's agent (a call
    # chain acts under the upstream mission); empty for an entry recorded before this was
    # kept.
    agent: str = ""
    # Set only on copies `composition_history` adds that may make a later act be asked,
    # never denied, and that spend no budget (each is uncertain and borrowed). For acts the
    # SS has answered that are not history yet (`Store.open_acts`): "own" when the act is
    # in the decided act's own history scope (the same mission, or the same agent outside
    # missions), "other" otherwise. "mission" for an act of another mission, "agent" for
    # an act outside missions of another agent of the same provider. Never stored.
    open: str = ""
    # When the agent's data raised the act to `action_class` through a rule of that
    # class: every further class it has, down to the one no raising rule gives it. A
    # higher class need not be in the compositions or budgets a lower one is in, so the act
    # also composes (as one act under any of its classes) and counts as each, certain only
    # where that class was and the act is.
    blind: list[Alias] = field(default_factory=list)
    # Where the act stood is not known: it arrived after acts it may have preceded (a token
    # replayed after a routing change, a person token reported with no decision, any token
    # an approval issues, a token reported after an act stamped later). It may have been
    # usable from the start of the history; copies keep it.
    unplaced: bool = False
    # One past the number of the last entry the SS had recorded when it answered the
    # decision this act follows (`DecisionRecord.recorded_n`): the act cannot have taken
    # effect before an entry numbered below it, which had taken place, and been reported,
    # before that answer. Set on an act whose place is not known (it may otherwise have
    # been usable from the start), and on one reported after acts recorded since its
    # decision (it may have been used at any moment since). 0: no such bound.
    after_n: int = 0
    # The PS's stamp (`iat`) on the request or event that put the act in history: stamps
    # of one clock, compared with each other where `at` mixes the PS's and the SS's. 0
    # when not known (a snapshot written before it was kept).
    iat: int = 0
    # Reported long after it took place (`WIDE_AFTER`, a replay): placed anywhere from
    # `iat` less what `at` is past it to `at`, not by the PS's lead now.
    wide: bool = False


UNBOUNDED_EXP = 2**62  # a token whose lifetime the SS does not know is treated as never expiring
# Protocol L863: a person token MUST NOT live more than an hour, nor past its mission's
# `expires_at`.
PERSON_TOKEN_LIFE = 3600

# How a history entry for a person token ends its `detail`: the token was issued for a
# resource that may serve on it alone (Person Identity Access). It composes as uncertain
# and spends no budget.
PERSON_TOKEN = "person token"

# How long after its `exp` an issued token is still treated as usable. The resource judges
# `exp` "by the verifier's own clock" with no tolerance defined (Protocol L2317), so a
# resource whose clock runs behind this SS's still accepts the token. The bound is the
# signature validity window the protocol uses for clock differences (L2246, L2320: 60 s by
# default); this is the SS's own conservative choice, not a draft requirement.
EXP_SKEW = 60
# Seconds an act a PS stamped may have taken place before its stamp moved by that PS's
# lead (`Store.lead_of`, with the server's `transit_allowance`): whole-second signatures.
STAMP_SLACK = 1
# A report signed longer than this after the act it reports, by the PS's own clock (a
# replay, an outage): the PS's clock may have changed in between, so the act is placed
# anywhere the signature window allows around its stamp (`HistoryEntry.wide`).
WIDE_AFTER = 300


def iso_to_epoch(v: Any) -> float | None:
    """A mission's `expires_at` in epoch seconds; None when the mission has none.

    A present value that is not an RFC 3339 timestamp with an offset fails closed: it is
    -inf, so the mission reads as expired. Read as "no expiry" it would let a malformed
    (or tampered) blob outlive its approval, and a timestamp without an offset would
    expire at a different instant on every host's local time zone.
    """
    if v is None:
        return None
    if not isinstance(v, str):
        return float("-inf")
    from datetime import datetime

    # RFC 3339 Section 5.6: "T" and "Z" may be lower case (the standard library reads a
    # lower-case "t", not a "z"), and a leap second is second 60 (Section 5.7), which the
    # standard library refuses: read as second 59 and one second more.
    text = v[:-1] + "+00:00" if v[-1:] in ("Z", "z") else v
    text, leap = _LEAP_SECOND.subn("59", text, count=1)
    try:
        t = datetime.fromisoformat(text)
    except ValueError:
        return float("-inf")
    return t.timestamp() + leap if t.tzinfo is not None else float("-inf")


_LEAP_SECOND = re.compile(r"(?<=[Tt]\d\d:\d\d:)60(?=[.+-])")

# The decisions that leave an act open until an event settles it (Store.open_acts).
# `reported`: a person token an approval issued, reported before its mission's
# `approved`: open until that report books it in the mission.
_OPEN_KINDS = frozenset({"ask", "clarify", "allow", "resolved_allow", "reported"})


@dataclass
class Mission:
    s256: str
    agent: str
    sub: str
    iss: str
    blob: dict[str, Any] = field(default_factory=dict)
    state: str = "active"  # active | terminated
    reason: str = ""
    history: list[HistoryEntry] = field(default_factory=list)
    # The descriptions of the updates the SS accepted, in order (Supervision, Update).
    updates: list[str] = field(default_factory=list)


@dataclass
class Reach:
    """A person's answer extended beyond one act (Reach of an Answer)."""

    value: str  # once | mission | always | an apply_options value
    iss: str
    sub: str
    agent: str
    kind: str  # "<class>|<resource>" the SS matches on
    mission_s256: str = ""
    composition_override: list[str] = field(default_factory=list)  # [a, b] pair allowed
    answer: str = "allow"  # what the person answered: allow, or deny
    # Whether the composition was completed on certain evidence when the person answered.
    certain: bool = False
    # The plain gate the answer is about (`intent`, `high_impact`), or "" for a composition
    # or an ask with neither. A row written before gates were kept has "", so it covers
    # no plain gate: the person is asked again.
    gate: str = ""


@dataclass
class StoredResponse:
    status: int
    headers: dict[str, str]
    body: str


@dataclass
class Pending:
    id: str
    iss: str
    sdi: str
    kind: str  # "clarify" | "connect"
    request: dict[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    rounds: int = 0
    resolved: StoredResponse | None = None
    cancelled: bool = False
    code: str = ""
    sub: str = ""
    # When the record expires (epoch seconds): an unanswered clarification's timeout, or
    # a connect's lifetime; 0 means it does not.
    deadline: float = 0.0
    # Set once the pending URL has returned a terminal (non-202) response: from then on it
    # answers 410 Gone (Protocol L2840). A retry of the request itself, under its `sdi`,
    # still gets the same decision (Supervision L316).
    gone: bool = False
    # A connect whose interaction page the person has opened with its code: polls say
    # `interacting` (Protocol L2523).
    arrived: bool = False
    # A connect's key in `events_seen` (its PS and `id`), removed with the record.
    once: str = ""
    # Wrong operator tokens posted with a connect's code (`MAX_OPERATOR_FAILURES`): kept
    # with the record, so they go when it goes, and saved with it.
    failures: int = 0


@dataclass
class DecisionRecord:
    """What the SS decided under an sdi, kept to tie later events back to it."""

    sdi: str
    iss: str
    sub: str
    agent: str
    act: str
    decision: str
    mission_s256: str = ""
    entry: HistoryEntry | None = None  # what will join history once the PS reports issuance
    kind: str = ""
    composition: list[str] = field(default_factory=list)
    response: StoredResponse | None = None  # the terminal answer, unsigned
    signed: StoredResponse | None = None  # the signed answer as first given at the endpoint
    fp: str = ""  # digest of the request that opened this sdi (Idempotence binds to it)
    # Whether the ask also named a plain gate (intent, high impact), which the person's
    # answer then covers beside `composition`, and which ones (`gates`).
    plain: bool = False
    # When the person's answer to an ask arrived, on the SS's clock (not the
    # `decision.resolved` `iat`); 0 before that or for a snapshot written before this was
    # kept.
    resolved_at: float = 0.0
    # Whether `composition` was completed on certain evidence when it was asked.
    certain: bool = False
    # A mission update put to the person: its description, kept with the mission if they
    # allow it.
    update: str = ""
    gates: list[str] = field(default_factory=list)
    # One past the number of the last history entry recorded when the SS answered
    # (`recorded_n`) and when the person's answer arrived (`resolved_n`): its act cannot
    # have taken effect before entries recorded earlier (`HistoryEntry.after_n`). 0: not
    # known (a snapshot written before these were kept).
    recorded_n: int = 0
    resolved_n: int = 0


def _conforms(v: Any, t: Any) -> bool:
    """Whether a JSON value matches a field annotation (the shapes this module uses)."""
    origin, args = typing.get_origin(t), typing.get_args(t)
    if t is Any:
        return True
    if origin in (types.UnionType, typing.Union):
        return any(_conforms(v, a) for a in args)
    if t is type(None):
        return v is None
    if origin is list:
        return isinstance(v, list) and all(_conforms(x, args[0]) for x in v)
    if origin is dict:
        return isinstance(v, dict) and all(
            _conforms(k, args[0]) and _conforms(x, args[1]) for k, x in v.items())
    if dataclasses.is_dataclass(t):
        return isinstance(v, dict)  # checked field by field by _typed
    if t is int:
        return isinstance(v, int) and not isinstance(v, bool)
    return isinstance(v, t)


_HINTS: dict[Any, dict[str, Any]] = {}


def _typed(cls: Any, d: Any, where: str) -> Any:
    """Build a dataclass from snapshot JSON, refusing a member of the wrong type, so a
    damaged snapshot is set aside at load instead of failing a later request."""
    if not isinstance(d, dict):
        raise ValueError(f"{where}: not an object")
    hints = _HINTS.get(cls)
    if hints is None:  # resolving them is most of a load's cost, so once per class
        hints = _HINTS[cls] = typing.get_type_hints(cls)
    names = {f.name for f in dataclasses.fields(cls)}
    if set(d) - names:
        raise ValueError(f"{where}: unknown members {sorted(set(d) - names)}")
    out: dict[str, Any] = {}
    for f in dataclasses.fields(cls):
        if f.name not in d:
            if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
                raise ValueError(f"{where}.{f.name}: missing")
            continue
        v, t = d[f.name], hints[f.name]
        if not _conforms(v, t):
            raise ValueError(f"{where}.{f.name}: wrong type")
        inner = [a for a in (typing.get_args(t) or (t,)) if dataclasses.is_dataclass(a)]
        if inner and v is not None:
            sub = inner[0]
            if typing.get_origin(t) is list:
                v = [_typed(sub, x, f"{where}.{f.name}[{i}]") for i, x in enumerate(v)]
            else:
                v = _typed(sub, v, f"{where}.{f.name}")
        out[f.name] = v
    return cls(**out)


def _upgrade_token_exp(raw: list[Any], typed: list[HistoryEntry]) -> None:
    for r, h in zip(raw, typed, strict=True):
        if "token_exp" not in r and not h.detail.endswith("audit record"):
            h.token_exp = UNBOUNDED_EXP
        if "amount_known" not in r and h.amount == 0:
            # 0.1.x booked an amount it never saw as 0; it cannot be told from a real 0,
            # so it is taken as unseen (an amount budget then asks, never undercounts).
            h.amount_known = False


# The OS lock a serving process holds on its state file (`Store.claim`): fcntl on POSIX,
# msvcrt on Windows.
_fcntl: Any = importlib.import_module("fcntl") if importlib.util.find_spec("fcntl") else None
_msvcrt: Any = importlib.import_module("msvcrt") if importlib.util.find_spec("msvcrt") else None


class StateInUse(Exception):
    """Another process holds the state file."""


class Store:
    def __init__(self, path: str | None = None, claim: bool = False) -> None:
        self.lock = threading.RLock()
        # Whether memory holds a change a failed write left off disk, or a request that
        # failed unexpectedly made: until a write succeeds, every request writes, even one
        # that changed nothing itself.
        self.unsaved = False
        # A state file that is a symbolic link (kept on a mounted volume) is the file it
        # points to: written there, and locked there, never replaced by a file of its own.
        self.path = Path(os.path.realpath(path)) if path else None
        self.connections: dict[str, dict[str, Any]] = {}  # "iss|sub" -> info
        self.agents: dict[str, dict[str, Any]] = {}  # "iss|sub|agent" -> bound info
        self.missions: dict[str, Mission] = {}  # "iss|s256"
        self.decisions: dict[str, DecisionRecord] = {}  # "iss|sdi"
        self.events_seen: set[str] = set()  # "iss|id"
        self.pending: dict[str, Pending] = {}
        self.reach: list[Reach] = []
        # The reach rows by person, kept as the table grows; built again when the table is
        # replaced or shrinks (`reach_of`).
        self._reach_table: list[Reach] | None = None
        self._reach_seen = 0
        self._reach_groups: dict[tuple[str, str], list[Reach]] = {}
        self.agent_history: dict[str, list[HistoryEntry]] = {}  # "iss|sub|agent" no-mission acts
        # How far ahead of this SS's clock each PS's clocks run, by PS: the most seen on
        # its signed requests for connected people (`observe_lead`).
        self.leads: dict[str, float] = {}
        self._open = _Index(lambda k, rec: [(rec.iss, rec.sub)])
        self._agents = _Index(lambda k, v: [tuple(k.split("|")[:2])])
        self._missions = _Index(lambda k, m: [(m.iss, m.sub)])
        self._by_code = _Index(lambda k, p: [code_key(p.code)] if p.kind == "connect" else [])
        self._by_sdi = _Index(lambda k, p: [(p.iss, p.sdi)] if p.kind == "clarify" else [])
        self._by_person = _Index(lambda k, p: [(p.iss, _sub_of(p))])
        if claim:
            # Held before it is read: a second SS on the file must not set aside the
            # snapshot of the one that serves from it.
            self.claim()
        if self.path and self.path.exists():
            try:
                self._load()
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
                # A snapshot the SS cannot read is set aside, not fatal: the SS starts empty
                # and answers unknown_sub / unknown_mission until the PS reconnects and
                # replays, which rebuilds missions and outstanding tokens, not everything
                # (the module docstring); `aauth-ss serve` reports it. Named so that two
                # set aside in one second are both kept.
                bad = self.path.with_name(f"{self.path.name}.unreadable-{int(time.time())}-"
                                          f"{secrets.token_hex(4)}")
                os.replace(self.path, bad)
                self.__init__(str(self.path))  # type: ignore[misc]
                self.load_error = f"{type(e).__name__}: {e} (moved to {bad.name})"

    load_error: str = ""
    _claimed: int | None = None  # the descriptor holding the state file's lock

    def claim(self) -> None:
        """Hold the state file for this process. A second SS started on it (a restart
        that overlaps the old process, a second terminal) fails here at once, instead of
        serving from a copy and writing over what the first records. The lock is the OS's,
        on `<state>.lock`, so it goes with the process however that ends."""
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path.with_name(self.path.name + ".lock"), os.O_RDWR | os.O_CREAT,
                     0o600)
        try:
            if _msvcrt is not None:
                _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
            else:
                _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            raise StateInUse(f"{self.path} is in use by another process") from e
        self._claimed = fd

    def release(self) -> None:
        if self._claimed is None:
            return
        if _msvcrt is not None:  # unlocked before the close (msvcrt's own advice)
            os.lseek(self._claimed, 0, os.SEEK_SET)
            _msvcrt.locking(self._claimed, _msvcrt.LK_UNLCK, 1)
        os.close(self._claimed)
        self._claimed = None

    # 2: history entries carry `token_exp`, `n`, `agent` and `amount_known`, records
    # `plain`, reach rows `answer`. A version 1 snapshot is read and migrated (see
    # `_load`); version 1 code refuses a version 2 one.
    VERSION = 2

    # ------------------------------------------------------------ keys
    @staticmethod
    def k(*parts: str) -> str:
        """Composite key. `sub`, `agent` and ids come from the PS, so `|` and `%` inside a
        part are escaped: ("a|b", "c") and ("a", "b|c") must not name the same entry."""
        return "|".join(p.replace("%", "%25").replace("|", "%7C") for p in parts)

    # ------------------------------------------------------------ persistence
    def save(self) -> None:
        if not self.path:
            return
        with self.lock:
            self.unsaved = True
            data = {
                "version": self.VERSION,
                "connections": self.connections,
                "agents": self.agents,
                "missions": {k: asdict(m) for k, m in self.missions.items()},
                "decisions": {k: asdict(d) for k, d in self.decisions.items()},
                "events_seen": sorted(self.events_seen),
                "pending": {k: asdict(p) for k, p in self.pending.items()},
                "reach": [asdict(r) for r in self.reach],
                "agent_history": {k: [asdict(e) for e in v] for k, v in self.agent_history.items()},
                "leads": self.leads,
            }
            # The directory is created if it is not there yet, and the new snapshot is on
            # disk before it replaces the old one, so a crash leaves one or the other whole.
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # The snapshot holds forwarded token claims and mission text, so on POSIX it is
            # created readable by its owner only (Windows ignores the mode bits; there the
            # directory's ACL decides). It is written through a file created anew (O_EXCL)
            # under a name no one can foresee, so never through a file or a link someone
            # left at it, and named after the whole file name, so a state file named
            # `*.tmp` is never its own temporary file.
            tmp = self.path.with_name(f"{self.path.name}.{secrets.token_hex(8)}.tmp")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            try:
                with os.fdopen(os.open(tmp, flags, 0o600), "w", encoding="utf-8") as f:
                    f.write(json.dumps(data))
                    f.flush()
                    os.fsync(f.fileno())
                attempt = 0
                while True:
                    try:
                        os.replace(tmp, self.path)
                        self.unsaved = False
                        break
                    except PermissionError:
                        # Windows refuses to replace a file another process holds open (a
                        # reader, a scanner); that passes in moments, so a few seconds.
                        attempt += 1
                        if attempt == 10:
                            raise
                        time.sleep(0.05 * attempt)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(tmp)
                raise

    def _load(self) -> None:
        assert self.path
        data = json.loads(self.path.read_text(encoding="utf-8"))
        version = data.get("version", 1) if isinstance(data, dict) else None
        if type(version) is not int or version not in (1, self.VERSION):
            raise ValueError(f"snapshot version {version!r}")

        def obj(name: str) -> dict[str, Any]:
            v = data.get(name, {})
            if not isinstance(v, dict):
                raise ValueError(f"{name}: not an object")
            return v

        def strs(name: str) -> set[str]:
            v = data.get(name, [])
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError(f"{name}: not an array of strings")
            return set(v)

        conns, agents = obj("connections"), obj("agents")
        for name, table in (("connections", conns), ("agents", agents)):
            if not all(isinstance(x, dict) for x in table.values()):
                raise ValueError(f"{name}: entries must be objects")
        self.connections, self.agents = conns, agents
        self.missions = {k: _typed(Mission, m, f"missions[{k}]")
                         for k, m in obj("missions").items()}
        self.decisions = {k: _typed(DecisionRecord, d, f"decisions[{k}]")
                          for k, d in obj("decisions").items()}
        self.events_seen = strs("events_seen")
        self.pending = {k: _typed(Pending, p, f"pending[{k}]") for k, p in obj("pending").items()}
        reach = data.get("reach", [])
        if not isinstance(reach, list):
            raise ValueError("reach: not an array")
        self.reach = [_typed(Reach, r, f"reach[{i}]") for i, r in enumerate(reach)]
        self.leads = {}
        for k, v in obj("leads").items():
            f = _finite(v)
            if f is None:
                raise ValueError(f"leads[{k}]: not a finite number")
            self.leads[k] = f
        self.agent_history = {}
        for k, v in obj("agent_history").items():
            if not isinstance(v, list):
                raise ValueError(f"agent_history[{k}]: not an array")
            self.agent_history[k] = [_typed(HistoryEntry, e, f"agent_history[{k}][{i}]")
                                     for i, e in enumerate(v)]
        # Version 1 (0.1.x) kept no `token_exp`. Every act it recorded but an audit record
        # can still take effect: an issued token whose `exp` it never kept, or a permission
        # grant, which has no lifetime. Read as a moment, it would stop counting the instant
        # after the upgrade. An audit record reports an action already taken.
        raw_missions = obj("missions")
        for k, m in self.missions.items():
            _upgrade_token_exp(raw_missions[k].get("history", []), m.history)
        for k, v in obj("agent_history").items():
            _upgrade_token_exp(v, self.agent_history[k])
        if version == 1:
            self._upgrade_order()
        # A decision record still open at the upgrade carries the act it will book when
        # issued: its unseen amount too was booked as 0. Its `token_exp` stays unset, as
        # the token's own `exp` is taken at issuance.
        for k, d in obj("decisions").items():
            e, rec = d.get("entry"), self.decisions[k]
            if isinstance(e, dict) and rec.entry is not None and "amount_known" not in e \
                    and rec.entry.amount == 0:
                rec.entry.amount_known = False
        # Set only on the copies a decision composes over, never stored: a stored one
        # would take an act out of its own budgets or mark it uncertain.
        for where, h in self._stored_entries():
            if h.borrowed or h.open or h.scope:
                raise ValueError(f"{where}: a member only a copy carries")

    def _upgrade_order(self) -> None:
        """Version 1 (0.1.x) kept no order of record, no answer times, and booked every
        report where it arrived. Its entries are numbered in the order a decision reads
        them (`_merged`), so what is recorded since a decision can be told; every act but
        an audit record floats, since 0.1.x judged no report late; a record with no
        position counts from the start; and an answer with no time counts as given now
        (it may have come just before the upgrade), so its token is awaited from now."""
        lists = [m.history for m in self.missions.values()] + list(self.agent_history.values())
        for i, h in enumerate(_merged(lists), 1):
            h.n = i
            h.unplaced = h.unplaced or not h.detail.endswith("audit record")
        self._n_last = None
        now = time.time()
        for rec in self.decisions.values():
            rec.recorded_n = rec.recorded_n or 1
            if rec.decision.startswith("resolved_") and not rec.resolved_at:
                rec.resolved_at = now

    def _stored_entries(self) -> Iterator[tuple[str, HistoryEntry]]:
        for k, m in self.missions.items():
            yield from ((f"missions[{k}]", h) for h in m.history)
        for k, v in self.agent_history.items():
            yield from ((f"agent_history[{k}]", h) for h in v)
        for k, d in self.decisions.items():
            if d.entry is not None:
                yield f"decisions[{k}]", d.entry

    # ------------------------------------------------------------ helpers
    def history_for(self, iss: str, sub: str, agent: str, mission_s256: str) -> list[HistoryEntry]:
        if mission_s256:
            m = self.missions.get(self.k(iss, mission_s256))
            return m.history if m else []
        return self.agent_history.setdefault(self.k(iss, sub, agent), [])

    def add_history(self, hist: list[HistoryEntry], entry: HistoryEntry,
                    agent: str = "") -> None:
        """Append an entry, numbered in the order the SS recorded it, as `agent`'s act."""
        self._n_last = self.recorded_count() + 1
        entry.n = self._n_last
        entry.agent = agent or entry.agent
        hist.append(entry)

    _n_last: int | None = None

    def _all_history(self) -> list[HistoryEntry]:
        out = [h for m in self.missions.values() for h in m.history]
        return out + [h for v in self.agent_history.values() for h in v]

    def composition_history(self, iss: str, sub: str, agent: str, mission_s256: str,
                            exclude_sdi: str = "", now: float | None = None
                            ) -> list[HistoryEntry]:
        """`_recorded_history`, then, when `now` is given, the acts of the same chain the
        SS has answered that are not history yet (`open_acts`), after all of it. Tokens
        held past their `exp` are history first (`_settle_reported`), so this very
        decision counts them, and records settled for good leave the open set before the
        scope is found (`_drop_settled`)."""
        if now is not None:
            self.settle_open(iss, sub, now)
        merged = self._recorded_history(iss, sub, agent, mission_s256)
        if now is None:
            return merged
        opened = self._open_acts(iss, sub, agent, mission_s256, exclude_sdi)
        return merged + opened if opened else merged

    # How long an allowed auth token is awaited before the SS stops counting it: an auth
    # token lives at most one hour (Protocol L1775), and the service caps the `exp` of
    # every auth token it allows directly at the decision plus this (Supervision L508), so
    # a token issued after that is already spent. An ask the person allowed carries no
    # such cap (the SS sends nothing after the answer); it is awaited as long from the
    # answer, on the assumption that a PS issues within that hour.
    OPEN_ISSUANCE = 3600

    # Decision records that may still be open, by person, so `open_acts` walks neither
    # every record the SS has kept nor another person's. A record leaves the index once it
    # is settled for good (time only moves on, and in place a record only moves from open
    # to settled: ask to resolved_*, clarify to expired or abandoned), and re-enters
    # whenever it is stored again (`record_decision`, the one way the service stores a
    # decision).
    _open: _Index

    def record_decision(self, key: str, rec: DecisionRecord) -> None:
        """Store a decision record, new or replacing the one under its sdi; a new one notes
        the history recorded so far (`recorded_n`)."""
        if not rec.recorded_n:
            rec.recorded_n = self.recorded_count() + 1
        self._open.put(self.decisions, key, rec)

    def recorded_count(self) -> int:
        """The number of the last history entry recorded (`HistoryEntry.n`), 0 with none."""
        if self._n_last is None:
            self._n_last = max((h.n for h in self._all_history()), default=0)
        return self._n_last

    def open_records(self, iss: str, sub: str) -> list[str]:
        """The keys of the person's decision records that may still be open, in the order
        they were recorded (an order the snapshot keeps, so a restart does not change it)."""
        keys = self._open.get(self.decisions, (iss, sub))
        return sorted(keys, key=self._open.place.__getitem__)

    def observe_lead(self, iss: str, sub: str, lead: float) -> bool:
        """Note how far ahead of the SS's clock the PS `iss` ran on one of its signed
        requests for the person `sub` (only while they are connected, so a stranger keeps
        nothing): its stamp or its signature, whichever is later, less the SS's clock on
        the request's arrival, which its transit only makes smaller. The most seen across
        the PS's people is kept (a disconnect does not drop it), so it errs only by the
        fastest transit since the PS's clocks last moved forward. True when it grew: a
        change of state."""
        if self.k(iss, sub) not in self.connections:
            return False
        if iss in self.leads and lead <= self.leads[iss]:
            return False
        self.leads[iss] = lead
        return True

    def lead_of(self, iss: str) -> float | None:
        """The most the PS `iss` was seen ahead (`observe_lead`), None before any."""
        return self.leads.get(iss)

    def latest_since(self, iss: str, sub: str, n0: int) -> float:
        """The latest PS stamp (`iat`, else `at`) among the person's acts recorded anywhere
        with a number from `n0` on; -inf with none."""
        return self.stamped_since(iss, sub, n0, math.inf)[1]

    def stamped_since(self, iss: str, sub: str, n0: int, iat: float) -> tuple[int, float]:
        """Among the person's acts recorded anywhere with a number from `n0` on: the
        lowest number of one the PS stamped (`iat`, else `at`) no earlier than `iat` (0
        with none), and the latest stamp (-inf with none)."""
        lists = [m.history for m in self.missions_of(iss, sub)] + [
            self.agent_history.get(self.k(iss, sub, a), []) for a in self._agents_outside(iss, sub)]
        first, latest = 0, -math.inf
        for hist in lists:
            for h in hist:
                if h.n >= n0:
                    t = float(h.iat or h.at)
                    latest = max(latest, t)
                    if t >= iat and (not first or h.n < first):
                        first = h.n
        return first, latest

    def settle_open(self, iss: str, sub: str, now: float) -> None:
        """Bring the person's open records up to `now` before they are read: tokens held
        past their `exp` become history, and records settled for good leave the open set,
        so what is read does not depend on which earlier request looked, nor on a
        restart."""
        self._settle_reported(iss, sub, now)
        self._drop_settled(iss, sub, now)

    def _settle_reported(self, iss: str, sub: str, now: float) -> None:
        """A token reported before its approval that no approval booked, past its `exp`:
        no longer usable, but issued all the same, a fact outside missions."""
        for key in self.open_records(iss, sub):
            rec = self.decisions[key]
            if rec.decision == "reported" and rec.entry is not None and (
                    rec.entry.token_exp is not None and now >= rec.entry.token_exp + EXP_SKEW):
                rec.entry.unplaced = True  # booked now, after acts it may have preceded
                self.add_history(self.history_for(iss, sub, rec.agent, ""), rec.entry,
                                 rec.agent)
                rec.entry = None
                self._open.drop((iss, sub), key)

    def _drop_settled(self, iss: str, sub: str, now: float) -> None:
        """Take out of the open set every record of the person settled for good, whatever
        the decision at hand: a record whose act is no longer open, an allowed token whose
        window is over, an act of a mission past its end, a question that is over, an act
        already history. The open acts that widen a scope (`_open_links`) are then the
        same for every decision, and the same after a restart, which indexes every record
        again."""
        seen: dict[tuple[str, str], set[str]] = {}
        for key in self.open_records(iss, sub):
            rec = self.decisions[key]
            if rec.entry is None or rec.decision not in _OPEN_KINDS or (
                    rec.decision != "ask" and rec.decision != "clarify"
                    and rec.act not in ("auth_token", "person_token")):
                self._open.drop((iss, sub), key)  # settled for good
                continue
            if rec.decision in ("allow", "resolved_allow"):
                # Awaited from the decision, or from the person's answer for an ask. A
                # direct allow caps the token's `exp` at the decision plus OPEN_ISSUANCE
                # (the service sends it, Supervision L508), so a token issued later is
                # spent on issue, up to the usable margin past its `exp`.
                # A token an approval issues lives up to an hour more (Protocol L863), and
                # is booked only when `approved` is reported.
                life = self.OPEN_ISSUANCE + (
                    PERSON_TOKEN_LIFE if self._of_proposal(iss, rec) is not None else 0)
                over = now >= max(rec.entry.at, rec.resolved_at) + life + EXP_SKEW
                if over and not self._awaits_answer(iss, rec):
                    self._open.drop((iss, sub), key)  # its window is over, for good
                    continue
            if rec.mission_s256:
                # A PS treats a mission past its `expires_at` as terminated on every path
                # and caps every token it issues under it there (Protocol L1425, L768), so
                # nothing still open in it can take effect past that, plus the margin.
                m_open = self.missions.get(self.k(iss, rec.mission_s256))
                end = iso_to_epoch(m_open.blob.get("expires_at")) if m_open else None
                if end is not None and now >= end + EXP_SKEW:
                    self._open.drop((iss, sub), key)
                    continue
            if rec.decision == "clarify":
                q = self.pending_by_sdi(iss, rec.sdi)
                if q is not None and (q.cancelled or q.resolved is not None or (
                        q.deadline and now >= q.deadline)):
                    self._open.drop((iss, sub), key)  # the question is over, for good
                    self.settle(q)
                    continue
            # Already history: the act is recorded where its own history is kept.
            where = (rec.agent, rec.mission_s256)
            if where not in seen:
                m_rec = self.missions.get(self.k(iss, rec.mission_s256)) \
                    if rec.mission_s256 else None
                hist = m_rec.history if m_rec is not None else \
                    self.agent_history.get(self.k(iss, sub, rec.agent), [])
                seen[where] = {h.sdi for h in hist if h.sdi}
            if rec.sdi in seen[where]:
                self._open.drop((iss, sub), key)  # history now, for good

    def _of_proposal(self, iss: str, rec: DecisionRecord) -> DecisionRecord | None:
        """The proposal whose approval would issue the token `rec` stands for, if it is
        one (an approval token, under the proposal's sdi)."""
        prop = self.decisions.get(self.k(iss, rec.sdi))
        if rec.act == "person_token" and prop is not None and prop.act == "mission_proposal":
            return prop
        return None

    def _awaits_answer(self, iss: str, rec: DecisionRecord) -> bool:
        """Whether `rec` is a token an approval would issue whose proposal the person has
        not answered yet: it cannot be issued before the answer, which opens its window
        again (`decision.resolved`), so the wait so far does not end it."""
        prop = self._of_proposal(iss, rec)
        return prop is not None and prop.decision == "ask"

    def open_acts(self, iss: str, sub: str, agent: str, mission_s256: str,
                  exclude_sdi: str, now: float) -> list[HistoryEntry]:
        """Acts the SS has answered that are not history yet: an act the person is still
        deciding (`ask`), an act whose clarification is still open, and a token allowed
        (an auth token, or a person token that is an act) whose issuance is not reported
        yet (awaited `OPEN_ISSUANCE` seconds).

        Supervision L211 orders event delivery by when acts occur, so a request of the
        same chain can legitimately arrive while one of these is open. Decided without
        them, it could complete a composition the person never sees. Each is returned as
        an uncertain, borrowed copy (`open` set) with no known end, that may take effect
        from now on (an allowed token from its allow or the person's answer on,
        `after_n`): it can only make a later act be asked, never denied, and it spends
        no budget. They are looked for in the whole scope `_recorded_history` composes
        over (`_scope`), its certain and its uncertain parts alike. Records settled for
        good leave the open set first (`_drop_settled`)."""
        self._drop_settled(iss, sub, now)
        return self._open_acts(iss, sub, agent, mission_s256, exclude_sdi)

    def _open_acts(self, iss: str, sub: str, agent: str, mission_s256: str,
                   exclude_sdi: str) -> list[HistoryEntry]:
        """`open_acts`, over an open set `_drop_settled` has just cleared."""
        chain, mine, elsewhere, kin = self._scope(iss, sub, agent, mission_s256)
        agents = chain | kin
        missions = {m.s256 for m in mine + elsewhere}
        out: list[HistoryEntry] = []
        for key in self.open_records(iss, sub):
            rec = self.decisions[key]
            if rec.entry is None or rec.sdi == exclude_sdi:
                continue
            if rec.mission_s256:
                if rec.mission_s256 not in missions:
                    continue
            elif rec.agent not in agents:
                continue
            if rec.decision == "clarify" and self.pending_by_sdi(iss, rec.sdi) is None:
                continue
            own = rec.mission_s256 == mission_s256 and (bool(mission_s256) or rec.agent == agent)
            e = dataclasses.replace(
                rec.entry, sdi=rec.sdi, borrowed=True, token_exp=UNBOUNDED_EXP,
                agent=rec.agent, scope="" if mission_s256 else rec.mission_s256,
                open="own" if own else "other",
                detail=f"uncertain: {rec.decision} not yet settled: {rec.entry.detail}")
            if rec.decision in ("allow", "resolved_allow"):
                # A token allowed may be issued at any moment from the allow (the person's
                # answer, for an ask): reported out of the order Supervision L211 asks for,
                # it may have been used before acts recorded since, not only from now on.
                e.unplaced = True
                e.after_n = max(e.after_n, rec.resolved_n or rec.recorded_n)
            out.append(e)
        return out

    def _recorded_history(self, iss: str, sub: str, agent: str,
                          mission_s256: str) -> list[HistoryEntry]:
        """What a decision composes over: the act's own history, plus the acts of the
        rest of its scope (`_scope`). Certain: the chain's acts outside missions and, for
        an act outside missions, each mission of its agent, marked with that mission
        (`scope`) and composed with the act separately as well. Uncertain: the person's
        other missions of the chain or its provider (`open` "mission": this SS approves
        missions by policy, so a second mission is not the person's approval, and a token
        outlives its mission's end), and the provider's other agents' acts outside
        missions (`open` "agent": every agent instance has its own identifier, Protocol
        L167, and instances of the provider an `aauth:local@domain` identifier names, L488,
        may share what they read). Borrowed entries are copies marked `borrowed`, merged
        in recorded order."""
        own = self.history_for(iss, sub, agent, mission_s256)
        chain, mine, elsewhere, kin = self._scope(iss, sub, agent, mission_s256)
        # Inside a mission, `own` is the mission's history and every agent of the chain is
        # borrowed from outside missions; outside missions, `own` is the agent's acts there.
        borrowed = sorted(chain if mission_s256 else chain - {agent})
        lists = [own] + [[_copy(h, borrowed=True) for h in
                          self.agent_history.get(self.k(iss, sub, a), [])] for a in borrowed]
        if not mission_s256:
            lists += [[_copy(h, borrowed=True, scope=m.s256) for h in m.history] for m in mine]
        lists += [[elsewhere_copy(h, o.s256) for h in o.history] for o in elsewhere]
        providers = {provider(a) for a in chain} - {""}
        lists += [[kin_copy(h, a, linked=provider(a) not in providers)
                   for h in self.agent_history.get(self.k(iss, sub, a), [])]
                  for a in sorted(kin)]
        if all(not o for o in lists[1:]):
            return own
        return _merged(lists)

    def _scope(self, iss: str, sub: str, agent: str, mission_s256: str
               ) -> tuple[set[str], list[Mission], list[Mission], set[str]]:
        """Who and what an act of `agent` (in `mission_s256`, or outside missions)
        composes with. `mine`: the missions whose acts compose certainly (the act's own
        mission; outside missions, every mission the agent owns or has acted in). `chain`:
        the agent and the agents of `mine` (its owners, and every agent with history in it:
        a call chain acts under the upstream mission), whose acts outside missions compose
        certainly. `kin`: the person's other agents from the provider of an agent of the
        chain; `elsewhere`: the person's other missions an agent of the chain or of `kin`
        owns or has acted in. Both compose as uncertain.

        An act the SS answered that is not history yet (an open record) counts wherever it
        would once recorded (Supervision L211): the scope is found again with every open
        act taken as history, and whatever that adds composes as uncertain. Recording an
        open act so never narrows the scope; it only makes part of it certain."""
        person = self.missions_of(iss, sub)
        chain, mine, elsewhere, kin = self._reach(iss, sub, agent, mission_s256, person,
                                                  {}, set())
        linked, opened = self._open_links(iss, sub)
        if not opened:
            return chain, mine, elsewhere, kin
        o_chain, o_mine, o_elsewhere, o_kin = self._reach(iss, sub, agent, mission_s256,
                                                          person, linked, opened)
        taken = {m.s256 for m in mine}
        more = {m.s256 for m in o_mine + o_elsewhere + elsewhere}
        return (chain, mine, [m for m in person if m.s256 not in taken and m.s256 in more],
                (kin | o_chain | o_kin) - chain)

    def _reach(self, iss: str, sub: str, agent: str, mission_s256: str,
               person: list[Mission], linked: dict[str, set[str]], opened: set[str]
               ) -> tuple[set[str], list[Mission], list[Mission], set[str]]:
        """`_scope`'s sets over the acts recorded, and the open acts given: `linked`, the
        agents with one in each mission, and `opened`, all of their agents."""
        def agents_of(m: Mission) -> set[str]:
            return {m.agent} | {h.agent for h in m.history if h.agent} | linked.get(
                m.s256, set())

        if mission_s256:
            mine = [m for m in person if m.s256 == mission_s256]
        else:
            mine = [m for m in person if agent in agents_of(m)]
        chain = {agent}.union(*(agents_of(m) for m in mine))
        kin = self._same_provider(iss, sub, chain, opened)
        near = chain | kin
        taken = {m.s256 for m in mine}  # one lookup per mission, not a scan of `mine`
        elsewhere = [m for m in person if m.s256 not in taken and agents_of(m) & near]
        return chain, mine, elsewhere, kin

    def _open_links(self, iss: str, sub: str) -> tuple[dict[str, set[str]], set[str]]:
        """The agents with an act the SS answered that is not history yet (an open record):
        by mission, for those in one, and all of them."""
        out: dict[str, set[str]] = {}
        agents: set[str] = set()
        for key in self.open_records(iss, sub):
            rec = self.decisions[key]
            if rec.entry is not None and rec.decision in _OPEN_KINDS:
                agents.add(rec.agent)
                if rec.mission_s256:
                    out.setdefault(rec.mission_s256, set()).add(rec.agent)
        return out, agents

    def _same_provider(self, iss: str, sub: str, chain: set[str],
                       opened: set[str]) -> set[str]:
        """The person's agents, outside `chain`, from the provider of an agent in it: those
        the SS has recorded, and those with an act not history yet (`opened`)."""
        providers = {provider(a) for a in chain} - {""}
        if not providers:
            return set()
        mine = self.missions_of(iss, sub)
        agents = self._agents_outside(iss, sub).union(
            opened, *({m.agent} | {h.agent for h in m.history} for m in mine))
        return {a for a in agents if provider(a) in providers} - chain

    # The agents with a history outside missions, by person, so that a decision does not
    # read every person's keys.
    _agents: _Index

    def _agents_outside(self, iss: str, sub: str) -> set[str]:
        return {_unescape(k.rpartition("|")[2]) for k in self._agents.get(
            self.agent_history, tuple(self.k(iss, sub).split("|")))}

    # Missions by person: every decision reads its person's missions only.
    _missions: _Index

    def add_mission(self, key: str, m: Mission) -> None:
        self._missions.put(self.missions, key, m)

    def missions_of(self, iss: str, sub: str) -> list[Mission]:
        return [self.missions[k] for k in self._missions.get(self.missions, (iss, sub))]

    # Pending records by what finds them: a connect by its interaction code, a
    # clarification by its sdi, and either by its person.
    _by_code: _Index
    _by_sdi: _Index
    _by_person: _Index

    def add_pending(self, p: Pending) -> None:
        for index in (self._by_code, self._by_sdi, self._by_person):
            index.sync(self.pending)
        self._by_code.put(self.pending, p.id, p)
        self._by_sdi.note(self.pending, p.id, p)
        self._by_person.note(self.pending, p.id, p)

    # Each lookup checks what it finds: a record replaced under its id is indexed under
    # what it is now, and is no longer found under what it was.
    def pending_by_code(self, code: str) -> Pending | None:
        want = code_key(code)
        return next((p for k in reversed(self._by_code.get(self.pending, want))
                     if (p := self.pending[k]).kind == "connect" and code_key(p.code) == want),
                    None)

    def pending_by_sdi(self, iss: str, sdi: str) -> Pending | None:
        return next((p for k in reversed(self._by_sdi.get(self.pending, (iss, sdi)))
                     if (p := self.pending[k]).kind == "clarify" and (p.iss, p.sdi) == (iss, sdi)),
                    None)

    def pendings_of(self, iss: str, sub: str) -> list[Pending]:
        return [p for k in self._by_person.get(self.pending, (iss, sub))
                if (p := self.pending[k]).iss == iss and _sub_of(p) == sub]

    def reach_of(self, iss: str, sub: str) -> list[Reach]:
        """The person's reach rows, in the table's order, without a walk of the table."""
        if self._reach_table is not self.reach or len(self.reach) < self._reach_seen:
            self._reach_table, self._reach_seen, self._reach_groups = self.reach, 0, {}
        for r in itertools.islice(self.reach, self._reach_seen, None):
            self._reach_groups.setdefault((r.iss, r.sub), []).append(r)
        self._reach_seen = len(self.reach)
        return self._reach_groups.get((iss, sub), [])

    def drop_pendings(self, ids: list[str]) -> None:
        """Remove pending records for good, with the event keys that opened them; the
        indexes are built again at their next use. (A table that shrank is indexed again
        anyway, `_Index.sync`; this also covers one written to directly in between.)"""
        for i in ids:
            p = self.pending.pop(i)
            self.events_seen.discard(p.once)
        for index in (self._by_code, self._by_sdi, self._by_person):
            index.of = None

    def settle(self, p: Pending) -> None:
        """A pending record that is over keeps no request: its URL answers from the
        record's state alone (410, or the stored terminal response). The person it was
        for is kept: a URL is answered for its own person only."""
        p.sub = _sub_of(p)
        p.request = {}


def provider(agent: str) -> str:
    """The agent provider's domain in an agent identifier `aauth:local@domain` (Protocol
    L488), in lower case; "" for an identifier of any other form, which has no provider
    another agent could share."""
    if not agent.startswith("aauth:"):
        return ""
    local, _, domain = agent[len("aauth:"):].partition("@")
    return domain.lower() if local else ""


def _unescape(part: str) -> str:
    """One part of a `Store.k` key, as it was before `k` escaped it."""
    return part.replace("%7C", "|").replace("%25", "%")


def _finite(v: Any) -> float | None:
    """`v` as a finite float, None if it is not a number that is one (a bool, a string, an
    integer past the float range, infinity, NaN)."""
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return None
    try:
        f = float(v)
    except OverflowError:
        return None
    return f if math.isfinite(f) else None


def kin_copy(h: HistoryEntry, agent: str, linked: bool = False) -> HistoryEntry:
    """An act outside missions of another agent of the same provider, or (`linked`) of one
    an act not settled yet links to the decided act's chain, as it composes with the
    decided act: borrowed, uncertain, asked about, never denied, spending no budget."""
    return _copy(h, borrowed=True, scope=f"agent:{agent}", open="link" if linked else "agent",
                 detail="uncertain: of another agent: " + h.detail)


def elsewhere_copy(h: HistoryEntry, s256: str) -> HistoryEntry:
    """An act of another mission, as it composes with an act of the decided act's chain:
    borrowed, marked with its mission, and uncertain, so it can make the act be asked,
    never denied, and spends none of the decided act's budgets."""
    return _copy(h, borrowed=True, scope=s256, open="mission",
                 detail="uncertain: in another mission: " + h.detail)


def _sub_of(p: Pending) -> str:
    """The person a pending record is for (a record older than `sub` names it only in
    its request)."""
    return p.sub or str(p.request.get("sub") or "")


def code_key(code: str) -> str:
    """An interaction code as core Interaction Code Format compares it: hyphens dropped,
    case ignored, I and L read as 1 and O as 0."""
    return code.replace("-", "").upper().translate(_CODE_READING)


_CODE_READING = str.maketrans("ILO", "110")


class _Index:
    """The keys of a table grouped by what finds them, kept as the table grows.

    A table is only ever added to. `put` adds and indexes in one step; `sync` catches up,
    in insertion order, with additions made directly on the table; a table that is not
    the one indexed (a snapshot loaded) or that shrank is indexed again from scratch."""

    def __init__(self, groups_of: Any) -> None:
        self.groups_of = groups_of
        self.of: dict[str, Any] | None = None
        self.seen = 0
        # Each group is a dict used as an ordered set: insertion order, O(1) to add or drop.
        self.groups: dict[Any, dict[str, None]] = {}
        # Each key's place in the table, kept when it is dropped and added again, so an
        # order read back by place is the one a restart (which reads the table) gives.
        self.place: dict[str, int] = {}

    def sync(self, table: dict[str, Any]) -> None:
        if self.of is not table or len(table) < self.seen:
            self.of, self.seen, self.groups, self.place = table, 0, {}, {}
        if len(table) > self.seen:
            for k in itertools.islice(table, self.seen, None):
                self._add(k, table[k])
            self.seen = len(table)

    def _add(self, k: str, v: Any) -> None:
        self.place.setdefault(k, len(self.place))
        for g in self.groups_of(k, v):
            self.groups.setdefault(g, {})[k] = None

    def put(self, table: dict[str, Any], k: str, v: Any) -> None:
        self.sync(table)
        new = k not in table
        table[k] = v
        self._add(k, v)
        self.seen += new

    def note(self, table: dict[str, Any], k: str, v: Any) -> None:
        """Index a key `put` (through another index) has just added to the table."""
        self._add(k, v)
        self.seen = len(table)

    def get(self, table: dict[str, Any], g: Any) -> dict[str, None]:
        self.sync(table)
        return self.groups.get(g, {})

    def drop(self, g: Any, k: str) -> None:
        self.groups.get(g, {}).pop(k, None)


def _copy(h: HistoryEntry, **changes: Any) -> HistoryEntry:
    """`dataclasses.replace` for a history entry, without its per-call walk of the
    fields: a decision copies every entry of the agent's other missions, and that walk was
    most of its cost. `HistoryEntry` has no `__post_init__` and no `init=False` field, so
    the copy is the same object `replace` would build."""
    c = object.__new__(HistoryEntry)
    c.__dict__.update(h.__dict__, **changes)
    return c


def _merged(lists: list[list[HistoryEntry]]) -> list[HistoryEntry]:
    """History lists merged in recorded order (unnumbered entries first, by time)."""
    return list(heapq.merge(*lists, key=lambda h: (h.n, h.at if h.n == 0 else 0)))
