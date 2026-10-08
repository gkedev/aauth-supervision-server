"""SS state: connections, missions, decisions, pending requests, history and reach.

Everything the SS holds can be rebuilt by PS replay (Supervision, Replay and
Recovery), so the store is in-memory with an optional JSON snapshot.
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import time
import types
import typing
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class HistoryEntry:
    """One act the SS knows happened, as composition state."""

    action_class: str
    resource: str
    provenance: str  # "resource" | "agent" | "configured" | "replay"
    sdi: str = ""
    at: int = 0
    amount: int = 0
    detail: str = ""
    # AAuth Budgets. When the resource token carried a `budget` offer, the act's allocation
    # at that resource: `unit` is "<unit>/<decimals>" (compared exactly, never converted),
    # `allocated` the offer the PS may have granted in full, `jti` the auth token that
    # carries it (from `auth_token.issued`), and `consumed` the latest resource-signed
    # `budget_consumed` for that token. Until a figure arrives the allocation counts as
    # fully consumed (Budgets, Unreported Allocations).
    unit: str = ""
    allocated: int = 0
    jti: str = ""
    consumed: int | None = None


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
    # When an unanswered clarification times out (epoch seconds); 0 means it does not.
    deadline: float = 0.0


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


def _typed(cls: Any, d: Any, where: str) -> Any:
    """Build a dataclass from snapshot JSON, refusing a member of the wrong type, so a
    damaged snapshot is set aside at load instead of failing a later request."""
    if not isinstance(d, dict):
        raise ValueError(f"{where}: not an object")
    hints = typing.get_type_hints(cls)
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


class Store:
    def __init__(self, path: str | None = None) -> None:
        self.lock = threading.RLock()
        self.path = Path(path) if path else None
        self.connections: dict[str, dict[str, Any]] = {}  # "iss|sub" -> info
        self.agents: dict[str, dict[str, Any]] = {}  # "iss|sub|agent" -> bound info
        self.missions: dict[str, Mission] = {}  # "iss|s256"
        self.decisions: dict[str, DecisionRecord] = {}  # "iss|sdi"
        self.events_seen: set[str] = set()  # "iss|id"
        self.pending: dict[str, Pending] = {}
        self.reach: list[Reach] = []
        self.agent_history: dict[str, list[HistoryEntry]] = {}  # "iss|sub|agent" no-mission acts
        self.revoked: set[str] = set()
        if self.path and self.path.exists():
            try:
                self._load()
            except (ValueError, TypeError, KeyError, AttributeError) as e:
                # Everything here is rebuilt by PS replay (Replay and Recovery), so a snapshot
                # the SS cannot read is set aside, not fatal: the SS starts empty and answers
                # unknown_sub / unknown_mission until the PS replays.
                bad = self.path.with_name(f"{self.path.name}.unreadable-{int(time.time())}")
                os.replace(self.path, bad)
                self.__init__(str(self.path))  # type: ignore[misc]
                self.load_error = f"{type(e).__name__}: {e} (moved to {bad.name})"

    load_error: str = ""
    VERSION = 1

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
                "revoked": sorted(self.revoked),
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, self.path)

    def _load(self) -> None:
        assert self.path
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version", 1) != self.VERSION:
            raise ValueError(f"snapshot version {data.get('version') if isinstance(data, dict) else None!r}")

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
        self.agent_history = {}
        for k, v in obj("agent_history").items():
            if not isinstance(v, list):
                raise ValueError(f"agent_history[{k}]: not an array")
            self.agent_history[k] = [_typed(HistoryEntry, e, f"agent_history[{k}][{i}]")
                                     for i, e in enumerate(v)]
        self.revoked = strs("revoked")

    # ------------------------------------------------------------ helpers
    def history_for(self, iss: str, sub: str, agent: str, mission_s256: str) -> list[HistoryEntry]:
        if mission_s256:
            m = self.missions.get(self.k(iss, mission_s256))
            return m.history if m else []
        return self.agent_history.setdefault(self.k(iss, sub, agent), [])
