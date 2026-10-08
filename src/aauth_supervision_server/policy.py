"""Deterministic APC policy for an AAuth Supervision Server.

The policy implements the Bounded Agents (Agentic Principal Chain) authorization
model on top of what Supervision -00 gives an SS:

  * Classification: each act is mapped to a semantic action class by ordered,
    declarative rules over the resource, operation, scope, tool, and (when the
    PS forwards them) the resource-asserted R3 `parameters` and `result`.
  * Provenance: every classification records where its evidence came from:
    `resource` (R3 proposal forwarded by the PS), `configured` (resource identity
    only), `agent` (justification, permission parameters, audit records) or
    `replay`. Agent-asserted evidence can only make a class more severe, never
    less (a compromised agent cannot talk its way down).
  * Composition closure: prohibited pairs and ordered sequences of classes over
    the mission history. A violation established on certain evidence is denied;
    one that depends on uncertain evidence is put to the person (`ask`).
  * Budgets: per-mission ceilings on count and amount per class.
  * Intent: resources and tools outside the approved mission are asked.
  * Reach: the person's earlier answers (`apply`) turn matching asks into allows,
    but never override a deny, and override a composition only if the answer was
    given for that composition.

No model is consulted. The same inputs always give the same decision.
"""

from __future__ import annotations

import fnmatch
import math
import re
import time
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any, Protocol, runtime_checkable

from .store import HistoryEntry, Mission, Reach

# ------------------------------------------------------------------ config


@dataclass
class Rule:
    cls: str
    resource: str = "*"
    operation: str | None = None
    scope: str | None = None
    tool: str | None = None
    result_contains_any: list[str] | None = None
    param_domain_not_in: dict[str, list[str]] | None = None
    param_gt: dict[str, int] | None = None
    amount_param: str | None = None
    if_unknown: str | None = None

    @property
    def needs_data(self) -> bool:
        return bool(self.result_contains_any or self.param_domain_not_in or self.param_gt)


@dataclass
class Budget:
    max_count: int | None = None
    max_amount: int | None = None


@dataclass
class ResourceBudget:
    """The person's ceiling at one metered resource, per mission (AAuth Budgets).

    In the resource's own `unit` and `decimals`: Budgets has the resource denominate, and
    a figure in another scale is never converted, only refused as incomparable."""

    unit: str
    decimals: int
    max_amount: int

    @property
    def denomination(self) -> str:
        return f"{self.unit}/{self.decimals}"


@dataclass
class PolicyConfig:
    severity: list[str] = field(default_factory=list)  # least -> most severe
    high_impact: set[str] = field(default_factory=set)
    rules: list[Rule] = field(default_factory=list)
    prohibited_pairs: list[tuple[str, str]] = field(default_factory=list)
    prohibited_sequences: list[tuple[str, ...]] = field(default_factory=list)
    budgets: dict[str, Budget] = field(default_factory=dict)
    # AAuth Budgets: per-mission ceilings at metered resources, keyed by the resource's
    # server identifier. Checked against the `budget` offers and `budget_consumed` records
    # the resource puts in its resource tokens.
    resource_budgets: dict[str, ResourceBudget] = field(default_factory=dict)
    deny_resources: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=lambda: ["*"])
    ask_tools: list[str] = field(default_factory=list)
    allow_unlisted_resources: bool = False
    clarify_missing_justification: bool = False
    max_mission_seconds: int | None = None
    default_class: str = "unclassified"
    ask_on_mission_update: bool = False
    composition_on_certain: str = "deny"  # deny | ask
    # Non-spec extension (AAuth #256): the request member carrying the resource-asserted R3
    # proposal. None (the default) is spec-only Supervision -00: the member is ignored.
    r3_member: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyConfig:
        """Build a config from its JSON form. A malformed file raises ValueError naming the
        member; nothing is silently ignored, because a misspelt key in a security policy
        (`high_imapct`) would otherwise quietly drop a protection."""
        _check_policy_shape(d)
        rules = []
        for r in d.get("rules", []):
            r = dict(r)
            r["cls"] = r.pop("class")
            rules.append(Rule(**r))
        return cls(
            severity=list(d.get("severity", [])),
            high_impact=set(d.get("high_impact", [])),
            rules=rules,
            prohibited_pairs=[tuple(p) for p in d.get("prohibited_pairs", [])],  # type: ignore[misc]
            prohibited_sequences=[tuple(s) for s in d.get("prohibited_sequences", [])],
            budgets={k: Budget(**v) for k, v in d.get("budgets", {}).items()},
            resource_budgets={k: ResourceBudget(**v)
                              for k, v in d.get("resource_budgets", {}).items()},
            deny_resources=list(d.get("deny_resources", [])),
            allowed_tools=list(d.get("allowed_tools", ["*"])),
            ask_tools=list(d.get("ask_tools", [])),
            allow_unlisted_resources=bool(d.get("allow_unlisted_resources", False)),
            clarify_missing_justification=bool(d.get("clarify_missing_justification", False)),
            max_mission_seconds=d.get("max_mission_seconds"),
            default_class=d.get("default_class", "unclassified"),
            ask_on_mission_update=bool(d.get("ask_on_mission_update", False)),
            composition_on_certain=d.get("composition_on_certain", "deny"),
            r3_member=d.get("r3_member"),
        )

    def rank(self, cls: str) -> int:
        return self.severity.index(cls) if cls in self.severity else -1


# Core, Server Identifiers: a lowercase https host (A-labels for IDNs), and nothing else.
SERVER_ID = re.compile(r"https://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*")


def _is_str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


_RULE_STR = ("class", "resource", "operation", "scope", "tool", "amount_param", "if_unknown")
_TOP_STR_LISTS = ("severity", "high_impact", "deny_resources", "allowed_tools", "ask_tools")
_TOP_BOOLS = ("allow_unlisted_resources", "clarify_missing_justification",
              "ask_on_mission_update")
_TOP_KEYS = frozenset(_TOP_STR_LISTS + _TOP_BOOLS + (
    "rules", "prohibited_pairs", "prohibited_sequences", "budgets", "resource_budgets",
    "max_mission_seconds",
    "default_class", "composition_on_certain", "r3_member"))


def _check_policy_shape(d: Any) -> None:
    def bad(where: str, what: str) -> None:
        raise ValueError(f"{where}: {what}")

    if not isinstance(d, dict):
        bad("policy", "must be a JSON object")
    for k in d:
        if k not in _TOP_KEYS:
            bad(k, "unknown member")
    for k in _TOP_STR_LISTS:
        if k in d and not _is_str_list(d[k]):
            bad(k, "must be an array of strings")
    for k in _TOP_BOOLS:
        if k in d and not isinstance(d[k], bool):
            bad(k, "must be true or false")
    for k in ("default_class", "composition_on_certain"):
        if k in d and not (isinstance(d[k], str) and d[k]):
            bad(k, "must be a non-empty string")
    if d.get("r3_member") is not None and not (isinstance(d["r3_member"], str)
                                               and d["r3_member"]):
        bad("r3_member", "must be a non-empty string or null (null: spec-only, extension off)")
    if "max_mission_seconds" in d and d["max_mission_seconds"] is not None and not (
            _is_count(d["max_mission_seconds"]) and d["max_mission_seconds"] > 0):
        bad("max_mission_seconds", "must be a positive integer")
    rules = d.get("rules", [])
    if not isinstance(rules, list):
        bad("rules", "must be an array")
    for i, r in enumerate(rules):
        w = f"rules[{i}]"
        if not isinstance(r, dict):
            bad(w, "must be an object")
        if not isinstance(r.get("class"), str) or not r["class"]:
            bad(w, "needs a non-empty string `class`")
        for k, v in r.items():
            if k in _RULE_STR:
                if not isinstance(v, str):
                    bad(f"{w}.{k}", "must be a string")
            elif k == "result_contains_any":
                if not _is_str_list(v) or not v:
                    bad(f"{w}.{k}", "must be a non-empty array of strings")
            elif k == "param_domain_not_in":
                if not isinstance(v, dict) or not v or not all(
                        isinstance(p, str) and _is_str_list(x) for p, x in v.items()):
                    bad(f"{w}.{k}", "must map parameter names to arrays of domains")
            elif k == "param_gt":
                if not isinstance(v, dict) or not v or not all(
                        isinstance(p, str) and isinstance(x, int | float)
                        and not isinstance(x, bool) for p, x in v.items()):
                    bad(f"{w}.{k}", "must map parameter names to numbers")
            else:
                bad(f"{w}.{k}", "unknown member")
    for k, n in (("prohibited_pairs", 2), ("prohibited_sequences", 0)):
        v = d.get(k, [])
        if not isinstance(v, list) or not all(_is_str_list(x) for x in v):
            bad(k, "must be an array of arrays of class names")
        if n and any(len(x) != n for x in v):
            bad(k, f"each entry must name exactly {n} classes")
        if not n and any(len(x) < 2 for x in v):
            # A sequence is "these classes, in this order"; fewer than two is not a
            # sequence, and evaluating one would fail on every decision.
            bad(k, "each entry must name at least 2 classes")
    budgets = d.get("budgets", {})
    if not isinstance(budgets, dict):
        bad("budgets", "must be an object keyed by class")
    for c, b in budgets.items():
        if not isinstance(b, dict) or not b:
            bad(f"budgets.{c}", "must be an object with max_count and/or max_amount")
        for k, v in b.items():
            if k not in ("max_count", "max_amount"):
                bad(f"budgets.{c}.{k}", "unknown member")
            if not _is_count(v):
                bad(f"budgets.{c}.{k}", "must be a non-negative integer")
    rbs = d.get("resource_budgets", {})
    if not isinstance(rbs, dict):
        bad("resource_budgets", "must be an object keyed by resource identifier")
    for res, rb in rbs.items():
        w = f"resource_budgets.{res}"
        if not SERVER_ID.fullmatch(res):
            bad(w, "the key must be a server identifier (lowercase https host)")
        if not isinstance(rb, dict) or set(rb) != {"unit", "decimals", "max_amount"}:
            bad(w, "must be an object with exactly unit, decimals and max_amount")
        if not isinstance(rb["unit"], str) or not rb["unit"]:
            bad(f"{w}.unit", "must be a non-empty string")
        for k in ("decimals", "max_amount"):
            if not _is_count(rb[k]):
                bad(f"{w}.{k}", "must be a non-negative integer")


# ------------------------------------------------------------------ acts


@dataclass
class Act:
    """An act normalized from a supervision request."""

    act: str  # auth_token | permission | person_token
    iss: str
    sub: str
    agent: str
    mission_s256: str = ""
    resource: str = ""
    operations: list[str] = field(default_factory=list)
    scope: str = ""
    tool: str = ""
    parameters: dict[str, Any] | None = None
    parameters_provenance: str = ""  # resource | agent
    result: dict[str, Any] | None = None
    justification: str = ""
    # AAuth Budgets, from the forwarded resource token: the resource's `budget` offer as
    # "<unit>/<decimals>" and `amount`, and its `budget_consumed` record, if any.
    budget_unit: str = ""
    budget_amount: int | None = None
    consumed_jti: str = ""
    consumed: int | None = None


@dataclass
class Classification:
    cls: str
    provenance: str
    uncertain: bool
    amount: int | None = None
    detail: str = ""


@dataclass
class Decision:
    decision: str  # allow | deny | ask | clarify
    reason: str = ""
    summary: str = ""
    recommendation: str = ""
    apply_options: list[dict[str, str]] = field(default_factory=list)
    narrow: dict[str, Any] = field(default_factory=dict)
    clarification: str = ""
    entry: HistoryEntry | None = None
    kind: str = ""
    composition: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


def _glob(pattern: str | None, value: str) -> bool:
    return pattern is None or fnmatch.fnmatchcase(value, pattern)


def _domain(addr: Any) -> str:
    s = str(addr)
    return s.rpartition("@")[2].lower().strip(" >") if "@" in s else s.lower()


def _is_digest(v: Any) -> bool:
    """An R3 digest object stands in for a large or sensitive value (R3, Proposal Document)."""
    return isinstance(v, dict) and isinstance(v.get("s256"), str)


# --------------------------------------------------------------- policy interface


@runtime_checkable
class SupervisionPolicy(Protocol):
    """The decision interface the protocol layer (`SupervisionServer`) depends on.

    `SupervisionServer` is pure Supervision -00 wire logic: it parses and verifies the
    request, builds an `Act`, keeps the mission/history/reach state, and signs the
    answer. It never reaches into how a decision is made. Any object with these three
    methods and two attributes can drive it; the APC `Policy` below is one such object,
    but a trivial allow-list, a rule engine, an LLM adapter or a human-in-the-loop queue
    could replace it without touching the protocol layer.

    * `classify(act)` maps an act to a semantic class with provenance (used on replay,
      where there is no live decision to record, only an event to characterize).
    * `decide(act, mission, history, reach, now, clarify=...)` is the per-act decision
      over the mission state: `allow | deny | ask | clarify`.
    * `decide_proposal(body, now)` decides a mission proposal (which resources/tools the
      mission may touch): `allow | deny | ask`.

    Two attributes let the protocol layer stay policy-agnostic without reading a
    concrete config object:

    * `r3_member` is the request member that carries the resource-asserted R3 proposal
      (a wire name the parser needs, not a policy knob). This is a NON-SPEC extension
      (AAuth #256); None means spec-only Supervision -00 and the member is ignored.
    * `ask_on_mission_update` says whether an agent-reported mission change is put to the
      person. A policy that does not model updates returns False.
    """

    @property
    def r3_member(self) -> str | None: ...

    @property
    def ask_on_mission_update(self) -> bool: ...

    def classify(self, act: Act) -> Classification: ...

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision: ...

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision: ...


class Policy:
    def __init__(self, cfg: PolicyConfig) -> None:
        self.cfg = cfg

    # The two protocol-level attributes, surfaced from the APC config so the protocol
    # layer never reads `policy.cfg` (see SupervisionPolicy).
    @property
    def r3_member(self) -> str | None:
        return self.cfg.r3_member

    @property
    def ask_on_mission_update(self) -> bool:
        return self.cfg.ask_on_mission_update

    # -------------------------------------------------------- classification

    def _data_match(self, r: Rule, act: Act) -> bool | None:
        """True/False if the rule's data conditions are decidable, None if not."""
        ok = True
        if r.result_contains_any:
            if act.result is None:
                return None
            contains = act.result.get("contains", [])
            vals = {str(x) for x in contains} if isinstance(contains, list) else set()
            vals |= {str(k) for k in act.result if k != "contains"}
            ok = ok and bool(vals & set(r.result_contains_any))
        for pname, allowed in (r.param_domain_not_in or {}).items():
            if act.parameters is None or pname not in act.parameters:
                return None
            v = act.parameters[pname]
            addrs = v if isinstance(v, list) else [v]
            if any(_is_digest(a) or not isinstance(a, str) for a in addrs):
                return None  # R3 digest object or non-string: the value is not visible
            ok = ok and any(_domain(a) not in {x.lower() for x in allowed} for a in addrs)
        for pname, limit in (r.param_gt or {}).items():
            if act.parameters is None or pname not in act.parameters:
                return None
            if _is_digest(act.parameters[pname]):
                return None
            try:
                value = float(act.parameters[pname])
            except (TypeError, ValueError):
                return None
            # NaN compares false with everything, so it would read as "not over the limit"
            # and escape `if_unknown`. A value that is not a finite number is not visible.
            if not math.isfinite(value):
                return None
            ok = ok and value > limit
        return ok

    def _static_match(self, r: Rule, act: Act) -> bool:
        if not _glob(r.resource, act.resource or act.tool):
            return False
        if r.operation is not None and not any(_glob(r.operation, o) for o in act.operations):
            return False
        if r.scope is not None and not any(_glob(r.scope, s) for s in act.scope.split()):
            return False
        if r.tool is not None and not _glob(r.tool, act.tool):
            return False
        return True

    def classify(self, act: Act) -> Classification:
        c = self._scan(act)
        if act.parameters_provenance == "agent" and (act.parameters or act.result):
            # Agent-asserted data may tighten, never loosen, for EVERY rule shape: whatever
            # the agent's data made of the act, it is at least as severe as the act would be
            # with that data unknown.
            blind = Act(act.act, act.iss, act.sub, act.agent, act.mission_s256, act.resource,
                        list(act.operations), act.scope, act.tool)
            base = self._scan(blind)
            if self.cfg.rank(base.cls) > self.cfg.rank(c.cls):
                return Classification(base.cls, "agent", True, c.amount,
                                      "agent-asserted evidence cannot lower the class")
        return c

    def _scan(self, act: Act) -> Classification:
        # Flags read only for truthiness: `False` -> `None` is an equivalent mutant.
        unknown_seen = False  # pragma: no mutate
        decided_on_resource = False  # pragma: no mutate
        for r in self.cfg.rules:
            if not self._static_match(r, act):
                continue
            if r.needs_data:
                m = self._data_match(r, act)
                if m is None:
                    unknown_seen = True
                    continue
                if act.parameters_provenance == "resource" or (
                        r.result_contains_any and act.result is not None):
                    decided_on_resource = True
                if m:
                    prov = "resource" if decided_on_resource else "agent"
                    return Classification(r.cls, prov, False, self._amount(r, act),
                                          f"rule {r.cls} on {prov}-asserted data")
                continue
            # A static rule closes the scan.
            fallback = r.if_unknown
            no_proposal = act.act == "auth_token" and act.parameters_provenance != "resource"
            if fallback and (unknown_seen or no_proposal):
                return Classification(fallback, "configured", True, self._amount(r, act),
                                      f"data needed by a more specific rule is unavailable; "
                                      f"assumed {fallback}")
            if act.parameters_provenance == "agent" and not decided_on_resource and fallback \
                    and self.cfg.rank(fallback) > self.cfg.rank(r.cls):
                # Agent-asserted data may tighten, never loosen.
                return Classification(fallback, "agent", True, self._amount(r, act),
                                      "agent-asserted evidence cannot lower the class")
            prov = "resource" if decided_on_resource else "configured"
            return Classification(r.cls, prov, False, self._amount(r, act), f"rule {r.cls}")
        return Classification(self.cfg.default_class, "configured", False, None, "no rule matched")

    @staticmethod
    def _amount(r: Rule, act: Act) -> int | None:
        if not r.amount_param:
            return None
        if act.parameters is None or r.amount_param not in act.parameters:
            return None
        # An amount the supervisor cannot read as a non-negative whole number is treated as
        # not visible, so the budget asks instead of counting it. A negative amount would
        # otherwise lower the running total and let a later payment through the ceiling.
        v = act.parameters[r.amount_param]
        if isinstance(v, bool):
            return None
        if isinstance(v, float):
            v = int(v) if v.is_integer() else None
        elif isinstance(v, str):
            v = int(v) if v.isascii() and v.isdigit() else None
        if not isinstance(v, int) or v < 0:
            return None
        return v

    # ------------------------------------------------------------ evaluation

    def _composition(self, cls: str, uncertain: bool, resource: str,
                     history: list[HistoryEntry]) -> tuple[list[str], bool]:
        """Return the violated pair/sequence and whether it rests on uncertain evidence.

        A violation is certain when it can be completed from certain history entries
        alone; an uncertain entry never masks a certain one that also completes it.
        """
        def unc_of(h: HistoryEntry) -> bool:
            return h.detail.startswith("uncertain")

        for a, b in self.cfg.prohibited_pairs:
            for other, me in ((a, b), (b, a)):
                if cls != me:
                    continue
                hits = [h for h in history if h.action_class == other]
                if hits:
                    return [other, me], uncertain or all(unc_of(h) for h in hits)
        for seq in self.cfg.prohibited_sequences:
            if seq[-1] != cls:
                continue
            for certain_only in (True, False):
                idx = 0
                for h in history:
                    if certain_only and unc_of(h):
                        continue
                    if idx < len(seq) - 1 and h.action_class == seq[idx]:
                        idx += 1
                if idx == len(seq) - 1:
                    return list(seq), uncertain or not certain_only
        return [], False

    def _reach(self, reach: list[Reach], act: Act, kind: str,
               composition: list[str]) -> Reach | None:
        for r in reach:
            if (r.iss, r.sub, r.agent) != (act.iss, act.sub, act.agent) or r.kind != kind:
                continue
            if r.value == "once":
                continue
            if r.value != "always" and r.mission_s256 and r.mission_s256 != act.mission_s256:
                continue
            if composition and r.composition_override != composition:
                continue
            return r
        return None

    def decide(self, act: Act, mission: Mission | None, history: list[HistoryEntry],
               reach: list[Reach], now: float | None = None, *,
               clarify: bool = True) -> Decision:
        """Decide one act. `clarify=False` is used once the agent has answered a
        clarification: the act then goes to the person instead of looping."""
        now = time.time() if now is None else now
        trace: list[str] = []
        cfg = self.cfg

        if mission is not None:
            if mission.state != "active":
                return Decision("deny", reason="The mission has terminated.", trace=["mission"])
            exp = _iso_to_epoch(mission.blob.get("expires_at"))
            if exp is not None and now >= exp:
                return Decision("deny", reason="The mission has expired.", trace=["mission"])

        if act.act == "person_token":
            return self._decide_person_token(act, mission, reach, now)

        if any(_glob(p, act.resource) for p in cfg.deny_resources if act.resource):
            return Decision("deny", reason=f"{act.resource} is not permitted by policy.",
                            trace=["deny_resources"])

        c = self.classify(act)
        trace.append(f"class={c.cls} provenance={c.provenance} uncertain={c.uncertain} ({c.detail})")
        target = act.resource or act.tool
        kind = f"{c.cls}|{target}"
        entry = HistoryEntry(c.cls, target, c.provenance, at=int(now), amount=c.amount or 0,
                             detail=("uncertain: " if c.uncertain else "") + c.detail)
        if act.budget_amount is not None:
            entry.unit, entry.allocated = act.budget_unit, act.budget_amount
        high = c.cls in cfg.high_impact

        # AAuth Budgets: the person's ceiling at a metered resource, against the resource's
        # own offer and consumption records. A hard ceiling, like the class budgets below.
        rb = cfg.resource_budgets.get(act.resource)  # a permission act has no resource
        if rb is not None:
            over = self._resource_budget(act, rb, history, c, kind, entry, trace)
            if over is not None:
                return over

        # Budgets: hard ceilings, never overridden.
        b = cfg.budgets.get(c.cls)
        if b is not None:
            same = [h for h in history if h.action_class == c.cls]
            if b.max_count is not None and len(same) + 1 > b.max_count:
                return Decision("deny", reason=f"Budget exhausted: at most {b.max_count} "
                                f"{c.cls} acts in this mission.", entry=entry, kind=kind,
                                trace=trace + ["budget count"])
            if b.max_amount is not None:
                if c.amount is None:
                    return self._ask(act, c, kind, entry, trace + ["budget amount unknown"],
                                     f"The {c.cls} amount is not visible to the supervisor, so "
                                     f"the {b.max_amount} budget cannot be checked.", "deny")
                spent = sum(h.amount for h in same)
                if spent + c.amount > b.max_amount:
                    return Decision("deny", reason=f"Budget exceeded: {spent} + {c.amount} > "
                                    f"{b.max_amount} for {c.cls}.", entry=entry, kind=kind,
                                    trace=trace + ["budget amount"])

        # Composition closure over the mission history.
        comp, comp_unc = self._composition(c.cls, c.uncertain, target, history)
        if comp:
            trace.append(f"composition {comp} uncertain={comp_unc}")
            r = self._reach(reach, act, kind, comp)
            if r is not None:
                trace.append(f"reach {r.value} overrides composition")
                return Decision("allow", entry=entry, kind=kind, composition=comp, trace=trace,
                                narrow=self.narrow(mission))
            if comp_unc or cfg.composition_on_certain == "ask":
                return self._ask(act, c, kind, entry, trace,
                                 self._comp_summary(comp, comp_unc), "deny", comp)
            return Decision("deny", reason=self._comp_summary(comp, False), entry=entry,
                            kind=kind, composition=comp, trace=trace)

        # Intent: inside the approved mission?
        if mission is not None:
            if act.act == "permission":
                tools = [t.get("name") for t in mission.blob.get("approved_tools", [])
                         if isinstance(t, dict)]
                if act.tool not in tools and not self._reach(reach, act, kind, []):
                    return self._ask(act, c, kind, entry, trace + ["tool outside mission"],
                                     f"`{act.tool}` is not an approved tool for this mission.",
                                     "")
            elif act.resource and not cfg.allow_unlisted_resources:
                res = mission.blob.get("approved_resources", [])
                if act.resource not in res and not self._reach(reach, act, kind, []):
                    return self._ask(act, c, kind, entry, trace + ["resource outside mission"],
                                     f"{act.resource} is not among the mission's approved "
                                     f"resources.", "")

        # High impact acts need resource-asserted evidence. A permission act never has
        # any (its parameters come from the agent), so a high-impact tool is put to the
        # person unless the person already gave it reach.
        if high and c.provenance != "resource":
            if clarify and cfg.clarify_missing_justification and not act.justification:
                return Decision("clarify", clarification=f"What is this {c.cls} act for, and "
                                f"what will it send or change?", entry=entry, kind=kind,
                                trace=trace + ["clarify"])
            if not self._reach(reach, act, kind, []):
                return self._ask(act, c, kind, entry, trace + ["high impact, no resource evidence"],
                                 f"This is a {c.cls} act and the supervisor has no "
                                 f"resource-asserted detail of it"
                                 + (f"; the agent says: {act.justification.rstrip('.')}"
                                    if act.justification else "") + ".", "")

        r = self._reach(reach, act, kind, [])
        if r is not None:
            trace.append(f"reach {r.value}")
        return Decision("allow", entry=entry, kind=kind, trace=trace, narrow=self.narrow(mission))

    def _decide_person_token(self, act: Act, mission: Mission | None, reach: list[Reach],
                             now: float) -> Decision:
        if any(_glob(p, act.resource) for p in self.cfg.deny_resources if act.resource):
            return Decision("deny", reason=f"{act.resource} is not permitted by policy.")
        if mission is not None and not self.cfg.allow_unlisted_resources:
            if act.resource not in mission.blob.get("approved_resources", []):
                kind = f"identity|{act.resource}"
                if not self._reach(reach, act, kind, []):
                    return Decision("ask", summary=f"The agent asks to identify you to "
                                    f"{act.resource}, which is not among the mission's approved "
                                    f"resources.", kind=kind,
                                    apply_options=_apply_options(act.resource))
        return Decision("allow", narrow=self.narrow(mission))

    def _resource_budget(self, act: Act, rb: ResourceBudget, history: list[HistoryEntry],
                         c: Classification, kind: str, entry: HistoryEntry,
                         trace: list[str]) -> Decision | None:
        """AAuth Budgets at a metered resource: None when the offer fits the ceiling.

        What this mission has committed at the resource is, per earlier allocation, the
        latest resource-signed `budget_consumed` for its token, or else the whole
        allocation (Budgets, Unreported Allocations: "the issuer MUST account for the
        allocation as fully consumed"). The new allocation is the resource's offer, the
        most the PS may grant. Supervision -00 gives the SS no way to grant less, so an
        offer that would cross the ceiling is put to the person with the headroom stated,
        not silently narrowed."""
        where = f"at {act.resource}"
        if act.budget_amount is None:
            return self._ask(act, c, kind, entry, trace + ["resource budget: no offer"],
                             f"{act.resource} is metered against a {_money(rb.max_amount, rb)} "
                             f"ceiling, but its resource token carries no `budget`, so the "
                             f"spend cannot be bounded.", "deny")
        if act.budget_unit != rb.denomination:
            return self._ask(act, c, kind, entry, trace + ["resource budget: other unit"],
                             f"{act.resource} offers a budget in {act.budget_unit}, which is "
                             f"not the {rb.denomination} its ceiling is set in.", "deny")
        prior = [h for h in history if h.resource == act.resource]
        if any(h.unit != rb.denomination for h in prior):
            return self._ask(act, c, kind, entry, trace + ["resource budget: unbounded history"],
                             f"An earlier act {where} has no budget the supervisor can account "
                             f"for, so the mission's spend there is unknown.", "deny")
        committed = sum(h.consumed if h.consumed is not None else h.allocated for h in prior)
        offer = act.budget_amount
        trace.append(f"resource budget: committed {committed} + offer {offer} "
                     f"vs {rb.max_amount} {rb.denomination}")
        if committed + offer <= rb.max_amount:
            return None
        if committed >= rb.max_amount:
            return Decision("deny", reason=f"Budget exhausted {where}: "
                            f"{_money(committed, rb)} of {_money(rb.max_amount, rb)} committed.",
                            entry=entry, kind=kind, trace=trace + ["resource budget exhausted"])
        return self._ask(act, c, kind, entry, trace + ["resource budget: offer over headroom"],
                         f"{act.resource} offers {_money(offer, rb)}, but only "
                         f"{_money(rb.max_amount - committed, rb)} of the "
                         f"{_money(rb.max_amount, rb)} mission ceiling is left. The supervisor "
                         f"cannot grant less under Supervision -00.", "deny")

    def _ask(self, act: Act, c: Classification, kind: str, entry: HistoryEntry,
             trace: list[str], summary: str, recommendation: str,
             composition: list[str] | None = None) -> Decision:
        return Decision("ask", summary=summary, recommendation=recommendation,
                        apply_options=_apply_options(act.resource or act.tool, composition),
                        entry=entry, kind=kind, composition=composition or [], trace=trace)

    @staticmethod
    def _comp_summary(comp: list[str], uncertain: bool) -> str:
        chain = " then ".join(comp)
        if uncertain:
            return (f"This act may complete a prohibited composition ({chain}). Part of the "
                    f"evidence is not resource-asserted, so the supervisor cannot rule it out.")
        return f"This act would complete a prohibited composition: {chain}."

    def narrow(self, mission: Mission | None) -> dict[str, Any]:
        """The narrowing every `allow` under this mission carries: an `exp` no later than
        the mission's `expires_at`. Public so a policy layered on this one (see
        `examples/layered_policy.py`) narrows its own allows exactly the same way."""
        if mission is None:
            return {}
        exp = _iso_to_epoch(mission.blob.get("expires_at"))
        return {"exp": int(exp)} if exp is not None else {}

    # --------------------------------------------------------- missions

    def decide_proposal(self, body: dict[str, Any], now: float | None = None) -> Decision:
        now = time.time() if now is None else now
        resources_in, tools_in = body.get("resources", []), body.get("tools", [])
        if not isinstance(resources_in, list) or not isinstance(tools_in, list):
            raise ValueError("resources and tools must be arrays")
        resources = [r for r in resources_in if isinstance(r, str)]
        tools = [t for t in tools_in if isinstance(t, dict)]
        denied = [r for r in resources if any(_glob(p, r) for p in self.cfg.deny_resources)]
        if denied:
            return Decision("deny", reason=f"Not permitted by policy: {', '.join(denied)}.")
        approved_tools, asked = [], []
        for t in tools:
            name = str(t.get("name", ""))
            if any(_glob(p, name) for p in self.cfg.ask_tools):
                asked.append(t)
            elif any(_glob(p, name) for p in self.cfg.allowed_tools):
                approved_tools.append(t)
        refined: dict[str, Any] = {
            "description": body.get("description", ""),
            "approved_tools": approved_tools,
            "approved_resources": resources,
        }
        if self.cfg.max_mission_seconds:
            refined["expires_at"] = _epoch_to_iso(now + self.cfg.max_mission_seconds)
        if asked:
            names = ", ".join(str(t.get("name")) for t in asked)
            return Decision("ask", summary=f"The mission asks for tools that need your approval: "
                            f"{names}. The proposed refinement leaves them out.",
                            narrow={"proposed": refined})
        return Decision("allow", narrow=refined)


def _money(amount: int, rb: ResourceBudget) -> str:
    """An integer amount in the resource's scale, printed exactly: 2500 at 2 decimals is
    "25.00 USD". Integer arithmetic only, as Budgets' Value Representation requires."""
    if rb.decimals == 0:
        return f"{amount} {rb.unit}"
    whole, frac = divmod(amount, 10 ** rb.decimals)
    return f"{whole}.{frac:0{rb.decimals}d} {rb.unit}"


def _apply_options(target: str, composition: list[str] | None = None) -> list[dict[str, str]]:
    if composition:
        return [{"value": "once", "label": "This act only"},
                {"value": "mission", "label": f"Allow {' then '.join(composition)} for the rest "
                                             f"of this mission"}]
    return [{"value": "once", "label": "This act only"},
            {"value": "mission", "label": f"Acts like this on {target} for this mission"},
            {"value": "always", "label": f"Acts like this on {target} by this agent"}]


def _iso_to_epoch(v: Any) -> float | None:
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

    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return float("-inf")
    return t.timestamp() if t.tzinfo is not None else float("-inf")


def _epoch_to_iso(t: float) -> str:
    from datetime import datetime

    return datetime.fromtimestamp(int(t), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
