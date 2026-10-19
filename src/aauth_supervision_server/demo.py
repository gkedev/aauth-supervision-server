"""`aauth-ss demo`: the SS deciding a short mission, step by step.

Everything is real except the person server: the SS is the unmodified
`SupervisionServer`, and `testing.SimulatedPS` speaks Supervision -00 to it with real
RFC 9421 signatures and real signed tokens, in-process, with no network. The mission, a
quarterly review, walks through what the README's diagrams show: an allowed read, metered inference against
an AAuth Budgets ceiling, a person's answer, and the split exfiltration the APC policy
exists to catch.

By default the PS speaks Supervision -00 as written. `--extension` turns on the R3
proposal forwarding of AAuth #256, which lets the SS decide the exfiltration itself.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Callable
from typing import Any

from .adversarial import build
from .errors import Response

RECORDS, MAIL, INFERENCE = ("https://records.example", "https://mail.example",
                            "https://inference.example")
SEND = {"operations": [{"operationId": "send_email"}]}

POLICY: dict[str, Any] = {
    "severity": ["unclassified", "read", "read_sensitive", "send_internal", "send_external"],
    "high_impact": ["send_external"],
    "rules": [
        {"resource": RECORDS, "class": "read_sensitive"},
        {"resource": MAIL, "operation": "send_email",
         "param_domain_not_in": {"to": ["corp.example"], "cc": ["corp.example"],
                                 "bcc": ["corp.example"]}, "class": "send_external"},
        {"resource": MAIL, "operation": "send_email", "class": "send_internal",
         "if_unknown": "send_external"},
        {"resource": MAIL, "scope": "mail.send", "class": "send_internal",
         "if_unknown": "send_external"},
        {"resource": MAIL, "class": "send_internal", "if_unknown": "send_external"},
        {"resource": INFERENCE, "class": "read"},
    ],
    "prohibited_pairs": [["read_sensitive", "send_external"]],
    "resource_budgets": {INFERENCE: {"unit": "USD", "decimals": 2, "max_amount": 2500}},
    "r3_member": "r3_proposal",
}


def usd(cents: int) -> dict[str, Any]:
    return {"amount": cents, "unit": "USD", "decimals": 2}


class Demo:
    def __init__(self, extension: bool, trace: bool, out: Callable[[str], None]) -> None:
        self.ss, self.ps, self.clock = build("apc/forwarded+issued" if extension else "apc/current",
                                             POLICY)
        self.extension, self.trace, self.out = extension, trace, out
        self.s256, self.step = "", 0
        self.tally: dict[str, int] = {}

    # ------------------------------------------------------------ narration

    def say(self, text: str, indent: str = "", hang: str = "") -> None:
        for line in textwrap.wrap(text, 88, initial_indent=indent,
                                  subsequent_indent=indent + hang) or [""]:
            self.out(line)

    def scene(self, title: str) -> None:
        self.out("")
        self.out(title)
        self.out("-" * len(title))

    def ask(self, what: str) -> None:
        self.step += 1
        self.say(f"{self.step}. {what}", hang="   ")

    def answer(self, r: Response, sdi: str = "") -> dict[str, Any]:
        d = r.json()
        assert isinstance(d, dict)
        verdict = str(d.get("decision") or d.get("status") or r.status)
        if "decision" in d:
            self.tally[verdict] = self.tally.get(verdict, 0) + 1
        detail = d.get("reason") or d.get("summary") or d.get("clarification") or ""
        self.say(f"SS: {verdict.upper()}" + (f". {detail}" if detail else ""), "     ", "    ")
        if self.trace and sdi:
            rec = self.ss.store.decisions[self.ss.store.k(self.ps.issuer, sdi)]
            self.say(f"trace: {rec.kind}"
                     + (f", completes {' then '.join(rec.composition)}" if rec.composition else ""),
                     "       ", "  ")
        return d

    # ------------------------------------------------------------ steps

    def token(self, resource: str, what: str, *, scope: str = "", proposal: dict[str, Any] | None
              = None, justification: str = "", budget: dict[str, Any] | None = None,
              consumed: dict[str, Any] | None = None, jti: str = "") -> tuple[str, dict[str, Any]]:
        self.ask(what)
        sdi, r, _ = self.ps.auth_token_request(
            self.ss, "person-1", "aauth:assistant@agent.example", self.s256, resource,
            scope=scope, proposal=proposal, justification=justification, budget=budget,
            consumed=consumed)
        d = self.answer(r, sdi)
        if d.get("decision") == "allow":
            self.ps.issued(self.ss, "person-1", "aauth:assistant@agent.example", self.s256, sdi,
                           resource, scope, proposal, jti=jti or None)
            self.say("PS issues the token and reports it: the act joins the mission history.",
                     "     ")
        return sdi, d

    def run(self) -> int:
        sub, agent = "person-1", "aauth:assistant@agent.example"
        self.say("AAuth Supervision Server demo. A simulated person server (PS) puts an "
                 "agent's acts to this SS over signed HTTP; the SS answers allow, deny, "
                 "clarify, or ask the person.")
        self.say("Transport: " + ("R3 proposal forwarded (AAuth #256, extension)." if self.extension
                                  else "Supervision -00 as written."))

        self.scene("Setting up")
        self.ask("The PS connects the person to this SS.")
        self.answer(self.ps.connect(self.ss, sub))
        self.ask("The agent proposes a mission: prepare the quarterly review.")
        r, self.s256 = self.ps.propose_and_approve(
            self.ss, sub, agent, "# Prepare the quarterly review", [RECORDS, MAIL, INFERENCE])
        self.answer(r)
        self.say("The PS records the approved mission and reports it; the SS now holds it.",
                 "     ")

        self.scene("Metered work against a 25.00 USD ceiling (AAuth Budgets)")
        self.token(INFERENCE, "The agent asks for inference; the resource offers 10.00 USD.",
                   scope="inference.completions", budget=usd(1000), jti="at-1")
        self.token(INFERENCE, "Another 10.00 USD offer.", scope="inference.completions",
                   budget=usd(1000), jti="at-2")
        self.token(INFERENCE, "A third 10.00 USD offer. Nothing has reported spend yet, so "
                   "both earlier allocations count in full.", scope="inference.completions",
                   budget=usd(1000))
        self.token(INFERENCE, "The agent asks for another 10.00 USD; the resource's token "
                   "also reports, signed, that the first token has spent only 2.00 USD so far. "
                   "That token is still live and may spend the rest, so the record frees "
                   "nothing (Budgets: a consumption record settles nothing).",
                   scope="inference.completions", budget=usd(1000),
                   consumed={"jti": "at-1", "consumed": 200}, jti="at-3")

        self.scene("A split exfiltration")
        self.token(RECORDS, "The agent reads the customer records (fine on its own).",
                   proposal={"operations": [{"operationId": "export"}],
                             "result": {"contains": ["customer_pii"]}})
        sdi, d = self.token(MAIL, "It then asks to email them to drop@evil.example, outside "
                            "the company.", scope="mail.send",
                            proposal=SEND | {"parameters": {"to": "drop@evil.example"}})

        if d.get("decision") == "ask":
            self.scene("The person decides what the SS could not")
            self.ask("The PS shows the person the SS's summary; the person refuses.")
            r = self.ps.resolved(self.ss, sub, agent, self.s256, sdi, "deny")
            self.say(f"The PS refuses the agent and reports the answer ({r.status} Created). "
                     f"Nothing was sent.", "     ")

        self.scene("What happened")
        counts = ", ".join(f"{n} {v}" for v, n in sorted(self.tally.items()))
        self.say(f"{sum(self.tally.values())} decisions: {counts}. Each was signed by the SS and "
                 f"verified by the PS before it acted on it.")
        if self.extension:
            self.say("With the proposal forwarded the SS sees who the mail goes to, so it denies "
                     "the exfiltration itself: no one has to be asked.")
        else:
            self.say("Under Supervision -00 the SS cannot see who the mail goes to, so it cannot "
                     "rule the exfiltration out: it puts the send to the person, naming the "
                     "composition it may complete. Run `aauth-ss demo --extension` to see the SS deny "
                     "it itself with the R3 proposal forwarded (AAuth #256).")
        return 0


def run(extension: bool = False, trace: bool = False,
        out: Callable[[str], None] = print) -> int:
    return Demo(extension, trace, out).run()


def policy_json() -> str:
    """The demo's policy, for `aauth-ss demo --show-policy`."""
    return json.dumps(POLICY, indent=2)
