"""Extract BCP 14 requirements from the pinned drafts into docs/conformance-matrix.md.

Every normative sentence (MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, MAY, OPTIONAL in upper case) becomes one row with its
file, line and enclosing section, plus a stable requirement id. The
"Status" and "Test" columns start empty and are filled as later stages
implement and test each row.

Scope:
  - Supervision -00: whole document (the SS is its implementation target).
  - R3 and core: only the sections an SS depends on (listed in SCOPED below).

Run:  python tools/extract_matrix.py
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "specs"
OUT = ROOT / "docs" / "conformance-matrix.md"

PIN = "70d67375deb0bb002af7da0711fc58f6e8926e7e"
KEYWORDS = re.compile(
    r"\b(MUST NOT|MUST|REQUIRED|SHALL NOT|SHALL|SHOULD NOT|SHOULD|NOT RECOMMENDED|"
    r"RECOMMENDED|MAY|OPTIONAL)\b"
)
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*(\{#[^}]*\})?\s*$")

# (file, id prefix, section-title predicate). None = whole document.
SCOPED: list[tuple[str, str, tuple[str, ...] | None]] = [
    ("draft-hardt-aauth-supervision.md", "SUP", None),
    (
        "draft-hardt-aauth-r3.md",
        "R3",
        (
            "Per-Call Proposals",
            "Proposal Document",
            "Flow",
            "Large and Sensitive Payloads",
            "Approving Release Rather Than Execution",
            "R3 Document Access Restriction",
            "Hash Verification",
        ),
    ),
    (
        "draft-hardt-oauth-aauth-protocol.md",
        "CORE",
        ("Consent Presentation", "Roles", "Policy Evaluation Points"),
    ),
]

# Supervision -00 SS behaviour stated without BCP 14 keywords: (id, level, line, section, text).
CURATED: list[tuple[str, str, int, str, str]] = [
    ("SUP-P01", "MUST", 190, "PS Authentication",
     "The SS never makes a request of the PS. Everything the SS has to say is a response."),
    ("SUP-P02", "MUST", 211, "Delivery",
     "The SS deduplicates on (iss, id) and answers a repeated event with 201 and nothing new recorded."),
    ("SUP-P03", "MUST", 254, "Supervision Decisions",
     "Four answers: allow/deny/ask (200, close the sdi) and clarify (202, requirement=clarification)."),
    ("SUP-P04", "MUST", 284, "Deferred Decisions",
     "An SS that cannot answer within the wait returns 202 with Location and Retry-After; polls are "
     "signed GETs from the same identity, otherwise unknown_pending."),
    ("SUP-P05", "MUST", 292, "Clarification",
     "Clarify = 202, requirement=clarification, body with sdi, status=pending, decision=clarify, "
     "clarification, timeout; replies arrive as signed POST (clarification_response, updated_request) "
     "or DELETE on the pending URL."),
    ("SUP-P06", "MUST", 396, "Proposal",
     "allow on a proposal carries description and MAY carry approved_tools, approved_resources, "
     "expires_at; ask MAY carry them under proposed."),
    ("SUP-P07", "MUST", 448, "Update",
     "Update: answer with a decision; it narrows nothing (accepted or not)."),
    ("SUP-P08", "MUST", 452, "Completion",
     "Completion: allow terminates (reason completed), deny keeps the mission active."),
    ("SUP-P09", "MUST", 510, "Permission",
     "Permission act carries action, description, parameters; allow -> granted, deny -> denied with reason."),
    ("SUP-P10", "MUST", 535, "Event Endpoint",
     "Every event request is a report; the SS answers 201 with no body and MAY use it in later decisions."),
    ("SUP-P11", "MUST", 582, "Reach of an Answer",
     "The SS remembers apply (once, mission, always or an apply_options value) from decision.resolved "
     "and applies it to later acts."),
    ("SUP-P12", "MUST", 619, "Replay and Recovery",
     "Routing change: the SS accepts agent.bound, mission approved + log entries, and issued-token "
     "events as replay, and rebuilds its state from them."),
    ("SUP-P13", "MUST", 621, "Replay and Recovery",
     "The SS answers unknown_mission when it has no record of mission_s256."),
    ("SUP-P14", "MUST", 625, "Errors",
     "Error bodies follow the core Error Response Format; signature failures are 401 with "
     "Signature-Error; codes and statuses per the Errors table."),
    ("SUP-P15", "MUST", 307, "Clarification",
     "The SS enforces the `timeout` it states in a clarification (core, Clarification Required: the "
     "recipient MUST respond before the deadline): a reply, poll or cancel after it gets 408 "
     "expired, and a timeout of 0 is not stated."),
    ("SUP-P16", "MUST", 310, "Clarification",
     "An updated_request is the same request (core, Updated Request): its resource token has the "
     "same iss, ps, sub, agent_jkt, mission_s256 and tenant as the original, or it is refused."),
    ("SUP-P17", "MUST", 310, "Clarification",
     "A signed DELETE withdraws an open clarification (the record is abandoned, the pending URL "
     "answers 410). A DELETE after the SS answered does not rewrite that answer."),
]

# Rows that bind another role, with the reason the SS has nothing to implement.
NA: dict[str, str] = {
    "SUP-009": "PS routing configuration",
    "SUP-010": "PS routing configuration",
    "SUP-018": "PS obligation; this SS always answers within the wait",
    "SUP-061": "PS wording obligation",
    "SUP-063": "PS registration UX",
    "SUP-065": "PS policy (this SS publishes jwks_uri: SUP-007)",
    "SUP-066": "PS registration UX",
    "R3-001": "resource builds the proposal; SS consumes operations (R3-002 tests)",
    "R3-004": "display aid; SS never decides on excerpts",
    "R3-005": "display aid",
    "R3-007": "display is for people; SS decides on machine-readable members only",
    "R3-008": "resource/agent flow",
    "R3-009": "resource enforcement",
    "R3-010": "resource enforcement (single use)",
    "R3-011": "PS behaviour on expiry",
    "R3-012": "resource display obligation",
    "R3-013": "resource execution rule",
    "R3-015": "resource metering",
    "R3-016": "SS never fetches r3_uri (the gap AAuth #256 raises)",
    "R3-017": "SS never fetches r3_uri (the gap AAuth #256 raises)",
    "R3-018": "resource implementation guidance",
    "CORE-001": "descriptive",
    "CORE-002": "descriptive",
}

TEST_MARK = re.compile(
    r"@pytest\.mark\.req\(([^)]*)\)[ \t]*\n(?:(?!def )[^\n]*\n){0,8}?def (test_\w+)")


def _tests_by_row() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in sorted((ROOT / "tests").glob("test_*.py")):
        for m in TEST_MARK.finditer(p.read_text(encoding="utf-8")):
            for rid in re.findall(r'"([A-Z0-9]+-[A-Z0-9]+)"', m.group(1)):
                out.setdefault(rid, []).append(f"{p.stem}::{m.group(2)}")
    return out


def _status(rid: str, tests: dict[str, list[str]]) -> tuple[str, str]:
    if rid in tests:
        t = tests[rid]
        shown = ", ".join(f"`{x}`" for x in t[:3]) + (f" +{len(t) - 3}" if len(t) > 3 else "")
        return "tested", shown
    if rid in NA:
        return "n/a", NA[rid]
    return "-", ""


def _rows(fname: str, prefix: str, sections: tuple[str, ...] | None) -> list[tuple[str, ...]]:
    lines = (SPECS / fname).read_text(encoding="utf-8").splitlines()
    stack: list[tuple[int, str]] = []
    in_code = False
    rows: list[tuple[str, ...]] = []
    n = 0
    for i, line in enumerate(lines, 1):
        if line.strip().startswith(("```", "~~~")):
            in_code = not in_code
            continue
        if in_code:
            continue
        h = HEADING.match(line)
        if h:
            level = len(h.group(1))
            stack = [s for s in stack if s[0] < level] + [(level, h.group(2))]
            continue
        if not stack:
            continue
        # Skip boilerplate / non-normative tail sections.
        top = stack[0][1]
        if top in ("Conventions and Definitions", "Document History", "Acknowledgments",
                   "Implementation Status", "IANA Considerations"):
            continue
        if sections is not None and not any(t in sections for _, t in stack):
            continue
        found = KEYWORDS.findall(line)
        if not found:
            continue
        n += 1
        section = " > ".join(t for _, t in stack)
        text = re.sub(r"\s+", " ", line.strip()).replace("|", "\\|")
        if len(text) > 300:
            text = text[:297] + "..."
        level = "MUST" if any(k.startswith(("MUST", "SHALL", "REQUIRED")) for k in found) else (
            "SHOULD" if any("SHOULD" in k or k == "RECOMMENDED" for k in found) else "MAY")
        rows.append((f"{prefix}-{n:03d}", level, fname, str(i), section, text))
    return rows


def main() -> int:
    import sys

    tests = _tests_by_row()
    out = [
        "# Conformance matrix",
        "",
        f"Generated by `tools/extract_matrix.py` from the drafts in `specs/` (AAuth repo at `{PIN}`).",
        "Do not edit rows by hand; regenerate. Status: `tested` (a test carries "
        "`@pytest.mark.req(<id>)`), `n/a` (binds another role; reason given), `-` open.",
        "",
    ]
    total = {"MUST": 0, "SHOULD": 0, "MAY": 0}
    state = {"tested": 0, "n/a": 0, "-": 0}
    open_must: list[str] = []

    def line(rid: str, level: str, ln: str, section: str, text: str) -> str:
        st, t = _status(rid, tests)
        state[st] += 1
        if st == "-" and level == "MUST":
            open_must.append(rid)
        return f"| {rid} | {level} | L{ln} | {section} | {text} | {st} | {t} |"

    for fname, prefix, sections in SCOPED:
        rows = _rows(fname, prefix, sections)
        for r in rows:
            total[r[1]] += 1
        scope = "whole document" if sections is None else "sections: " + ", ".join(sections)
        out += [f"## {fname} ({scope})", "",
                "| Id | Level | Line | Section | Requirement | Status | Test |",
                "|---|---|---|---|---|---|---|"]
        out += [line(r[0], r[1], r[3], r[4], r[5]) for r in rows]
        out.append("")
    out += [
        "## Behaviour stated without BCP 14 keywords (curated)",
        "",
        "Supervision -00 states several SS obligations in plain prose. They are listed here so",
        "they get tests like any keyword row.",
        "",
        "| Id | Level | Line | Section | Requirement | Status | Test |",
        "|---|---|---|---|---|---|---|",
    ]
    out += [line(c[0], c[1], str(c[2]), c[3], c[4]) for c in CURATED]
    out.append("")
    rows_n = sum(total.values())
    out.insert(4, f"Rows: {rows_n} keyword rows (MUST {total['MUST']}, SHOULD {total['SHOULD']}, "
                  f"MAY {total['MAY']}) + {len(CURATED)} curated. Status: {state['tested']} "
                  f"tested, {state['n/a']} n/a, {state['-']} open.")
    text = "\n".join(out) + "\n"
    if "--check" in sys.argv:
        stale = OUT.read_text(encoding="utf-8") != text
        if stale:
            print("conformance-matrix.md is stale: run python tools/extract_matrix.py")
        if open_must:
            print("MUST rows with no test and no n/a reason: " + ", ".join(open_must))
        print(f"tested {state['tested']}, n/a {state['n/a']}, open {state['-']}")
        return 1 if stale or open_must else 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}: tested {state['tested']}, n/a {state['n/a']}, open {state['-']}"
          + (f"; open MUST: {', '.join(open_must)}" if open_must else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
