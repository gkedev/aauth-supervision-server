"""Extract BCP 14 requirements from the pinned drafts into docs/conformance-matrix.md.

Every normative sentence (MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD,
SHOULD NOT, RECOMMENDED, MAY, OPTIONAL in upper case) becomes one row with its
file, line and enclosing section, plus a stable requirement id. The
"Status" column is computed: `tested` where a test carries
`@pytest.mark.req(<id>)` (named in "Test"), `n/a` or `gap` with the reason
given below, `-` (open) otherwise.

Scope:
  - Supervision -00: whole document (the SS is its implementation target).
  - R3 and core: only the sections an SS depends on (listed in SCOPED below).
  - Core sections Supervision -00 incorporates by reference for the SS's own answers
    (clarification, deferred responses, interaction, errors, identifiers, metadata).
  - Core sections the SS meets as the verifier of every PS request (signature profile,
    verification, freshness, JWKS discovery and caching).
  - Budgets: the sections this SS implements.

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

# (file, id prefix, section-title predicate). None = whole document. A title matches any
# heading enclosing the line; a title starting with `=` matches the innermost one only.
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
    (
        # Supervision L244, L286, L292, L310, L627, L639, L157, L165 defer to these core
        # sections (L244 and L292 "exactly as"); the SS is the server they bind.
        "draft-hardt-oauth-aauth-protocol.md",
        "REF",
        ("=Clarification Required", "=Agent Response to Clarification",
         "=Clarification Response", "=Updated Request", "=Cancel Request",
         "=Clarification Limits", "=Server Identifiers", "=Metadata Documents",
         "=Interaction Required", "=Interaction Code Format", "=Deferred Responses",
         "=Pending Response", "=Polling with GET", "=Deferred Response State Machine",
         "=Error Response Format", "=Polling Error Codes", "=Pending URL Security",
         "=Interaction Code Misdirection"),
    ),
    (
        # Supervision L181: every PS request is signed under the core's HTTP Message
        # Signatures Profile, and L627 answers a failed signature as it says: the SS is the
        # verifier (the server) of these sections, and the PS the signer.
        "draft-hardt-oauth-aauth-protocol.md",
        "VER",
        ("=Signature Algorithms", "=Keying Material", "=Covered Components",
         "=Signature Parameters", "=Verification (Server)", "=Signature-Key Scheme Rejection",
         "=Freshness and Replay", "=JWKS Discovery and Caching"),
    ),
    (
        "draft-hardt-aauth-budgets.md",
        "BUD",
        ("Value Representation", "Range Limits", "The Budget Object",
         "Resource Token Extensions", "Unreported Allocations", "Concurrency"),
    ),
]

# Supervision -00 SS behaviour stated without BCP 14 keywords: (id, level, line, section, text).
# Their level is `prose`: the matrix never attributes a keyword the draft does not use.
CURATED: list[tuple[str, str, int, str, str]] = [
    ("SUP-P01", "prose", 190, "PS Authentication",
     "The SS never makes a request of the PS. Everything the SS has to say is a response."),
    ("SUP-P02", "prose", 211, "Delivery",
     "The SS deduplicates on (iss, id) and answers a repeated event with 201 and nothing new recorded."),
    ("SUP-P03", "prose", 253, "Supervision Decisions",
     "Four answers: allow/deny/ask (200, close the sdi) and clarify (202, requirement=clarification)."),
    ("SUP-P04", "prose", 286, "Deferred Decisions",
     "An SS that cannot answer within the PS's wait returns 202 with Location and "
     "Retry-After; the PS polls the pending URL with a signed GET under the identity that "
     "made the request."),
    ("SUP-P05", "prose", 292, "Clarification",
     "Clarify = 202, requirement=clarification, body with sdi, status=pending, decision=clarify, "
     "clarification, timeout; replies arrive as signed POST (clarification_response, updated_request) "
     "or DELETE on the pending URL."),
    ("SUP-P06", "prose", 397, "Proposal",
     "allow on a proposal carries description and MAY carry approved_tools, approved_resources, "
     "expires_at; ask MAY carry them under proposed."),
    ("SUP-P07", "prose", 450, "Update",
     "Update: answer with a decision; it narrows nothing (accepted or not)."),
    ("SUP-P08", "prose", 454, "Completion",
     "Completion: allow terminates (reason completed), deny keeps the mission active."),
    ("SUP-P09", "prose", 531, "Permission",
     "Permission act carries action, description, parameters; allow -> granted, deny -> denied with reason."),
    ("SUP-P10", "prose", 535, "Event Endpoint",
     "Every event request is a report; the SS answers 201 with no body and MAY use it in later decisions."),
    ("SUP-P11", "prose", 582, "Reach of an Answer",
     "The SS remembers apply (once, mission, always or an apply_options value) from decision.resolved "
     "and applies it to later acts."),
    ("SUP-P12", "prose", 619, "Replay and Recovery",
     "Routing change: the SS accepts agent.bound, mission approved + log entries, and issued-token "
     "events as replay, and rebuilds its state from them."),
    ("SUP-P13", "prose", 621, "Replay and Recovery",
     "The SS answers unknown_mission when it has no record of mission_s256."),
    ("SUP-P14", "prose", 627, "Errors",
     "Error bodies follow the core Error Response Format; signature failures are 401 with "
     "Signature-Error; codes and statuses per the Errors table."),
    ("SUP-P15", "prose", 307, "Clarification",
     "Clarification reuses core Clarification Required (L292), whose `timeout` is 'Seconds "
     "until the server times out the request' (Protocol L1071). This SS enforces the timeout "
     "it states: a reply, poll or cancel after it gets 408 expired, and a timeout of 0 is not "
     "stated."),
    ("SUP-P16", "prose", 310, "Clarification",
     "An updated_request is the same request: core, Updated Request, has the PS check that its "
     "resource token has the same iss, ps, sub, agent_jkt, mission_s256 and tenant as the original; "
     "this SS checks it too and refuses one that differs."),
    ("SUP-P17", "prose", 310, "Clarification",
     "A signed DELETE withdraws an open clarification (the record is abandoned, the pending URL "
     "answers 410). A DELETE after the SS answered does not rewrite that answer."),
]

# Rows that bind another role, with the reason the SS has nothing to implement.
NA: dict[str, str] = {
    "SUP-009": "PS routing configuration",
    "SUP-010": "PS routing configuration",
    "SUP-018": "the keywords bind the PS; the row's last sentence (an SS that cannot answer "
               "within the wait defers) does not arise here: this SS decides within the "
               "request, so a pluggable policy must answer within the wait (SUP-P04 note)",
    "SUP-045": "binds the PS, which issues the person token no later than the allow's `exp`; "
               "the SS's part, carrying `exp`, is a MAY (tested under SUP-049)",
    "SUP-057": "binds the PS (its reason field); the SS takes a `decision.resolved` with no "
               "`reason` (SUP-051's test)",
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
    "R3-011": "with an SS configured the PS applies no recorded answer (Supervision L282); "
              "this SS decides the resubmission as a new act, so a `once` answer is asked "
              "again (findings F17)",
    "R3-012": "resource display obligation",
    "R3-013": "resource execution rule",
    "R3-015": "resource metering",
    "R3-016": "SS never fetches r3_uri (the gap AAuth #256 raises)",
    "R3-017": "SS never fetches r3_uri (the gap AAuth #256 raises)",
    "R3-018": "resource implementation guidance",
    "CORE-001": "descriptive",
    "CORE-002": "descriptive",
    "CORE-003": "binds the PS (its consent surface, and a decision it makes itself); the SS "
                "keeps the distinction in its own decisions: agent-asserted data never lowers "
                "an act's class (test_policy)",
    "CORE-004": "binds the PS, which conveys the distinction to the SS: Supervision -00 forwards "
                "the resource token and the agent's `justification` as separate members, and "
                "the SS reads them as such (CORE-003)",
    "REF-005": "binds the recipient of the question (the PS, for the agent); the SS refuses "
               "any other answer (REF-007)",
    "REF-006": "agent obligation",
    "REF-008": "binds the party answering a clarification (the agent, whose answer the PS "
               "relays: Supervision L310); the SS accepts an updated request "
               "(`test_conformance::test_clarify_updated_request`) and refuses one that is "
               "another request (REF-009)",
    "REF-024": "the SS publishes no description and renders none",
    "REF-025": "the SS publishes no logo",
    "REF-026": "the SS publishes no logo",
    "REF-028": "the SS publishes no terms of service",
    "REF-029": "the SS publishes no privacy policy",
    "REF-042": "agent obligation (the SS answers 202 for a clarification and for a connect "
               "awaiting the operator)",
    "REF-048": "agent obligation",
    "REF-051": "binds receivers of an error",
    "REF-052": "the SS never answers `revoked`",
    "VER-006": "binds a signer whose keys are ECDSA on P-256; the SS verifies ES256 (VER-001)",
    "VER-007": "binds agents; a PS signs to the SS as a server, under `jwks_uri` (VER-008)",
    "VER-022": "binds a resource that also serves clients outside AAuth; the SS accepts "
               "`jwks_uri` alone and names it (VER-018)",
    "VER-024": "the SS keeps no replay cache (a MAY): a request replayed within the window "
               "changes nothing, since what changes state is acted on once (under its `sdi` or "
               "`id`, Supervision L211, L316, or at a pending URL gone after its answer) and "
               "a poll only reads",
    "VER-025": "binds a verifier that first sees a signed request after a delay; the SS "
               "verifies each request as it arrives, within its window (VER-017)",
    "BUD-001": "binds the issuer of a budget (the PS or an AS); the SS issues none, and reads "
               "an offer past 15 digits as no budget (BUD-002)",
    "BUD-009": "resource obligation",
    "BUD-011": "binds the issuer of an allocation (the PS or an AS), which may revoke again; "
               "the SS issues no allocation (BUD-012) and revokes nothing (Supervision L545)",
    "BUD-012": "the SS issues no allocation, and its ceilings are per mission or, outside "
               "missions, per agent (README, What it does), never per calendar period",
    "BUD-013": "resource enforcement",
    "BUD-014": "resource enforcement",
}

# Rows tested for what they require, with a note after the tests: a SHOULD in the same
# sentence this SS does not follow, or a case the sentence names that this SS answers
# otherwise or never meets. Each is documented where its user reads about it.
NOTES: dict[str, str] = {
    "SUP-027": "a poller this SS does not accept is answered `unsupported_iss` (L188), not "
               "`unknown_pending` (`docs/findings.md` F12)",
    "REF-010": "the SS's question is to the agent, never to the person (Supervision L312): "
               "a withdrawn one is abandoned, and the SS has no one to tell",
    "SUP-P04": "this SS defers only a clarification and a connect awaiting confirmation, "
               "never a decision for lack of time (README Limitations)",
    "VER-028": "its SHOULD on `Cache-Control` and `Expires` is not followed: keys are kept "
               "on the SS's own schedule (README Limitations)",
    "R3-019": "an object under a custom `r3_member` with no `r3_s256` is taken on the PS's "
              "word",
    "BUD-010": "binds the issuer (the PS); this SS holds the same invariant for its own "
               "ceiling",
    "BUD-015": "binds the issuer (the PS); this SS holds the same invariant for its own "
               "ceiling",
}

# Rows this SS does not meet, each documented where its user reads about it.
GAP: dict[str, str] = {
    "REF-040": "the development interaction page does not rate-limit lookups of unknown "
               "codes; a connect fails for good after five wrong operator tokens with its "
               "code (README, Run it)",
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
        return "tested", shown + (f"; {NOTES[rid]}" if rid in NOTES else "")
    if rid in NA:
        return "n/a", NA[rid]
    if rid in GAP:
        return "gap", GAP[rid]
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
        if sections is not None and not any(t in sections for _, t in stack) \
                and "=" + stack[-1][1] not in sections:
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
        "`@pytest.mark.req(<id>)`), `n/a` (binds another role; reason given), `gap` (not met; "
        "documented where given), `-` open.",
        "",
    ]
    total = {"MUST": 0, "SHOULD": 0, "MAY": 0}
    state = {"tested": 0, "n/a": 0, "gap": 0, "-": 0}
    open_must: list[str] = []

    def line(rid: str, level: str, ln: str, section: str, text: str) -> str:
        st, t = _status(rid, tests)
        state[st] += 1
        if st == "-" and level in ("MUST", "prose"):
            open_must.append(rid)
        return f"| {rid} | {level} | L{ln} | {section} | {text} | {st} | {t} |"

    for fname, prefix, sections in SCOPED:
        rows = _rows(fname, prefix, sections)
        for r in rows:
            total[r[1]] += 1
        scope = "whole document" if sections is None else "sections: " + ", ".join(
            s.lstrip("=") for s in sections)
        out += [f"## {fname} ({scope})", "",
                "| Id | Level | Line | Section | Requirement | Status | Test |",
                "|---|---|---|---|---|---|---|"]
        out += [line(r[0], r[1], r[3], r[4], r[5]) for r in rows]
        out.append("")
    out += [
        "## Behaviour stated without BCP 14 keywords (prose)",
        "",
        "Supervision -00 states these SS behaviours in prose (a keyword in the same lines is a row",
        "of its own above), so their Level is `prose`. They are listed so they get tests like any",
        "keyword row, and an untested one fails the check like an untested MUST. SUP-P15 to SUP-P17",
        "add what this SS does where the draft leaves it implicit; SUP-P16 is a check the core puts",
        "on the PS (Updated Request) that this SS makes as well.",
        "",
        "| Id | Level | Line | Section | Requirement | Status | Test |",
        "|---|---|---|---|---|---|---|",
    ]
    out += [line(c[0], c[1], str(c[2]), c[3], c[4]) for c in CURATED]
    out.append("")
    rows_n = sum(total.values())
    out.insert(4, f"Rows: {rows_n} keyword rows (MUST {total['MUST']}, SHOULD {total['SHOULD']}, "
                  f"MAY {total['MAY']}) + {len(CURATED)} prose. Status: {state['tested']} "
                  f"tested, {state['n/a']} n/a, {state['gap']} gap, {state['-']} open.")
    text = "\n".join(out) + "\n"
    if "--check" in sys.argv:
        stale = OUT.read_text(encoding="utf-8") != text
        if stale:
            print("conformance-matrix.md is stale: run python tools/extract_matrix.py")
        if open_must:
            print("MUST or prose rows with no test and no n/a reason: " + ", ".join(open_must))
        print(f"tested {state['tested']}, n/a {state['n/a']}, gap {state['gap']}, "
              f"open {state['-']}")
        return 1 if stale or open_must else 0
    OUT.write_text(text, encoding="utf-8", newline="\n")  # LF on every platform
    print(f"wrote {OUT}: tested {state['tested']}, n/a {state['n/a']}, gap {state['gap']}, "
          f"open {state['-']}"
          + (f"; open MUST: {', '.join(open_must)}" if open_must else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
