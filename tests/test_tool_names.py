"""A tool name is decided, and shown to the person, as exactly what it is.

A permission's `action`, an audit record's `action` and the tool names of a mission
proposal are the agent's words, matched as written against rules, `ask_tools` and the
mission's approved tools. A name with a control or format character (a zero-width space,
a bidi override) or leading or trailing whitespace would match none of them while the
question the PS shows the person, which cannot show those characters, reads as the name
it imitates. Such a name is refused (`invalid_request`). A name that merely looks like another (a homoglyph)
is a different name, and the README says so.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

BAD = ["SendEmail ", " SendEmail", "Send" + chr(0x200B) + "Email", "Send" + chr(0x202E) + "Email",
       "Send" + chr(9) + "Email", "SendEmail" + chr(0x2028), ""]
# Characters that show as nothing, or as a blank, without being a control or format
# character: variation selectors, the grapheme joiner, Hangul fillers, the Braille blank,
# a Mongolian variation selector, a no-break space and an unassigned code point.
INVISIBLE = [0xFE0F, 0xFE00, 0xE0100, 0x034F, 0x3164, 0x115F, 0x1160, 0xFFA0, 0x2800, 0x180B,
             0x17B4, 0x00A0, 0x2007, 0x3000, 0x0378]
BAD += ["Send" + chr(c) + "Email" for c in INVISIBLE] + ["SendEmail" + chr(c) for c in INVISIBLE]


def _env() -> tuple[Any, Any, Any, str]:
    ss, ps, clock = make_env()
    return ss, ps, clock, connected((ss, ps, clock))


@pytest.mark.parametrize("name", BAD)
def test_a_permission_for_a_name_with_hidden_characters_is_refused(name: str) -> None:
    ss, ps, clock, s256 = _env()
    r = ps.call(ss, "POST", "/decision", {
        "sdi": ps.nid("d"), "act": "permission", "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "mission_s256": s256, "action": name, "parameters": {}})
    assert r.status == 400 and r.json()["error"] == "invalid_request", r.body


@pytest.mark.parametrize("name", BAD)
def test_a_proposal_naming_such_a_tool_is_refused(name: str) -> None:
    ss, ps, clock, _ = _env()
    r = ps.call(ss, "POST", "/mission", {
        "sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# Task",
        "tools": [{"name": name, "description": "x"}], "resources": []})
    assert r.status == 400 and r.json()["error"] == "invalid_request", r.body


@pytest.mark.parametrize("name", BAD)
def test_an_audit_record_of_such_an_action_is_refused(name: str) -> None:
    ss, ps, clock, s256 = _env()
    r = ps.call(ss, "POST", "/event", {
        "event": "audit.recorded", "id": ps.nid("e"), "iat": int(clock()), "sub": SUB,
        "agent": AGENT, "mission_s256": s256, "action": name, "parameters": {}})
    assert r.status == 400 and r.json()["error"] == "invalid_request", r.body


def test_ordinary_names_are_decided() -> None:
    ss, ps, clock, s256 = _env()
    # Marks that are seen pass: a Devanagari vowel sign, a combining accent.
    hindi = "".join(chr(c) for c in (0x092E, 0x0947, 0x0932, 0x0020, 0x092D, 0x0947, 0x091C))
    for name in ("SendEmail", "mcp.files/read", "Envoyer le courriel", "Lire", hindi,
                 "Cafe" + chr(0x0301)):
        r = ps.call(ss, "POST", "/decision", {
            "sdi": ps.nid("d"), "act": "permission", "iat": int(clock()), "sub": SUB,
            "agent": AGENT, "mission_s256": s256, "action": name, "parameters": {}})
        assert r.status == 200, (name, r.body)


@pytest.mark.parametrize("resource", ["https://EXFIL.example", "https://exfil.example/",
                                      "https://exfil.example:443", "http://exfil.example",
                                      "exfil.example", 5])
def test_a_proposal_resource_that_is_not_a_server_identifier_is_refused(resource: Any) -> None:
    # Approved resources are matched against policy patterns as exact strings, so a
    # variant would pass a `deny_resources` entry (Protocol L1948-L1969).
    ss, ps, clock, _ = _env()
    r = ps.call(ss, "POST", "/mission", {
        "sdi": ps.nid("d"), "iat": int(clock()), "sub": SUB, "agent": AGENT,
        "agent_token": ps.agent_token(AGENT), "description": "# Task", "tools": [],
        "resources": ["https://mail.example", resource]})
    assert r.status == 400 and r.json()["error"] == "invalid_request", r.body
