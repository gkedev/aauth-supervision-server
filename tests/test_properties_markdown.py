"""Property: whatever the text, the two Markdown forms show it as written.

Checked against what CommonMark 0.31.2 says each form means, not against the code: a
code span ends only at a backtick string as long as the one that opened it, and drops
one space at each end when both are there
(6.1); a fenced block ends only at a line of at least as many backticks as its fence,
indented by at most three spaces and followed by nothing but spaces or tabs (4.5).
"""
from __future__ import annotations

import itertools
import re
import unicodedata

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from aauth_supervision_server import markdown

HIDDEN = {"Cc", "Cf", "Cs", "Zl", "Zp"}
MARKS = {"Mn", "Me"}
UNBOUNDED = 10 ** 6
TEXTS = st.text(max_size=60) | st.text(
    alphabet="`*_[]()<>!&\\ \n\r\t\u202e\u200b\u2028ab@.", max_size=60)


def few_marks(s: str) -> str:
    """`s` with each run of combining marks cut to its first four."""
    return "".join("".join(list(run)[:4] if is_mark else run)
                   for is_mark, run in itertools.groupby(
                       s, key=lambda c: unicodedata.category(c) in MARKS))


def one_line(s: str) -> str:
    """What the person reads of `s` on one line: hidden characters gone, spacing collapsed,
    combining marks kept to four in a row."""
    return " ".join(few_marks("".join(" " if unicodedata.category(c) in HIDDEN else c
                                      for c in s)).split())


@settings(max_examples=400, deadline=None)
@given(TEXTS)
def test_a_code_span_shows_the_text(s: str) -> None:
    assume(one_line(s))
    out = markdown.code(s, limit=UNBOUNDED)
    n = len(out) - len(out.lstrip("`"))
    assert out.endswith("`" * n) and not out.endswith("`" * (n + 1)) and len(out) > 2 * n
    inner = out[n:-n]
    assert not inner.startswith("`") and not inner.endswith("`")  # the fences stay whole
    assert all(len(run) != n for run in re.findall(r"`+", inner))  # nothing inside closes
    if inner.startswith(" ") and inner.endswith(" ") and inner.strip(" "):
        inner = inner[1:-1]
    assert inner == one_line(s)


@settings(max_examples=400, deadline=None)
@given(TEXTS)
def test_a_fenced_block_shows_the_text(s: str) -> None:
    out = markdown.block(s, limit=UNBOUNDED)
    lines = out.split("\n")
    fence = lines[0]
    assert set(fence) == {"`"} and len(fence) >= 3 and lines[-1] == fence
    for line in lines[1:-1]:
        body = line.lstrip(" ")
        run = len(body) - len(body.lstrip("`"))
        closes = (len(line) - len(body) <= 3 and run >= len(fence)
                  and not body[run:].strip(" \t"))
        assert not closes, out
    written = s.replace("\r\n", "\n").replace("\r", "\n")
    assert "\n".join(lines[1:-1]) == few_marks("".join(
        c for c in written if c in "\n\t" or unicodedata.category(c) not in HIDDEN))
