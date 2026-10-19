"""Text the SS did not write, inside the Markdown it gives the PS to show the person.

An ask's `summary` is "a Markdown string the PS presents alongside the request"
(Supervision L266) and each `apply_options` `label` is Markdown the PS shows the person
(L584). Some of what the SS says there is the agent's (a justification, a tool name, a
mission update) or a resource's (a budget unit, unless a short word of ASCII letters,
`policy._offered`). It must reach the person as the text it is: never as an image the PS
would load (a channel out for whatever the agent has read), a link, HTML, or emphasis or
a block that reads as the supervisor's own words.

Control and format characters (line breaks, bidi overrides, zero-width marks) become a
space in the one-line forms (`code`, `plain`) and are removed from a block, which keeps
only its line breaks and tabs; combining marks are kept to a few on one character (enough for any
script's accents, too few to draw over the lines around), and each form is cut to a
length, so a quotation cannot reorder, hide, cover or bury the supervisor's text around
it. Section numbers are CommonMark 0.31.2.
"""

from __future__ import annotations

import re
import unicodedata

# Controls, format characters (bidi overrides, zero-width marks), surrogates, and line
# and paragraph separators.
_HIDDEN = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
# Combining marks that stack on the character before them.
_MARKS = frozenset({"Mn", "Me"})
MAX_MARKS = 4
_TICKS = re.compile(r"`+")

CODE_LIMIT = 500
BLOCK_LIMIT = 4000


# Unicode's Default_Ignorable_Code_Point (DerivedCoreProperties.txt, Unicode 15.1):
# characters a renderer shows as nothing, among them the variation selectors, the
# combining grapheme joiner and the Hangul fillers, which are not all format characters.
_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160),
    (0x17B4, 0x17B5), (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E),
    (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF))
_BRAILLE_BLANK = 0x2800


def _unseen(c: str) -> bool:
    """A character the person cannot tell apart from nothing or from a space: a control
    or format character, a separator, a default-ignorable or unassigned code point, a
    space other than U+0020, or the Braille blank."""
    cat, n = unicodedata.category(c), ord(c)
    return cat in _HIDDEN or cat == "Cn" or (cat == "Zs" and c != " ") \
        or n == _BRAILLE_BLANK or any(lo <= n <= hi for lo, hi in _IGNORABLE)


def hides(s: str) -> bool:
    """Whether `s` holds a character the person cannot see, or starts or ends with
    whitespace."""
    return s != s.strip() or any(_unseen(c) for c in s)


def _few_marks(s: str) -> str:
    """`s` with at most MAX_MARKS combining marks on one visible character. A character
    the person cannot see (`_unseen`, a Hangul filler for one) is drawn as nothing, so the
    marks after it land on the same character: it does not start a new run."""
    out: list[str] = []
    run = 0
    for c in s:
        if unicodedata.category(c) in _MARKS:
            run += 1
            if run > MAX_MARKS:
                continue
        elif not _unseen(c):
            run = 0
        out.append(c)
    return "".join(out)


def _cut(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[:limit - 1] + "\u2026"


def _one_line(s: str, limit: int) -> str:
    s = "".join(" " if unicodedata.category(c) in _HIDDEN else c for c in s)
    return _cut(" ".join(_few_marks(s).split()), limit)


def plain(s: str, limit: int) -> str:
    """`s` as one line of plain text for a page: no character the person cannot see, no
    more than MAX_MARKS marks on one character, cut to `limit` characters. For a name
    another party chose (a PS's `name`), which the page escapes for HTML itself. Only the
    first `4 * limit` characters are read, so a name of any length costs the same."""
    s = "".join(" " if _unseen(c) else c for c in s[:4 * limit])
    return _cut(" ".join(_few_marks(s).split()), limit)


def _fence(s: str, least: int) -> str:
    return "`" * max(least, max((len(m) for m in _TICKS.findall(s)), default=0) + 1)


def code(s: str, limit: int = CODE_LIMIT) -> str:
    """`s` as a code span (CommonMark 6.1), shown literally: the fence is longer than any
    run of backticks in `s`, so nothing inside can close it."""
    s = _one_line(s, limit)
    fence = _fence(s, 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def block(s: str, limit: int = BLOCK_LIMIT) -> str:
    """`s`, which may span lines, as a fenced code block (CommonMark 4.5), shown literally:
    the fence is longer than any run of backticks in `s`, so no line inside can close it."""
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = _cut(_few_marks("".join(c if c in "\n\t" or unicodedata.category(c) not in _HIDDEN
                                else "" for c in s)), limit)
    fence = _fence(s, 3)
    return f"{fence}\n{s}\n{fence}"
