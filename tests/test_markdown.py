"""The two ways the SS puts text it did not write into Markdown (`markdown.py`)."""
from __future__ import annotations

import unicodedata

import pytest

from aauth_supervision_server import markdown


@pytest.mark.parametrize("raw,out", [
    ("DeleteRepo", "`DeleteRepo`"),
    ("a`b", "``a`b``"),
    ("a``b`c", "```a``b`c```"),
    ("`edge`", "`` `edge` ``"),
    ("x`", "`` x` ``"),
    ("`start", "`` `start ``"),
    ("<img src=x>", "`<img src=x>`"),
    ("two\nlines", "`two lines`"),
    ("", "``"),
])
def test_code_is_a_span_no_backtick_inside_can_close(raw: str, out: str) -> None:
    assert markdown.code(raw) == out


def test_code_is_cut_short() -> None:
    assert markdown.code("abcdef", limit=4) == "`abc\u2026`"


@pytest.mark.parametrize("raw,out", [
    ("one line", "```\none line\n```"),
    ("a\r\nb\rc", "```\na\nb\nc\n```"),
    ("```\nfenced\n```", "````\n```\nfenced\n```\n````"),
    ("tab\tkept\u202e", "```\ntab\tkept\n```"),
    ("a\x1bb\u2028c\u2029d", "```\nabcd\n```"),
    ("", "```\n\n```"),
])
def test_block_is_fenced_longer_than_any_backtick_run(raw: str, out: str) -> None:
    assert markdown.block(raw) == out


def test_the_default_lengths() -> None:
    cut = chr(0x2026)  # the ellipsis that ends a cut text
    assert markdown.code("a" * 501) == "`" + "a" * 499 + cut + "`"
    assert markdown.block("a" * 4001) == "```\n" + "a" * 3999 + cut + "\n```"


def test_block_is_cut_short() -> None:
    assert markdown.block("abcdef", limit=4) == "```\nabc\u2026\n```"


def test_combining_marks_are_kept_to_four_on_a_character() -> None:
    acute, ring = "\u0301", "\u20dd"   # a combining accent; an enclosing mark
    assert markdown.code("e" + acute * 9) == "`e" + acute * 4 + "`"
    assert markdown.code("x" + ring * 2 + "y" + acute * 5) == (
        "`x" + ring * 2 + "y" + acute * 4 + "`")
    assert markdown.block("a" + acute * 6 + "\nb" + acute) == (
        "```\na" + acute * 4 + "\nb" + acute + "\n```")
    # Vietnamese keeps every mark it uses.
    assert markdown.code("ho\u0323\u0302") == "`ho\u0323\u0302`"


def test_marks_are_capped_on_the_visible_character_whatever_unseen_ones_separate_them() -> None:
    # A Hangul filler (Lo, default-ignorable) is drawn as nothing: marks after it land on
    # the same visible character, so it does not start a new run.
    def stacked(s: str) -> int:  # the most marks drawn on one visible character
        best = run = 0
        for c in s:
            if unicodedata.category(c) in ("Mn", "Me"):
                run += 1
                best = max(best, run)
            elif not markdown._unseen(c):
                run = 0
        return best

    marks = "\u0301\u0302\u0303\u0304"
    for filler in ("\u1160", "\u115f", "\u3164", "\uffa0", "\u200b"):
        for render in (markdown.code, markdown.block):
            assert stacked(render("x" + (marks + filler) * 30)) == markdown.MAX_MARKS
    # A visible character takes the marks after it.
    assert markdown.code("a\u0301b\u0301") == "`a\u0301b\u0301`"


def test_a_plain_name_shows_nothing_unseen_and_is_cut() -> None:
    assert markdown.plain("Acme\u202e PS\u2066 ", 64) == "Acme PS"
    assert markdown.plain("A" * 100, 10) == "A" * 9 + "\u2026"
    assert markdown.plain("\u3164\u200b", 10) == ""


def test_a_plain_name_reads_only_a_bounded_prefix() -> None:
    # A name of any length costs the same: only the first characters can be shown, so
    # only a prefix is read. Counted in what is read, not timed, so a slow runner cannot
    # fail it.
    read: list[object] = []

    class Name(str):
        def __getitem__(self, k: object) -> str:  # type: ignore[override]
            read.append(k)
            return str.__getitem__(self, k)  # type: ignore[index]

        def __iter__(self):  # type: ignore[no-untyped-def]
            read.append("all")
            return str.__iter__(self)

    assert markdown.plain(Name("N" * 2_000_000), 64) == "N" * 63 + chr(0x2026)
    assert read == [slice(None, 4 * 64)]
