"""Release metadata stays in one story: package, pyproject, changelog and pinned drafts."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

import aauth_supervision_server

ROOT = Path(__file__).resolve().parents[1]


def test_package_version_matches_pyproject() -> None:
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert meta["project"]["version"] == aauth_supervision_server.__version__


def test_changelog_names_the_release_and_its_draft() -> None:
    log = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    version = re.escape(aauth_supervision_server.__version__)
    assert re.search(rf"^## \[{version}\].*{aauth_supervision_server.DRAFT}", log, re.M)
    assert aauth_supervision_server.DRAFT_COMMIT in log


def test_pinned_draft_is_the_one_in_specs() -> None:
    specs = " ".join(p.name for p in (ROOT / "specs").iterdir())
    assert "supervision" in specs.lower()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert aauth_supervision_server.DRAFT_COMMIT in readme


def test_no_matrix_row_puts_a_keyword_in_the_drafts_mouth() -> None:
    """Every row of the conformance matrix cites a line of a pinned draft. A keyword row's
    Level is a BCP 14 keyword that line carries; a curated row, which the draft states in
    plain prose, says `prose`, so the matrix never attributes a MUST the draft does not
    use. No row cites a blank line or a heading."""
    matrix = (ROOT / "docs" / "conformance-matrix.md").read_text(encoding="utf-8")
    keyword = {"MUST": r"\b(MUST|SHALL|REQUIRED)\b", "SHOULD": r"\b(SHOULD|RECOMMENDED)\b",
               "MAY": r"\b(MAY|OPTIONAL)\b"}
    spec: list[str] = []
    rows = 0
    for line in matrix.splitlines():
        h = re.match(r"## (draft-[\w.-]+\.md) ", line)
        if h or line.startswith("## Behaviour stated without BCP 14 keywords"):
            name = h.group(1) if h else "draft-hardt-aauth-supervision.md"
            spec = (ROOT / "specs" / name).read_text(encoding="utf-8").splitlines()
        m = re.match(r"\| [A-Z0-9]+-[A-Z0-9]+ \| (\w+) \| L(\d+) \|", line)
        if not m:
            continue
        rows += 1
        level, cited = m.group(1), spec[int(m.group(2)) - 1]
        assert cited.strip() and not cited.startswith("#"), line
        assert level == "prose" or re.search(keyword[level], cited), line
    assert rows == 206  # 189 keyword rows and 17 curated


def test_an_untested_prose_row_fails_the_matrix_check(monkeypatch, capsys) -> None:
    """Relabelling the curated rows `prose` must not let one go untested: the check fails
    for an untested prose row exactly as for an untested MUST."""
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("extract_matrix",
                                                  ROOT / "tools" / "extract_matrix.py")
    assert spec is not None and spec.loader is not None
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    tested = tool._tests_by_row()
    monkeypatch.setattr(sys, "argv", ["extract_matrix.py", "--check"])
    monkeypatch.setattr(tool, "_tests_by_row",
                        lambda: {k: v for k, v in tested.items() if k != "SUP-P01"})
    assert tool.main() == 1
    assert "SUP-P01" in capsys.readouterr().out
