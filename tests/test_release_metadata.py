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
