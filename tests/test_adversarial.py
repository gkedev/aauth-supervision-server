"""The adversarial suite (docs/adversarial-results.md) as a regression test."""

from __future__ import annotations

import subprocess
import sys

import pytest
from conftest import ROOT

from aauth_supervision_server.adversarial import outcome, render_markdown, run_all, start

EXPECTED = {  # scenario -> critical decision for (per-call, current, forwarded, forwarded+issued)
    "T1": ("allow", "allow", "allow", "allow"),
    "T2": ("allow", "ask", "deny", "deny"),
    "T3": ("allow", "ask", "deny", "deny"),
    "T4": ("allow", "ask", "deny", "deny"),
    "T5": ("allow", "ask", "deny", "deny"),
    "T6": ("ask", "ask", "ask", "ask"),
    "T7": ("allow", "ask", "allow", "allow"),
    "T8": ("allow", "ask", "deny", "deny"),
    "T9": ("allow", "ask", "ask", "deny"),
    "T10": ("allow", "deny", "deny", "deny"),
}


@pytest.fixture(scope="module")
def rows(tmp_path_factory):
    return run_all(str(tmp_path_factory.mktemp("adv")))


def test_critical_decisions(rows):
    got = {}
    for r in rows:
        got.setdefault(r["id"], []).append(r["decision"])
    assert {k: tuple(v) for k, v in got.items()} == EXPECTED


def test_apc_is_never_unsafe(rows):
    assert not [r for r in rows if r["config"].startswith("apc") and r["outcome"] == "unsafe"]


def test_forwarding_in_request_and_issued_decides_every_scenario(rows):
    assert all(r["outcome"] == "correct" for r in rows if r["config"] == "apc/forwarded+issued")


def test_request_forwarding_alone_does_not_survive_a_routing_change(rows):
    """The case the follow-up to AAuth #256 is about: a released result lost on replay."""
    t9 = {r["config"]: r["decision"] for r in rows if r["id"] == "T9"}
    assert t9["apc/forwarded"] == "ask" and t9["apc/forwarded+issued"] == "deny"


def test_committed_results_are_current():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "run_adversarial.py"), "--check"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_committed_matrix_is_current():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "extract_matrix.py"), "--check"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr


def test_rendered_results_are_the_committed_page(rows):
    """In process, so the renderer is measured too (the --check above runs it in a child)."""
    committed = (ROOT / "docs" / "adversarial-results.md").read_text(encoding="utf-8")
    assert render_markdown(rows) == committed


@pytest.mark.parametrize("decision,ideal,want", [
    ("deny", "deny", "correct"), ("ask", "deny", "escalated"), ("allow", "deny", "unsafe"),
    ("deny", "allow", "blocked"), ("server_error", "deny", "blocked"),
])
def test_outcome_against_the_ideal(decision, ideal, want):
    assert outcome(decision, ideal) == want


def test_a_denied_preparatory_step_is_neither_approved_nor_issued():
    run = start("apc/current")
    sent = len(run.ps.sent)
    run.complete({"sdi": "d-x", "d": {"decision": "deny"}, "resource": "https://hr.example",
                  "scope": "", "prop": None})
    assert len(run.ps.sent) == sent and run.prompts == 0
