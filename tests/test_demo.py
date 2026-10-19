"""`aauth-ss demo`: the narrated mission runs the real SS and tells the truth about it."""

from __future__ import annotations

import json

import pytest

from aauth_supervision_server import demo
from aauth_supervision_server.cli import main, validate_policy


def run(**kw: bool) -> str:
    lines: list[str] = []
    assert demo.run(out=lines.append, **kw) == 0
    return "\n".join(lines)


def test_under_supervision_00_the_exfiltration_is_put_to_the_person() -> None:
    out = run()
    assert "Transport: Supervision -00 as written." in out
    # AAuth Budgets: two allocations fit, the third does not, and a consumption record for
    # a live token frees nothing (Budgets L841: it "settles nothing").
    assert "5.00 USD of the 25.00\n         USD mission ceiling is left" in out
    assert out.count("5.00 USD of the 25.00") == 2
    assert out.count("SS: ALLOW") == 4
    assert ("may complete a combination the policy forbids: `read_sensitive`, then "
            "`send_external`.") in " ".join(out.split())
    assert "The person decides what the SS could not" in out and "Nothing was sent." in out
    assert "7 decisions: 4 allow, 3 ask." in out
    assert "--extension" in out  # the closing hint points at the extension run
    assert "trace:" not in out
    # On the -00 wire a per-call SS asks too (high impact, no resource detail): what the
    # composition adds is the reason the person is told, not the ask itself.
    flat = " ".join(out.split())
    assert "per-call SS would have allowed" not in flat
    assert "naming the composition it may complete" in flat


def test_with_the_proposal_forwarded_the_ss_denies_it_itself() -> None:
    out = run(extension=True, trace=True)
    assert "R3 proposal forwarded (AAuth #256, extension)" in out
    assert ("SS: DENY. Together with other acts, this act would complete a combination the "
            "policy forbids: `read_sensitive`, then `send_external`.") in " ".join(out.split())
    assert "The person decides what the SS could not" not in out
    assert "7 decisions: 4 allow, 2 ask, 1 deny." in out
    assert "trace: send_external|https://mail.example, completes read_sensitive then" in out
    assert "trace: read|https://inference.example" in out


def test_no_line_is_wider_than_a_terminal() -> None:
    for line in (run() + "\n" + run(extension=True, trace=True)).splitlines():
        assert len(line) <= 88, line


def test_the_demo_policy_is_a_valid_policy() -> None:
    assert validate_policy(json.loads(demo.policy_json())) == []


@pytest.mark.parametrize("argv,needle", [(["demo"], "7 decisions: 4 allow, 3 ask."),
                                         (["demo", "--extension"], "1 deny."),
                                         (["demo", "--show-policy"], '"resource_budgets"')])
def test_the_command(argv: list[str], needle: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 0
    assert needle in capsys.readouterr().out


def test_the_readme_tells_what_the_demo_shows() -> None:
    # The metered part ends on an ask: a consumption record for a live token frees nothing.
    from pathlib import Path
    readme = " ".join((Path(__file__).resolve().parents[1] / "README.md").read_text(
        encoding="utf-8").split())
    assert "is let through again" not in readme
    assert ("runs into an AAuth Budgets ceiling, which a consumption record for a token "
            "still live does not lift") in readme
    assert "6. The agent asks for another 10.00 USD" in run() and "frees nothing" in run()
