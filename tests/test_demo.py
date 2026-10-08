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
    # AAuth Budgets: two allocations fit, the third does not until spend is reported.
    assert "5.00 USD of the 25.00\n         USD mission ceiling is left" in out
    assert out.count("SS: ALLOW") == 5
    assert "may complete a prohibited composition (read_sensitive then\n         send_external)" in out
    assert "The person decides what the SS could not" in out and "Nothing was sent." in out
    assert "7 decisions: 5 allow, 2 ask." in out
    assert "--extension" in out  # the closing hint points at the extension run
    assert "trace:" not in out


def test_with_the_proposal_forwarded_the_ss_denies_it_itself() -> None:
    out = run(extension=True, trace=True)
    assert "R3 proposal forwarded (AAuth #256, extension)" in out
    assert "SS: DENY. This act would complete a prohibited composition: read_sensitive then" in out
    assert "The person decides what the SS could not" not in out
    assert "7 decisions: 5 allow, 1 ask, 1 deny." in out
    assert "trace: send_external|https://mail.example, completes read_sensitive then" in out
    assert "trace: read|https://inference.example" in out


def test_no_line_is_wider_than_a_terminal() -> None:
    for line in (run() + "\n" + run(extension=True, trace=True)).splitlines():
        assert len(line) <= 88, line


def test_the_demo_policy_is_a_valid_policy() -> None:
    assert validate_policy(json.loads(demo.policy_json())) == []


@pytest.mark.parametrize("argv,needle", [(["demo"], "7 decisions: 5 allow, 2 ask."),
                                         (["demo", "--extension"], "1 deny."),
                                         (["demo", "--show-policy"], '"resource_budgets"')])
def test_the_command(argv: list[str], needle: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 0
    assert needle in capsys.readouterr().out
