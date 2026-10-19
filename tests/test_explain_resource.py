"""`aauth-ss explain` decides only what `serve` would: a resource that is not a server
identifier (Protocol L1948-L1969), which the SS refuses at its endpoints, is an error, not
a decision a policy author could take as the SS's.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aauth_supervision_server import cli

POLICY = str(Path(__file__).resolve().parents[1] / "examples" / "policy.json")


@pytest.mark.parametrize("resource", ["https://Mail.example", "https://mail.example/",
                                      "mail.example", "https://mail.example:443"])
def test_a_resource_the_ss_refuses_is_an_error(capsys: Any, resource: str) -> None:
    assert cli.main(["explain", POLICY, "--resource", resource]) == 2
    out = capsys.readouterr()
    assert "server identifier" in out.err and out.out == ""


def test_a_server_identifier_is_explained(capsys: Any) -> None:
    assert cli.main(["explain", POLICY, "--resource", "https://mail.example"]) == 0
    assert '"decision"' in capsys.readouterr().out
