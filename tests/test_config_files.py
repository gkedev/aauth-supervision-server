"""Configuration files and the CLI: malformed input names the member, examples are valid."""

from __future__ import annotations

import json
import re

import pytest
from conftest import ROOT

from aauth_supervision_server.cli import main, validate_policy
from aauth_supervision_server.policy import PolicyConfig
from aauth_supervision_server.service import ServerConfig

POLICY = json.loads((ROOT / "examples" / "policy.json").read_text())
SERVER = json.loads((ROOT / "examples" / "server.json").read_text())


@pytest.mark.parametrize("patch, where", [
    ({"high_imapct": ["payment"]}, "high_imapct"),  # a misspelt key would drop a protection
    ({"severity": "read"}, "severity"),
    ({"high_impact": [1]}, "high_impact"),
    ({"allow_unlisted_resources": "no"}, "allow_unlisted_resources"),
    ({"max_mission_seconds": -5}, "max_mission_seconds"),
    ({"rules": [{"resource": "*"}]}, "rules[0]"),
    ({"rules": [{"class": "read", "tool": 5}]}, "rules[0].tool"),
    ({"rules": [{"class": "read", "param_gt": {"amount": "10"}}]}, "rules[0].param_gt"),
    ({"rules": [{"class": "read", "when": "never"}]}, "rules[0].when"),
    ({"prohibited_pairs": [["read"]]}, "prohibited_pairs"),
    ({"budgets": {"payment": {"max_amount": -1}}}, "budgets.payment.max_amount"),
    ({"budgets": {"payment": {"max_ammount": 5}}}, "budgets.payment.max_ammount"),
])
def test_a_malformed_policy_names_the_member(patch, where):
    d = POLICY | patch
    with pytest.raises(ValueError, match="^" + re.escape(where) + ":"):
        PolicyConfig.from_dict(d)
    assert validate_policy(d) and where in validate_policy(d)[0]


def test_the_example_policy_is_valid():
    assert validate_policy(POLICY) == []


@pytest.mark.parametrize("patch", [
    {"open_registraton": True}, {"signature_window": "60"}, {"rate_limit_per_minute": -1},
    {"open_registration": 1}, {"trusted_ps": {"https://ps.example": {"autoconnect": True}}},
    {"trusted_ps": {"https://ps.example": {"tenants": "corp.example"}}}])
def test_a_malformed_server_config_is_an_error(patch):
    d = {k: v for k, v in SERVER.items() if k != "egress"} | patch
    with pytest.raises(ValueError, match="server config"):
        ServerConfig.from_dict(d)


def test_the_example_server_config_is_valid():
    cfg = ServerConfig.from_dict({k: v for k, v in SERVER.items() if k != "egress"})
    assert cfg.trusted_ps["https://ps.example"].tenants == ["corp.example"]


def _run(capsys, *argv):
    try:
        rc = main(list(argv))
    except SystemExit as e:  # argparse-level and file errors exit with a message
        rc = e.code if isinstance(e.code, int) else 1
        err = str(e.code) if not isinstance(e.code, int) else ""
        return rc, capsys.readouterr().err + err
    return rc, capsys.readouterr().err


def test_cli_reports_bad_files_without_a_traceback(tmp_path, capsys):
    rc, err = _run(capsys, "check-policy", str(tmp_path / "missing.json"))
    assert rc != 0 and "missing.json" in err and "Traceback" not in err
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    rc, err = _run(capsys, "explain", str(bad), "--resource", "https://x.example")
    assert rc != 0 and "not valid JSON" in err
    typo = tmp_path / "typo.json"
    typo.write_text(json.dumps(POLICY | {"high_imapct": []}), encoding="utf-8")
    rc, err = _run(capsys, "explain", str(typo), "--resource", "https://x.example")
    assert rc != 0 and "high_imapct" in err
    srv = tmp_path / "server.json"
    srv.write_text(json.dumps(SERVER | {"egress": {"timeuot": 5}}), encoding="utf-8")
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps(POLICY), encoding="utf-8")
    rc, err = _run(capsys, "serve", "--config", str(srv), "--policy", str(pol))
    assert rc == 2 and "egress" in err


def test_a_file_nested_past_the_json_reader_is_reported_without_a_traceback(tmp_path, capsys):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 200_000 + "]" * 200_000, encoding="utf-8")
    for argv in (("check-policy", str(deep)),
                 ("explain", str(deep), "--resource", "https://x.example")):
        rc, err = _run(capsys, *argv)
        assert rc != 0 and "deep.json: not valid JSON (nested too deep)" in err, err


def test_the_transit_allowance_is_a_server_setting() -> None:
    # How long the fastest of a PS's requests may take to reach the SS: read from the
    # server config, and like every count never negative.
    cfg = ServerConfig.from_dict({"issuer": "https://ss.example", "transit_allowance": 10})
    assert cfg.transit_allowance == 10
    assert ServerConfig(issuer="https://ss.example").transit_allowance == 2
    with pytest.raises(ValueError, match="must not be negative"):
        ServerConfig.from_dict({"issuer": "https://ss.example", "transit_allowance": -1})


@pytest.mark.parametrize("member", ["signature_window", "transit_allowance",
                                    "clarification_timeout"])
def test_a_time_setting_past_a_day_is_an_error(member: str) -> None:
    # Seconds the SS adds to its clock: a value past a day is no window an operator means,
    # and one past the float range would fail every request that reads it.
    base = {"issuer": "https://ss.example"}
    assert getattr(ServerConfig.from_dict(base | {member: 86_400}), member) == 86_400
    for v in (86_401, 10**309):
        with pytest.raises(ValueError, match=f"server config: {member} must be at most"):
            ServerConfig.from_dict(base | {member: v})
        with pytest.raises(ValueError, match=f"server config: {member} must be at most"):
            ServerConfig(issuer="https://ss.example", **{member: v})  # built directly too


def test_check_policy_names_the_default_class_when_severity_lacks_it() -> None:
    # An empty policy uses `default_class` ("unclassified") for every act: the problem
    # says where the class comes from, not only that it is missing.
    problems = validate_policy({})
    assert any("default_class" in p and "unclassified" in p for p in problems), problems
