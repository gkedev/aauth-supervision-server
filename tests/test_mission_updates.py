"""A mission update the person allows is kept, whoever decided it.

Supervision, Update: the SS answers an update with a decision. An update this SS allows
directly is kept with the mission (`Mission.updates`); one it puts to the person is kept
once the person allows it (`decision.resolved`), and not when they deny it.
"""
from __future__ import annotations

import pytest
from conftest import AGENT, SUB, connected, make_env


@pytest.mark.parametrize("answer,kept", [("allow", ["# Changed plan"]), ("deny", [])])
def test_an_update_put_to_the_person_is_kept_once_they_allow_it(answer: str,
                                                                 kept: list[str]) -> None:
    ss, ps, clock = make_env(ask_on_mission_update=True)
    s256 = connected((ss, ps, clock))
    sdi = ps.nid("d")
    r = ps.call(ss, "POST", f"/mission/{s256}", {"action": "update", "sdi": sdi,
                                                 "iat": int(clock()), "sub": SUB,
                                                 "agent": AGENT, "description": "# Changed plan"})
    assert r.json()["decision"] == "ask"
    m = ss.store.missions[f"{ps.issuer}|{s256}"]
    assert m.updates == []
    assert ps.resolved(ss, SUB, AGENT, s256, sdi, answer).status == 201
    assert m.updates == kept
