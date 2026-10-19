"""A mission past its `expires_at` is terminated on every path that acts on it.

Protocol L1425: "Every PS decision path that acts on a mission MUST compare the current
time to `expires_at` and MUST treat a mission past it as terminated". With an SS
configured the PS "makes no supervision decision of its own" (Supervision L79): the SS
decides, so an update or a completion of an expired mission is denied like any act in
it, and an update past it is not kept.
"""
from __future__ import annotations

from typing import Any

import pytest
from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import iso_to_epoch


@pytest.mark.parametrize("action,member", [("update", "description"), ("completion", "summary")])
def test_an_update_or_completion_past_expires_at_is_denied(action: str, member: str) -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    m = ss.store.missions[f"{ps.issuer}|{s256}"]
    end = iso_to_epoch(m.blob["expires_at"])
    assert end is not None

    def send() -> dict[str, Any]:
        r = ps.call(ss, "POST", f"/mission/{s256}", {"action": action, "sdi": ps.nid("d"),
                                                     "iat": int(clock()), "sub": SUB,
                                                     "agent": AGENT, member: "# Changed"})
        return r.json()

    clock.t = end - 1
    assert send()["decision"] == "allow"            # still within it
    m.state, m.updates = "active", []
    clock.t = end
    body = send()
    assert body["decision"] == "deny" and body["reason"] == "The mission has expired."
    assert m.updates == [] and m.state == "active"
