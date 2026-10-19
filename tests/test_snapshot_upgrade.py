"""A state file written by 0.1.x loads with its tokens still live.

0.1.x kept no `token_exp` on a history entry (it checked a sequence only at its last
step). An entry it wrote for an issued auth token is a token whose `exp` the SS does not
know, and must load as one: read as a one-moment grant, a token taken before the upgrade
for a later step of a sequence would no longer stop the earlier steps after it. So is a
permission grant, which has no lifetime; an audit record reports an action already taken.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from conftest import AGENT, SUB, Clock, connected

from aauth_supervision_server.egress import StaticFetcher
from aauth_supervision_server.jwk import SigningKey
from aauth_supervision_server.policy import Policy, PolicyConfig
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.service import ServerConfig, SupervisionServer, TrustedPS
from aauth_supervision_server.store import UNBOUNDED_EXP, Store
from aauth_supervision_server.testing import SimulatedPS

A, B, C = "https://a.example", "https://b.example", "https://c.example"
POLICY = {"severity": ["unclassified", "A", "B", "C"],
          "rules": [{"resource": A, "class": "A"}, {"resource": B, "class": "B"},
                    {"resource": C, "class": "C"}, {"resource": "*", "tool": "Note",
                                                    "class": "A"},
                    {"resource": "*", "tool": "Mark", "class": "B"}],
          "prohibited_sequences": [["A", "B", "C"]]}
NEW_FIELDS = ("token_exp", "n", "borrowed", "agent", "amount_known", "scope", "unplaced",
              "after_n", "iat", "blind", "wide", "open")
NEW_RECORD_FIELDS = ("recorded_n", "resolved_n", "resolved_at")


class Rig:
    def __init__(self, state: Path, policy: dict[str, Any] | None = None) -> None:
        self.state, self.clock, self.fetcher = state, Clock(), StaticFetcher()
        self.policy = policy or POLICY
        self.ps = SimulatedPS(clock=self.clock)
        self.ps.install(self.fetcher)
        self.key = SigningKey.generate("ss-key-1")
        self.ps.ss_jwk = self.key.public_jwk()
        self.ss = self.server()

    def server(self) -> SupervisionServer:
        cfg = ServerConfig(issuer="https://ss.example",
                           trusted_ps={self.ps.issuer: TrustedPS(auto_connect=True)})
        return SupervisionServer(cfg, Policy(PolicyConfig.from_dict(self.policy)),
                                 JwksUriResolver(self.fetcher), self.key,
                                 store=Store(str(self.state)), clock=self.clock)

    def take(self, s256: str, res: str, scope: str = "") -> str:
        sdi, r, _ = self.ps.auth_token_request(self.ss, SUB, AGENT, s256, res, scope=scope)
        d = str(r.json()["decision"])
        if d == "allow":
            assert self.ps.issued(self.ss, SUB, AGENT, s256, sdi, res, scope).status == 201
        return d

    def as_written_by_0_1(self) -> None:
        """Rewrite the state file the way 0.1.x wrote it: no token_exp, n or borrowed."""
        data = json.loads(self.state.read_text())
        data["version"] = 1
        for m in data["missions"].values():
            for h in m["history"]:
                for k in NEW_FIELDS:
                    del h[k]
        for v in data["agent_history"].values():
            for h in v:
                for k in NEW_FIELDS:
                    del h[k]
        for d in data["decisions"].values():
            for k in NEW_RECORD_FIELDS:
                d.pop(k, None)
            if isinstance(d.get("entry"), dict):
                for k in NEW_FIELDS:
                    d["entry"].pop(k, None)
        self.state.write_text(json.dumps(data))

    def restart(self) -> None:
        self.ss = self.server()
        assert self.ss.store.load_error == ""


def test_a_token_taken_before_the_upgrade_still_stops_the_earlier_steps(tmp_path: Path) -> None:
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A, B, C))
    assert rig.take(s256, C) == "allow"           # the last step's token, under 0.1.x
    rig.as_written_by_0_1()
    rig.clock.t += 60
    rig.restart()
    assert rig.take(s256, A) == "allow"
    assert rig.take(s256, B) == "deny"            # the C token can still be presented


def _event(rig: Rig, s256: str, **members: Any) -> None:
    body = {"id": rig.ps.nid("e"), "iat": int(rig.clock()), "sub": SUB, "agent": AGENT,
            **members}
    if s256:
        body["mission_s256"] = s256
    assert rig.ps.call(rig.ss, "POST", "/event", body).status == 201


def test_what_each_legacy_entry_was_is_kept(tmp_path: Path) -> None:
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A, B, C),
                     tools=[{"name": "Note", "description": "notes"}])
    assert rig.take(s256, A) == "allow"                                   # issued token
    sdi = rig.ps.nid("d")
    r = rig.ps.call(rig.ss, "POST", "/decision", {
        "sdi": sdi, "act": "permission", "iat": int(rig.clock()), "sub": SUB, "agent": AGENT,
        "mission_s256": s256, "action": "Note"})
    assert r.json()["decision"] == "allow"                                # permission grant
    _event(rig, s256, event="audit.recorded", action="Note")              # audit record
    assert rig.take("", C) == "allow"                                     # outside missions
    _event(rig, s256, event="auth_token.issued", sdi="d-elsewhere", aud=B, jti="j",
           exp=int(rig.clock()) + 60)                                      # replayed token
    rig.as_written_by_0_1()
    rig.restart()
    hist = rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, s256)
    assert [(h.action_class, h.token_exp) for h in hist] == [
        ("A", UNBOUNDED_EXP), ("A", UNBOUNDED_EXP), ("A", None), ("B", UNBOUNDED_EXP)]
    outside = rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, "")
    assert [(h.action_class, h.token_exp) for h in outside] == [("C", UNBOUNDED_EXP)]


def test_entries_this_version_wrote_load_as_written(tmp_path: Path) -> None:
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A, B, C),
                     tools=[{"name": "Note", "description": "notes"}])
    assert rig.take(s256, A) == "allow"
    before = [(h.action_class, h.token_exp, h.n)
              for h in rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, s256)]
    rig.restart()
    after = [(h.action_class, h.token_exp, h.n)
             for h in rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, s256)]
    assert after == before and before[0][1] not in (None, UNBOUNDED_EXP)


def test_an_amount_0_1_never_saw_stays_unseen_after_the_upgrade(tmp_path: Path) -> None:
    # 0.1.x booked an act of unseen amount as 0; read as a known 0 after the upgrade, a
    # later payment would be checked against too low a total.
    from aauth_supervision_server.store import HistoryEntry
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A,))
    m = rig.ss.store.missions[f"{rig.ps.issuer}|{s256}"]
    rig.ss.store.add_history(m.history, HistoryEntry("payment", A, "configured", amount=0))
    rig.ss.store.add_history(m.history, HistoryEntry("payment", A, "resource", amount=700))
    rig.ss.store.save()
    rig.as_written_by_0_1()
    rig.restart()
    hist = rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, s256)
    assert [(h.amount, h.amount_known) for h in hist] == [(0, False), (700, True)]


def test_a_late_report_of_a_decision_0_1_made_floats_after_the_upgrade(tmp_path: Path) -> None:
    # Decided by 0.1.x and issued at t, reported after the upgrade, after an audited B
    # action 0.1.x recorded at t + 5: stamped before it, it surely came first, as
    # delivered in order.
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A, B, C),
                     tools=[{"name": "Mark", "description": "m"}])
    sdi_a, r, _ = rig.ps.auth_token_request(rig.ss, SUB, AGENT, s256, A)
    assert r.json()["decision"] == "allow"
    t = int(rig.clock())
    rig.clock.t += 5
    _event(rig, s256, event="audit.recorded", action="Mark")
    rig.as_written_by_0_1()
    rig.clock.t += 5
    rig.restart()
    _event(rig, s256, event="auth_token.issued", sdi=sdi_a, iat=t, aud=A, jti="a-late",
           exp=t + 3600)
    assert rig.take(s256, C) == "deny"


def test_a_late_report_0_1_booked_itself_floats_after_the_upgrade(tmp_path: Path) -> None:
    # 0.1.x booked a report where it arrived, after acts it may have preceded.
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(A, B, C),
                     tools=[{"name": "Mark", "description": "m"}])
    sdi_a, r, _ = rig.ps.auth_token_request(rig.ss, SUB, AGENT, s256, A)
    assert r.json()["decision"] == "allow"
    t = int(rig.clock())
    rig.clock.t += 5
    _event(rig, s256, event="audit.recorded", action="Mark")
    _event(rig, s256, event="auth_token.issued", sdi=sdi_a, iat=t, aud=A, jti="a-late",
           exp=t + 3600)
    rig.as_written_by_0_1()
    rig.restart()
    assert rig.take(s256, C) != "allow"


def test_an_ask_0_1_saw_answered_awaits_its_token_from_the_upgrade(tmp_path: Path) -> None:
    # Answered before the upgrade, when 0.1.x kept no answer time: its token may still be
    # issued, and used before acts recorded since.
    rig = Rig(tmp_path / "ss.json")
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(B, C))
    sdi_a, r, _ = rig.ps.auth_token_request(rig.ss, SUB, AGENT, s256, A)
    assert r.json()["decision"] == "ask"
    rig.clock.t += 7200
    assert rig.ps.resolved(rig.ss, SUB, AGENT, s256, sdi_a, "allow").status == 201
    rig.as_written_by_0_1()
    rig.restart()
    rig.clock.t += 5
    assert rig.take(s256, B) == "allow"
    rig.clock.t += 15
    assert rig.take(s256, C) != "allow"


MAIL, W, P = "https://mail.example", "https://w.example", "https://p.example"
SENDS = {"severity": ["unclassified", "write", "post", "send_internal", "send_external"],
         "rules": [{"resource": MAIL, "scope": "mail.send", "class": "send_internal",
                    "if_unknown": "send_external"},
                   {"resource": W, "class": "write"}, {"resource": P, "class": "post"}],
         "prohibited_sequences": [["send_internal", "write"], ["send_external", "post"]]}


def _after_a_send(state: Path, upgrade: bool) -> tuple[str, str]:
    """A mail send of unknown recipients, then a write, then a post, across a restart."""
    rig = Rig(state, SENDS)
    s256 = connected((rig.ss, rig.ps, rig.clock), resources=(MAIL, W, P))
    assert rig.take(s256, MAIL, "mail.send") == "allow"
    [sent] = rig.ss.store.history_for(rig.ps.issuer, SUB, AGENT, s256)
    assert (sent.action_class, [a.cls for a in sent.blind]) == ("send_external", ["send_internal"])
    if upgrade:
        rig.as_written_by_0_1()
    rig.restart()
    return rig.take(s256, W), rig.take(s256, P)


def test_an_act_0_1_recorded_keeps_the_one_class_it_was_booked_with(tmp_path: Path) -> None:
    # A send whose recipients are not known is assumed external and may be internal: as
    # this version records it, it composes as both. A 0.1.x entry holds the one class it
    # was booked with, the external send, and composes as that class alone: it takes the
    # external-send step of a sequence, never the internal-send one.
    assert _after_a_send(tmp_path / "now.json", upgrade=False) == ("ask", "ask")
    assert _after_a_send(tmp_path / "old.json", upgrade=True) == ("allow", "ask")
