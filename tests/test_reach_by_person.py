"""A decision reads the person's reach rows only, through an index kept by person.

The reach table holds every person's answers with reach (Supervision L582). A decision
for one person is handed that person's rows, found through an index that grows with the
table, so its cost does not grow with other people's answers.
"""
from __future__ import annotations

from typing import Any

from conftest import AGENT, SUB, connected, make_env

from aauth_supervision_server.store import Reach

MAIL = "https://mail.example"


def _spy(ss: Any) -> list[list[Reach]]:
    seen: list[list[Reach]] = []
    decide = ss.policy.decide

    def spied(act: Any, mission: Any, history: Any, reach: list[Reach], *a: Any,
              **kw: Any) -> Any:
        seen.append(list(reach))
        return decide(act, mission, history, reach, *a, **kw)

    ss.policy.decide = spied
    return seen


def test_a_decision_is_handed_the_person_s_rows_only() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    others = [Reach("always", ps.issuer, f"person-{i}", AGENT, f"send_internal|{MAIL}")
              for i in range(500)]
    mine = Reach("always", ps.issuer, SUB, AGENT, "read_internal|https://hr.example")
    ss.store.reach.extend(others[:250] + [mine] + others[250:])
    seen = _spy(ss)
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert r.status == 200
    assert seen == [[mine]]
    # A row added later is found too, and the table may be replaced whole.
    later = Reach("mission", ps.issuer, SUB, AGENT, f"send_internal|{MAIL}", s256)
    ss.store.reach.append(later)
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert seen[-1] == [mine, later]
    ss.store.reach = [later]
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert seen[-1] == [later]


def test_a_table_emptied_in_place_is_read_again() -> None:
    ss, ps, clock = make_env()
    s256 = connected((ss, ps, clock))
    mine = Reach("always", ps.issuer, SUB, AGENT, "read_internal|https://hr.example")
    ss.store.reach.append(mine)
    seen = _spy(ss)
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    ss.store.reach.clear()
    ps.auth_token_request(ss, SUB, AGENT, s256, "https://hr.example")
    assert seen == [[mine], []]
