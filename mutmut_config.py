"""mutmut hooks: skip the two kinds of mutant that cannot change behaviour by construction.

mutmut (2.5) reads this module from the working directory. Each skipped mutant is
reported by mutmut as `skipped`, never as killed; `docs/mutation-testing.md` counts them
apart. Everything else is mutated and must be killed or listed as equivalent.

* **Annotations.** Every module uses `from __future__ import annotations`, so an
  annotation is a string that is never evaluated at runtime (mypy is its gate). mutmut
  already skips parameter annotations and bare `x: T`; this also skips the annotation of
  `x: T = value` and a return annotation, where it would turn `A | None` into `A & None`.
  The `= value` default on the same line is still mutated.
* **Protocol declarations.** The body of a `class X(Protocol):` is a declaration
  (`def m(self) -> T: ...`) that never executes, the same rule coverage applies
  (`exclude_also` in pyproject.toml).
"""
from __future__ import annotations

from typing import Any

import mutmut

_probe: dict[str, Any] = {"active": False, "skip": False}


def _is_annotation(parent: Any, child: Any) -> bool:
    kids = getattr(parent, "children", [])
    if parent.type == "annassign":
        return len(kids) > 1 and child is kids[1]
    if parent.type == "funcdef":
        return any(k.type == "operator" and k.value == "->" and kids[i + 1] is child
                   for i, k in enumerate(kids[:-1]))
    return False


def _in_protocol(stack: list[Any]) -> bool:
    for node in stack:
        kids = getattr(node, "children", [])
        if node.type == "classdef" and len(kids) > 4 and kids[2].type == "operator" \
                and kids[2].value == "(":
            bases = [b.strip() for b in kids[3].get_code().split(",")]
            if "Protocol" in bases:
                return True
    return False


def pre_mutation_ast(context: Any) -> None:
    if not _probe["active"] or context.mutation_id_of_current_index != context.mutation_id:
        return
    stack = context.stack
    if _in_protocol(stack) or any(_is_annotation(p, c)
                                  for p, c in zip(stack, stack[1:], strict=False)):
        _probe["skip"] = True


def pre_mutation(context: Any) -> None:
    """Re-derive this mutant on a fresh context, and skip it if it is one of the above."""
    probe = mutmut.Context(source=context.source, mutation_id=context.mutation_id,
                           filename=context.filename, dict_synonyms=context.dict_synonyms,
                           config=context.config)
    _probe.update(active=True, skip=False)
    try:
        mutmut.mutate(probe)
    finally:
        _probe["active"] = False
    if _probe["skip"]:
        context.skip = True
