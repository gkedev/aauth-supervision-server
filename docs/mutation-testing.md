# Mutation testing

Mutation testing checks the tests, not the code: it makes small changes ("mutants") to
the source and runs the suite against each one. A mutant the suite fails on is
**killed**. A mutant that passes the whole suite **survived**: either a test is missing,
or the change has no observable behaviour (an **equivalent** mutant). Every survivor
below was examined and is either killed by a test added for it or listed as
equivalent, with the reason.

## Results (2026-10-08, mutmut 2.5.1)

The campaign ran before the late hardening and feature changes: non-finite parameter
values and the AAuth Budgets ceiling in `policy.py`, and server-identifier validation,
the operator-token byte comparison and lockout, and the Budgets claim parsing and ledger
in `service.py`. Each has tests that fail when the change is reverted, and the lines are
under the 100% coverage gate. The Budgets logic also went through a hand campaign of 16
targeted mutants (ceiling boundaries, the unreported-allocation rule, unit comparison,
range limits, reconciliation by `jti` and resource), all killed by
`tests/test_budgets.py`; `examples/layered_policy.py` through one of 14, all killed. A
full mutmut campaign over the new lines has not been run yet.

| Module | Mutants | Killed | Equivalent | Real survivors |
|---|---|---|---|---|
| `policy.py` | 403 | 386 | 17 | 0 |
| `httpsig.py` | 173 | 173 | 0 | 0 |
| `service.py` | 573 | 572 | 1 | 0 |

Counts are after the 100%-branch-coverage work: `parse_list` and two dead guards were
removed from the source, so there are fewer mutants and fewer equivalents than the
2026-10-07 campaign. Every non-killed mutant was re-verified with
`tools/mutation_recheck.py` (below) and is listed under equivalents; no module has a
real survivor.

String and f-string literal mutations and decorator removal are disabled
(`--disable-mutation-types string,fstring,decorator`). The suite asserts on error
*codes* and statuses, never on human-readable messages, so a garbled message is not
observable to a conforming client; asserting exact prose everywhere would make the
suite brittle without making the server safer.

## What it found

Mutation testing found two defects, both fixed with regression tests:

- **A short prohibited sequence crashed every decision.** The policy loader accepted a
  `prohibited_sequences` entry with fewer than two classes (`[]`), and evaluating it
  raised `IndexError`. `serve` was protected (`validate_policy` refused the file);
  library use through `PolicyConfig.from_dict` was not. The loader now refuses it
  (`tests/test_policy_loader.py`).
- **A reordered retry got a signature that did not verify.** A retry with the same
  members in a different order is the same request (the fingerprint is canonical), but
  it was answered with the stored signed response, whose `content-digest;req` was the
  original request's. It is now signed for the delivery
  (`tests/test_service_semantics.py::test_a_retry_with_members_reordered_is_the_same_request`).

The 2026-10-08 re-verification (on the 100%-coverage source) left three live survivors
in `service.py`, each now pinned by a test:

- **The one-second clarification timeout.** `clarification_timeout > 0` differs from
  `> 1` only at exactly 1 second. A `clarification_timeout` of 1 must still set a real
  deadline and still be stated in the clarify body
  (`test_a_one_second_timeout_still_sets_a_deadline_and_is_stated`).
- **An expired poll whose record was pruned.** Past the deadline the poll is `expired`
  (408). The guard `rec and rec.decision == "clarify"` must not dereference a missing
  record; even if the decision record has been pruned the poll must still 408, never
  fall into the defensive 500
  (`test_an_expired_poll_whose_record_is_gone_still_times_out_cleanly`).

All three were confirmed killed: red under the hand-applied mutant, green when restored.

The surviving mutants also showed which behaviour the scenario suites exercised
without pinning. These tests were added for them:

| Test module | Pins |
|---|---|
| `tests/test_config_defaults.py` | Every configuration default (the safe ones: no auto-connect, no open registration, R3 extension off) |
| `tests/test_policy_loader.py` | Every loader refusal, with its message, and every member at its boundary |
| `tests/test_policy_semantics.py` | Each engine rule at its edge: matching, data rules, provenance, amounts, budgets, composition, reach, expiry, proposals |
| `tests/test_httpsig_semantics.py` | Each RFC 9421 check with its non-refusal neighbour: windows, labels, `expires`, `alg`, Signature-Key members, response checks |
| `tests/test_service_semantics.py` | Member types, routing, Accept-Signature, retry caching, clarification rounds, permissions, every event's effect, the defensive 500 |
| `tests/test_service_edges.py` | Discovery endpoints, rate limiting, connect acceptance, the interaction page |

## Equivalent mutants

After the 100%-coverage work the only mutants that survive re-verification are ones no
caller can observe:

- **Type annotations** (`A | None` to `A & None`). Every module uses
  `from __future__ import annotations`, and nothing evaluates the annotations of the
  three mutated modules at runtime (the only `typing.get_type_hints` call is in
  `store.py`, for its own snapshot dataclasses); mypy is their gate. These are the 16 dataclass-field annotations in `policy.py` and
  the one `ServerConfig.from_dict` type-map annotation in `service.py`. `httpsig.py` has
  none left.
- **A `Protocol` method's default argument** (`SupervisionPolicy.decide`,
  `clarify=True`). The stub body is `...` and never executes; implementations define
  their own signature. (policy, 1)

The earlier campaign (2026-10-07) also listed equivalents that no longer exist: the
`parse_list` SFV helper and two dead guards in `service.py` (an `iat` type check already
done for every body, and a `POST`-only `body_required` test) were removed from the
source during the coverage work, so there is nothing left to mutate there.

## Re-verifying survivors

On Windows, mutmut 2.5.1 records mutants as survived that the suite kills when the
mutant is applied by hand. In the 2026-10-08 campaign it reported 21 non-killed mutants
in `policy.py` and 20 in `service.py` (`httpsig.py` had none); re-verification killed 4
of the policy set and 16 of the service set outright. Of the service remainder, three
were real boundary/robustness gaps now pinned by tests (above) and one is a type
annotation. The cause of mutmut's miscount was not isolated, so the table does not take
survivors from mutmut:
`tools/mutation_recheck.py` applies each one, clears the bytecode caches, runs the full
suite with bytecode writing off, and restores the source. Only mutants that pass the
whole suite there are counted as survivors, and each of those is an equivalent listed
above.

## How to run

mutmut 2.5.x is configured in `setup.cfg`. A whole-module run against the full suite
is slow (each mutant runs the suite); scope one module and a focused runner:

```
python -m mutmut run --paths-to-mutate src/aauth_supervision_server/policy.py \
  --disable-mutation-types string,fstring,decorator \
  --runner "python -m pytest -q -x -p no:cacheprovider tests/test_policy.py tests/test_policy_semantics.py tests/test_policy_loader.py tests/test_adversarial.py"
python -m mutmut results
python -m mutmut show <id>
python tools/mutation_recheck.py src/aauth_supervision_server/policy.py   # confirm the survivors
```

On Windows, mutmut 2.5.1 counts a mutant as killed only when the runner exits with
status 1. A mutant that breaks import makes pytest exit with 2 (collection error), which
mutmut then records as *survived*. Wrap the runner in a script that maps any non-zero
exit to 1, or such mutants are false survivors:

```
@echo off
python -B -m pytest -q -x -p no:cacheprovider <tests>
if errorlevel 1 exit /b 1
exit /b 0
```

The same applies on POSIX (`pytest ...; [ $? -eq 0 ] || exit 1`).
