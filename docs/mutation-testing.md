# Mutation testing

Mutation testing checks the tests, not the code: it makes small changes ("mutants") to
the source and runs the suite against each one. A mutant the suite fails on is
**killed**. A mutant that passes the whole suite **survived**: either a test is missing,
or the change has no observable behaviour (an **equivalent** mutant). Every survivor
below is either killed by a test added for it or listed as equivalent, with the reason,
but for 10 that targeted code since removed or simplified.

## Method

- **The 0.1.0 code base:** mutmut 2.5.1 over `policy.py`, `httpsig.py` and
  `service.py`, with string, f-string and decorator mutations disabled
  (`--disable-mutation-types string,fstring,decorator`). The suite then asserted on
  error *codes* and statuses, not on human-readable messages, so a garbled message was
  not observable to a conforming client; asserting exact prose everywhere would make the
  suite brittle without making the server safer. Later tests do pin some messages (the
  policy loader's refusals, what an ask tells the person), which mutants of those strings
  would now fail. Survivors are confirmed with
  `tools/mutation_recheck.py` (see "How to run").
- **Lines added or changed in 0.2.0:** every changed line of `policy.py`, `service.py`
  and `store.py` under an AST mutator (comparison, boolean, arithmetic, negation,
  constant, dropped statement, `return None`), and, for each later change up to these
  runs, one mutant per decision the change makes (a gate disabled, a bound lifted, a window moved, a
  check removed), run against the tests written for it.

## Results

### 0.1.0 code base (mutmut 2.5.1)

| Module | Mutants | Killed | Equivalent | Real survivors |
|---|---|---|---|---|
| `policy.py` | 403 | 386 | 17 | 0 |
| `httpsig.py` | 173 | 173 | 0 | 0 |
| `service.py` | 573 | 572 | 1 | 0 |

### Lines added or changed in 0.2.0

| Area | Mutants | Killed | Equivalent |
|---|---|---|---|
| Every changed line of `policy.py`, `service.py`, `store.py` (AST mutator) | 179 | 168 | 11 |
| Sequence search: count check and pruning | 31 | 27 | 4 |
| Budget ledger, history timing, state, key discovery, transport | 33 | 32 | 0 (1 targeted a redundant branch, removed) |
| Open acts, open allocations, fetch deadline, signature checks, unknown paths | 24 | 23 | 0 (1 targeted a redundant `close()`, removed) |
| Mission blob shape, permission `exp`, NumericDate `exp`, `typ`, nesting and number range, PS `id`, access log, composition label, matrix generator | 42 | 42 | 0 |
| Composition across missions; person tokens where a resource serves on identity | 27 | 27 | 0 |
| Cost of composition across missions | 15 | 12 | 3 |
| Recipients in a value and across parameters, agent text in what the person sees, access log escapes | 74 | 74 | 0 |
| Composition across instances of one agent provider, and the index that finds them | 43 | 38 | 3 (2 targeted code since removed or rewritten) |
| Replay per token, open acts in every scope, person-token decisions, `if_unknown` with a proposal, call chains outside missions, reach certainty, tool names | 63 | 61 | 0 (2 targeted code since removed) |
| Work under the store lock: composition passes, indexes, clarification caps, signature field and rate-table bounds, decisions a policy may give | 58 | 56 | 1 (1 targeted a redundant check, removed) |
| Key discovery: lock, single flight, least-recently-used eviction, kept signers, backoff, URL and name checks | 25 | 25 | 0 |
| Listener framing, request targets, error format, 405 and HEAD, keys and digests, one SS per port and state file | 44 | 43 | 1 |
| Policy loader patterns, mission expiry, pending order, `documentation_uri`, reasons for "may", agent-raised classes, kept updates, advisor time bound | 38 | 38 | 0 |
| Command line files, `kid`, `keygen`, Markdown marks and lists, confirmation page origin, egress settings | 26 | 25 | 0 (1 targeted code since simplified) |
| Person tokens at mission approval, the class of an unread data rule, an answer per plain gate, an act under two classes in the search, connect ids and lifetime, open-registration bounds, proposal members, methods, re-keying, snapshot writes, `aud` bounds, the reach index, the request deadline and connection cap, start-up, eviction and the fetch floor, RFC 3339 times, the confirmation page, Markdown marks, loader bounds and patterns, tool lists, published URLs, error lines | 128 | 123 | 3 (2 targeted code since simplified) |
| Every class of an act whose class agent data raised (gates, budgets with each class's amount, compositions, the search, reasons), patterns walked against the identifier grammar, instances and missions linked by open acts, approval tokens decided in turn and on an ask, refusals and retries that write nothing, ids and names kept for open registration and its fair share at the cap, `description` and tool-name bounds, the listener at capacity, fetch floors kept, the bounded name read | 55 | 53 | 2 |
| **Total** | **905** | **867** | **28** (and 10 that targeted code since removed or simplified) |

A full mutmut run over the 0.2.0 lines has not been made; the lines added up to these
runs are covered by the mutants above, and every line is under the 100% line and branch
coverage gate. Changes made after these runs were not mutated: among them how acts are
placed in time against a token's end (the PS's lead and `transit_allowance`), the order
of late reports and replays, and the classes an act may have where data a rule needs is
missing. Each began with a test that failed before the change, and the property-based
tests and the coverage gate apply to them as to the rest. The
model-based `tests/test_properties_cross_mission.py`, run alone against 12 of the
cross-mission mutants when it was written, killed the 7 within what it models (the others
concern another person, budgets, a refusal with reach, sequences across several missions,
or the act's own mission seen twice, and the deterministic tests kill them). It is a
check of its model, not a mutant killer: its model asks on any act of the other half, so
it tells few cases apart.

Later gaps, each closed by a test added for it: a composition the search over all
missions could not settle that a mission's own pass settles; an index whose table is
replaced by one as large; a key dropped from an index that stays dropped; a pending
record replaced under its id; a retry that finds the newest question for its `sdi`;
questions withdrawn or timed out, and a further round of an open one, not counting
against the cap; the round-limit note; a signature field of 16 KiB against one of 6 KiB;
the resolver's wait starting over after a success, and its table touched only under its
lock; a refused claim of the state file leaving nothing open; a composition across two
of an agent's missions naming them; an earlier act's class with the agent's data set
aside; a composition found both ways keeping the firmer answer; a data rule
that matched an act's operation but could not read it; an unread class no more severe
than the rule's; the most severe of several unread data rules; answers to the two plain
gates kept side by side, and an answer to the intent gate in the trace; `Retry-After`
counted from the oldest connect held; a trusted PS's records kept while a stranger's are
removed, and a removed record found under neither its code nor its person; repeated
connects and reports, and gone URLs, writing nothing; a reach table emptied in place; a
read still waiting when the request's deadline passes; the IPv6 loopback; resource
patterns with `!` or `]` first in a class; a pattern whose label passes 63
characters whatever its wildcards match; the tokens of one approval decided in turn when
history already holds acts; a resource named twice named once; and a disconnect with
nothing to disconnect from a signer only open registration admits writing nothing.

## What it found

Defects in the code, each fixed with a regression test:

- **A pluggable policy that still asked after the round limit got a terminal `clarify`.**
  The built-in policy never asks again once the agent has answered, so the round limit
  was reached only by a policy that ignores `clarify=False`; the mutants on that path
  survived until such a policy was written for them, and it showed the SS sending a 200
  with `decision: clarify`. A decision the protocol does not define now goes to the
  person (`tests/test_clarification_rounds.py`).
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
- **The fetch deadline did not stop a worker.** `close()` alone left the worker reading,
  because the response's file still held the socket; the socket is now shut down
  (`tests/test_egress_loopback.py::test_trickled_headers_hit_the_same_deadline`).

Gaps in the tests, each closed by a test added for it: the one-second clarification
timeout; an expired poll whose decision record is gone; the `exp` reader at its bounds
and with no `exp`; search backtracking; an act reported exactly at a token's `exp`; the
composition named when two certain ones are open; the order the search tries windows in;
the earliest one-off act and the live-token rules of the search; a token reported twice
with an earlier `exp`; open acts with no comparable budget or an unknown amount; an exact
fit of a ceiling with open allocations; a resource token whose header is not an object;
another person's mission of the same agent; a migrated refusal outside missions; a person
token for two listed audiences, and one with an empty audience; the layered policy's
delegation of `serves_on_identity`; a recipient list split by line breaks, which only
a whole-value match refuses; a control character that is not whitespace, and line and
paragraph separators inside a fenced block; a code span that opens with a
backtick; a mission of another instance in which only another provider's agent acted; an
agent identifier whose store key escapes a literal `%7C`; and the agent index read
incrementally and holding only agents with a history outside missions. The model-based
`tests/test_properties_cross_mission.py` does not pin the composition of instances (a
mutant that finds no provider survives it); the deterministic tests in
`tests/test_agent_provider.py` do.

The surviving mutants also showed which behaviour the scenario suites exercised without
pinning. These test modules pin it:

| Test module | Pins |
|---|---|
| `tests/test_config_defaults.py` | Every configuration default (the safe ones: no auto-connect, no open registration, R3 extension off) |
| `tests/test_policy_loader.py` | Every loader refusal, with its message, and every member at its boundary |
| `tests/test_policy_semantics.py` | Each engine rule at its edge: matching, data rules, provenance, amounts, budgets, composition, reach, expiry, proposals |
| `tests/test_httpsig_semantics.py` | Each RFC 9421 check with its non-refusal neighbour: windows, labels, `expires`, `alg`, Signature-Key members, response checks |
| `tests/test_service_semantics.py` | Member types, routing, Accept-Signature, retry caching, clarification rounds, permissions, every event's effect, the defensive 500 |
| `tests/test_service_edges.py` | Discovery endpoints, rate limiting, connect acceptance, the interaction page |

## Equivalent mutants

No caller can observe these:

- **Type annotations** (`A | None` to `A & None`). Every module uses
  `from __future__ import annotations`, and nothing evaluates the annotations of the
  mutated modules at runtime (the only `typing.get_type_hints` call is in `store.py`,
  for its own snapshot dataclasses); mypy is their gate. These are the 16
  dataclass-field annotations in `policy.py` and the one `ServerConfig.from_dict`
  type-map annotation in `service.py`.
- **A `Protocol` method's default argument** (`SupervisionPolicy.decide`,
  `clarify=True`). The stub body is `...` and never executes; implementations define
  their own signature.
- **Lines marked `# pragma: no mutate`**, each with its reason beside it: the empty
  body of a bodiless `GET` or `DELETE` (its handler never reads it), two flags in
  `Policy._scan` read only for truthiness, two type aliases in `sfv.py` used only in
  annotations, and `ensure_ascii` in the request fingerprint (it changes no distinction,
  but changing it would change every stored fingerprint, so a retry across an upgrade
  would no longer match its `sdi`).

On the 0.2.0 lines:

| Mutant | Why it is equivalent |
| --- | --- |
| `_SEQUENCE_SEARCH_BUDGET` and its decrement and comparison off by one (4, and 3 of them again in the pruning set) | Shift the budget by a step or two; exhaustion is pinned by a test with a budget of 2 against a search that needs far more. |
| `range(i + 1, n)` -> `range(i - 1, n)` | Visits entries before `i` first; `last` is overwritten by every later entry within the `exp`, and an earlier one only matters when `exp` precedes the token's own report, where the window still ends at `i`. |
| `last > i` -> `last >= i` | Gives `i + 0.5` instead of `i` when no later entry is within the `exp`; no other act has a moment between the two. |
| Trace text for an overriding reach (2) | Diagnostic wording; tests match the composition, not the prefix. |
| `UNBOUNDED_EXP` `2 ** 62` -> `3 ** 62` or `2 ** 63` (2) | Any value beyond every real `exp` behaves the same. |
| History merge key `else 0` -> `else 1` | A secondary key for numbered entries only; their `n` is unique, so it never decides. |
| The count check counting each act twice (`sum(1 ...)` -> `sum(2 ...)`) | The check is a shortcut; with the pruning, the search reaches the same answer without it. |
| The person filters that find the other instances (3) | They bound the work to the person: another person's agent has no history under this person's keys, and the person's missions are filtered again where they are read. |
| A mission's certain pass run when the act itself is uncertain, or with uncertain acts left in its pool (3) | Extra work whose results the pass over all missions already gives (adding acts never makes a composition harder to complete); `tests/test_cross_mission_scale.py` checks the answer against the plain per-mission computation. |
| The person's other missions found by comparing missions, not their digests | Two missions of one person compare equal only when their digests are equal; the digest set is one lookup per mission instead of a scan. |
| The listener reading a target that starts with `//` as a URL | The standard library has already turned a leading `//` into `/` (CPython gh-87389) before the handler sees the target. |
| The retry after a failed verification made even when the refreshed key is the one that failed | Verifying again with the same key gives the same answer; the check only saves the work. |
| The last check of `_can_match` (that the candidate matches the pattern) removed, in its first form | Candidates were built from the pattern as `fnmatch` reads it, so every candidate that is an identifier matched; the check guarded that construction. `_can_match` has since been rewritten as a search over the identifier grammar. |
| An unclosed `[` in a pattern read as any identifier character, not as itself | Every path through the pattern takes that `[`, which no identifier holds: without the mutant no path exists, and with it the witness lacks the `[` that `fnmatch` reads literally, so the final check refuses it. |
| A class that agent data lowered, held to the class with the data unknown, always uncertain | Where that class is certain, the scan with every deciding data rule set aside closes at the same rule with no more unread data, so it gives that class, certain, and the firmest reading of each class is kept. |
| The index reset after pending records are removed | An index is built again when its table shrinks (`_Index.sync`); the reset also covers a direct write to the table in between, which no current path makes. |

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

On Windows, mutmut 2.5.1 records as survived some mutants that the suite kills when the
mutant is applied by hand, so survivors are not taken from mutmut:
`tools/mutation_recheck.py` applies each one, clears the bytecode caches, runs the full
suite with bytecode writing off, and restores the source. Only mutants that pass the
whole suite there count as survivors.

mutmut 2.5.1 on Windows also counts a mutant as killed only when the runner exits with
status 1. A mutant that breaks import makes pytest exit with 2 (collection error), which
mutmut then records as *survived*. Wrap the runner in a script that maps any non-zero
exit to 1:

```
@echo off
python -B -m pytest -q -x -p no:cacheprovider <tests>
if errorlevel 1 exit /b 1
exit /b 0
```

The same applies on POSIX (`pytest ...; [ $? -eq 0 ] || exit 1`).
