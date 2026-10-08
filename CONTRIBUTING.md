# Contributing

Thank you for your interest. This is an independent implementation of the AAuth
Supervision Server, pinned to revision -00 of the AAuth Supervision draft (AAuth commit
`70d67375`). Contributions that
improve conformance, test rigour, interoperability, or clarity are welcome.

## Where things belong

- **Code, tests, docs in this repository:** open an issue or pull request here.
- **A weakness in the protocol itself** (not in this code): it belongs upstream in
  the [AAuth repository](https://github.com/dickhardt/AAuth), per `SECURITY.md`.
- **A suspected vulnerability:** report it privately; see `SECURITY.md`.

Everyone taking part is expected to follow the `CODE_OF_CONDUCT.md` (Contributor
Covenant 2.1).

## Before you open a pull request

Run the full offline gate. Once dependencies are installed it needs no network and no
running second implementation, and it
is exactly what CI runs on Linux, macOS and Windows:

```
python tools/check.py      # inside the activated .venv, on any OS
```

The auth-go interop tests need a Go toolchain (1.26 or later) on `PATH`; without one
they skip locally. CI installs Go and sets `AAUTH_SS_REQUIRE_GO=1`, so there they always
run. Set it yourself to make a missing toolchain fail rather than skip.

A change is ready when the gate is green end to end:

- **ruff** and **mypy** (strict typing of `src/`) are clean.
- The suite passes under **100% line and branch coverage** of `src/`
  (`fail_under = 100`, no inline `pragma: no cover`). New code comes with the tests
  that cover it.
- `docs/conformance-matrix.md` and `docs/adversarial-results.md` are **regenerated**,
  not hand-edited, and match their generators (`tools/extract_matrix.py`,
  `tools/run_adversarial.py`). A new behaviour that satisfies a draft requirement
  carries `@pytest.mark.req(<id>)` so its matrix row names a test.

For a decision-critical change to `policy.py`, `httpsig.py` or `service.py`, run
mutation testing and either kill every surviving mutant or record it as equivalent
with a reason (`docs/mutation-testing.md`, `tools/mutation_recheck.py`).

## Scope and style

- Match the surrounding style; keep `src/` fully typed.
- Keep the protocol layer (`service.py`) policy-agnostic: decision logic lives behind
  the `SupervisionPolicy` interface (see "the policy is a plug" in `README.md`).
- Extensions beyond Supervision -00 (for example R3 proposal forwarding) stay **off by
  default** and are marked non-spec.
- Note the draft revision you targeted; the implementation tracks a moving draft.

## Licensing and attribution of contributions

By contributing, you agree that your contribution is licensed under **Apache-2.0**,
the licence of this repository (the drafts under `specs/` keep the IETF Trust's
terms). Keep authorship accurate and your own: do not add third-party or
machine-generated authorship marks or co-author trailers to commits or text.

Note that the AAuth drafts are part of the IETF Standards Process. Anything you take
*upstream* to the AAuth repository (issues, comments, pull requests) is a Contribution
under BCP 78/79, with the public, irrevocable attribution that entails. That applies
to the AAuth repository, not to this one.
