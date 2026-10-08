# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this tracks an unsubmitted draft, every version also names the draft
revision it implements. The drafts are pinned to the AAuth repository at commit
`70d67375deb0bb002af7da0711fc58f6e8926e7e`.

## [Unreleased]

## [0.1.0] - 2026-10-08: implements AAuth Supervision -00

Initial public release.

### Added

- The SS side of Supervision -00: metadata and JWKS, connect, the mission endpoint,
  the decision endpoint for `person_token`, `auth_token` and `permission`, events,
  deferred decisions and clarification (with an enforced `timeout`), signed decisions,
  idempotence, replay and recovery, and the error table.
- RFC 9421 request verification and response signing under the AAuth profile, with
  `jwks_uri` key discovery under egress admission (HTTPS only, no private destinations,
  DNS pinning, no redirects).
- The APC policy: declarative action classes, provenance on every classification,
  composition closure across resources, per-mission budgets, intent checks, and the
  reach of the person's answers. It sits behind the `SupervisionPolicy` interface, so it
  can be replaced without touching the protocol layer.
- R3 forwarding (the change [AAuth #256](https://github.com/dickhardt/AAuth/issues/256) proposes) of a per-call proposal or the R3
  document a resource token references, checked against `r3_s256`, off by default.
- Composition across a delegation chain: history is per mission, so an exfiltration
  split between a parent agent, a sub-agent (`subagent_token`) and a call chain
  (`upstream_token`) still composes.
- AAuth Budgets: per-mission ceilings at metered resources (`resource_budgets`), held
  against the `budget` offer and the signed `budget_consumed` record in the forwarded
  resource token, with every unreported allocation counted as fully consumed. Adversarial
  scenario T10 shows it deciding correctly under Supervision -00 as written.
- `aauth-ss demo`: a narrated mission run against the real server, in-process, with real
  signatures and no network (`--extension` forwards the R3 proposal; `--trace`).
- `examples/layered_policy.py`: the APC policy as a deterministic floor with an advisor
  (standing preferences, or any language model) that may refuse any act the floor would
  ask about but settle only the low-stakes ones.
- The `aauth-ss` command: `keygen`, `check-policy`, `explain` and `serve`.
- A conformance matrix generated from the pinned drafts (83 tested, 23 n/a, 0 open) and
  an adversarial suite of ten attack scenarios under four configurations.
- The offline merge gate (`tools/check.py`), run by CI on Linux, macOS and Windows with
  Python 3.11 to 3.13: ruff, strict mypy, 100% line and branch coverage, Hypothesis
  property and model-based lifecycle tests, and staleness checks for the generated docs.
- Mutation testing of `policy.py`, `httpsig.py` and `service.py`, with every surviving
  mutant re-verified against the full suite (`docs/mutation-testing.md`).
- Signature interop with two independent AAuth implementations in both directions:
  regent-httpsig (Python) and auth-go (Go, draft -11), plus a full mission against the
  server with every PS request signed by auth-go (`tests/test_interop_regent_httpsig.py`,
  `tests/test_interop_auth_go.py`, `interop/auth-go/`).
