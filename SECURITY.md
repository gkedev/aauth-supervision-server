# Security

## Status

This is an independent implementation of the AAuth Supervision Server, pinned to
revision -00 of the AAuth Supervision draft (AAuth commit `70d67375`), which the draft
itself marks "Exploration, not
yet submitted." It is intended for study, interop experiments and conformance work,
not as a production authorization service. Do not place it on the decision path of a
real deployment without an independent security review.

## Supported versions

Only the latest release on the default branch receives fixes. Each release names the
draft revision it implements (`CHANGELOG.md`); when the draft moves, older releases
are not maintained.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private vulnerability
reporting (the repository's **Security** tab, "Report a vulnerability"), not in a
public issue. Include the affected version or commit, the component (for example
`httpsig`, `egress`, `service`), a minimal reproduction, and the impact you observed.
Reports are handled on a best-effort basis. Please allow reasonable time for a fix
before any public disclosure.

If the issue is in the drafts rather than in this code (a protocol-level weakness),
it belongs in the [AAuth repository](https://github.com/dickhardt/AAuth) instead.

## Threat model and hardening in this code

The server treats the person server (PS) as the only authenticated caller and treats
every byte on the wire as hostile:

- **Request authentication.** Every PS request is verified under RFC 9421 with the
  AAuth `jwks_uri` scheme. `alg` is required and polymorphic-algorithm confusion is
  refused. The signature base is reconstructed from the covered components and checked
  against the published key (see `tests/test_rfc9421_vectors.py`, pinned to RFC 9421
  Appendix B).
- **Key discovery egress (SSRF).** `jwks_uri` resolution is admitted through
  `egress.py`: HTTPS only, no private, loopback or link-local destinations, DNS
  pinning so the resolved address is the one connected to, and no redirects.
- **Parser robustness.** The structured-field parser, JWK decoder, JWT-claims decoder
  and policy loader are fuzzed and property-tested: any malformed input maps to a
  typed 4xx, never a 500 and never a false allow (`tests/test_fuzz_signature_headers.py`,
  `tests/test_fuzz_snapshot.py`, `tests/test_properties.py`).
- **State-machine safety.** The mission lifecycle, pending/polling, clarification,
  replay and event-dedup transitions are fuzzed through random interleavings with the
  invariant that no request yields a 500 and the store stays well-formed
  (`tests/test_fuzz_state_machine.py`).
- **Forwarded tokens.** The agent, resource and presented tokens inside a PS request
  are read for their claims, not re-verified: the draft has the PS forward them "as the
  agent sent them", and the SS's trust rests on the PS's verified request signature.
  A claim taken from them never counts as resource-asserted evidence on its own.
- **Provenance.** Evidence the agent asserts can only make a decision stricter, never
  looser. Clarifications are agent-asserted and can never lower an action class.
- **Identifiers and values.** Resource identifiers must be server identifiers as the
  core defines them (lowercase https host), so a case variant cannot slip past a
  `deny_resources` entry; a parameter value that is not a finite number is treated as
  not visible rather than as "below the limit".
- **Deployment.** `serve` binds a loopback address only and refuses any other. It is
  meant to sit behind a TLS-terminating reverse proxy for the `issuer` origin that
  passes the original `Host` through, because the PS signs `@authority`. The connect
  confirmation page is gated by an operator token and is a development stand-in for a
  real person-facing confirmation. It cannot be framed, and after five wrong tokens it
  refuses every confirmation until the process restarts. The listener bounds each body
  (1 MiB) and each read (15 s) but starts a thread per connection, so connection limits
  belong in the proxy.

## Known limitations

See the "Limitations" section of `README.md`. The load-bearing one for security: no
second implementation speaks Supervision -00 yet, so interoperability is tested only
against this project's own simulated PS (`docs/interop.md`).
