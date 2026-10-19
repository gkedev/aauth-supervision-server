# Security

## Status

This is an independent implementation of the AAuth Supervision Server, pinned to
revision -00 of the AAuth Supervision draft (AAuth commit `70d67375`), which the AAuth
repository's README lists as "Exploration, not yet submitted". It is intended for study,
interop experiments and conformance work, not as a production authorization service. Do
not place it on the decision path of a real deployment without an independent security
review.

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
  AAuth `jwks_uri` scheme. The key's JWK `alg` is required and polymorphic-algorithm
  confusion is refused; a signature's `alg` parameter is ignored (Protocol L2236). The
  signature base is reconstructed from the covered components and checked against the
  published key (see `tests/test_rfc9421_vectors.py`, pinned to RFC 9421 Appendix B).
- **Key discovery egress (SSRF).** `jwks_uri` resolution is admitted through
  `egress.py`: HTTPS only, no private, loopback or link-local destinations (an IPv6
  address that carries an IPv4 address, as 6to4 and NAT64 do, is judged by it), DNS
  pinning so the resolved address is the one connected to, and no redirects. A signer's
  keys are fetched at most once a minute, and less often while its host fails as long as
  it stays in the key cache (one pushed out by other signers starts over), and one
  fetch serves the requests that arrive together; the key cache is bounded, locked,
  never evicts a trusted PS, and keeps the fetch floor of a signer it evicts
  (`tests/test_resolver_hardening.py`). A cached key that fails is refreshed once,
  within the same floor, so a key replaced under its `kid` is not served stale
  (`tests/test_rekey_same_kid.py`). Keys that bind no
  signer (an Ed25519 key of small order, a point off the curve) are refused
  (`tests/test_key_and_digest_edges.py`), and so is a key whose `use` is not `sig` or
  whose `key_ops` leaves out `verify`.
- **Parser robustness.** The structured-field parser, JWK decoder, JWT-claims decoder
  and policy loader are fuzzed and property-tested: any malformed input maps to a
  typed 4xx, never a 500 and never a false allow (`tests/test_fuzz_signature_headers.py`,
  `tests/test_fuzz_snapshot.py`, `tests/test_properties.py`). That includes what the
  body's own checks cannot see: a mission blob of the wrong shape, bytes nested past the
  decoder's limit inside a token, and numbers past the float range
  (`tests/test_state_robustness.py`).
- **State-machine safety.** The mission lifecycle, pending/polling, clarification,
  replay and event-dedup transitions are fuzzed through random interleavings with the
  invariant that no request yields a 500 and the store stays well-formed
  (`tests/test_fuzz_state_machine.py`).
- **Forwarded tokens.** The agent, resource and presented tokens inside a PS request
  are read for their claims, not re-verified: the draft has the PS forward them "as the
  agent sent them", and the SS's trust rests on the PS's verified request signature.
  The resource token's `typ` is checked before its claims are read. A claim taken from
  them never counts as resource-asserted evidence on its own.
- **Provenance.** Evidence the agent asserts can only make a decision stricter, never
  looser, and never takes an act out of a prohibited composition
  (`tests/test_agent_tightening.py`). Clarifications are agent-asserted and can never
  lower an action class. Less evidence never loosens either: an act whose class was
  assumed for data a rule needs also composes as each class it could have.
- **Time.** Acts are ordered by the PS's own stamps and placed against a token's end,
  on this SS's clock, by how far ahead the PS's clocks run, read from its signed
  requests (the protocol gives the SS no round trip to measure). That rests on stated
  assumptions about the PS's clocks, with what breaking each one costs (README
  "Limitations"); a PS that lies about when its acts took place is outside them, as it
  is outside any SS's view.
- **Identifiers and values.** Resource identifiers must be server identifiers as the
  core defines them (lowercase https host), so a case variant cannot slip past a
  `deny_resources` entry; a parameter value that is not a finite number is treated as
  not visible rather than as "below the limit". A domain rule reads every recipient a
  value names (`a@x.example, b@y.example` is two) in every parameter it names, and a
  recipient that is not plainly `local@domain` is outside every listed domain
  (`tests/test_recipient_domains.py`).
- **What the person is shown.** An ask's `summary` and its `apply_options` labels are
  Markdown the PS shows the person. Text the agent chose (its justification, a tool
  name, a mission update) is quoted in a code span or fenced block that nothing inside
  can close, attributed to the agent, with control and format characters removed, so it
  can neither become an image, link, HTML or emphasis nor pass for the supervisor's own
  words; a resource's budget unit is quoted the same way unless it is a short word of
  ASCII letters, and combining marks are kept to a few on one visible character
  (`tests/test_person_facing_text.py`, `tests/test_properties_markdown.py`). The
  supervisor's own sentence comes before the agent's names, which are cut. A tool name
  with invisible characters is refused. The access log escapes control characters in the
  request line, and no log line or error repeats a request line, which can carry an
  interaction code.
- **Deployment.** `serve` binds a loopback address only and refuses any other. It is
  meant to sit behind a TLS-terminating reverse proxy for the `issuer` origin that
  passes the original `Host` through, because the PS signs `@authority`. The connect
  confirmation page is gated by an operator token and is a development stand-in for a
  real person-facing confirmation. It cannot be framed, it refuses a form post a browser
  sends from another site, and five wrong tokens posted with one connect's code fail
  that connect for good (as Protocol L2398 has for code attempts): guessing the token
  costs a live code every five tries, and no one holding a code can stop the operator
  confirming the others. It shows the code before the PS's self-asserted name, which it
  shows as plain text, cut; a code expires with its connect after an hour. Under open
  registration a signer no person has confirmed holds at most 64 connects awaiting
  confirmation or failed by wrong operator tokens, each removed with its id a lifetime
  after it expires, and keeps nothing else; all such signers together hold at most
  1,024, and at that cap the domain holding the most makes room for another, the names
  made under one domain counting as one; in the key table the signers of one domain
  hold at most 64 entries together. Every identifier and text the SS
  keeps is bounded, text by the size it is kept at, and so are a proposal's tools and an
  approved mission blob (`tests/test_connect_lifetime.py`,
  `tests/test_state_bounds.py`). The listener bounds each body (1 MiB), each signature
  field (8 KiB) and each request (10 s whole, every read within it), serves at most 64
  connections at once (the next waits in the listen queue; while all are taken, each
  answer closes its connection), refuses a header block it cannot read whole (RFC 9112
  5.1), and answers each of its own refusals in the protocol's error format
  (`tests/test_listener_limits.py`). It cannot tell clients apart behind the proxy, so
  limits per client, and buffering whole requests, belong to the proxy. It binds its
  port for exclusive use, and `aauth-ss serve` holds its state file before it reads it,
  so a second SS started on either fails at once and leaves the first one's file alone
  (`tests/test_single_instance.py`, `tests/test_serve_startup.py`).

## Known limitations

See the "Limitations" section of `README.md`. The load-bearing one for security: no
second implementation speaks Supervision -00 yet, so Supervision interoperability is
tested only against this project's own simulated PS; request signatures are also
cross-tested with regent-httpsig and aauth-go (`docs/interop.md`).
