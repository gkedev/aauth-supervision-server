# Interoperability probe

Checked 2026-10-06 against the public implementations the AAuth README and community list.
Supervision -00 was published on 2026-10-03 and the AAuth README lists it as
"Exploration, not yet submitted", so no counterpart was expected yet.

| Implementation | Role | Speaks Supervision -00? | Evidence |
|---|---|---|---|
| Hellō Mockin | mock PS (core, bootstrap, R3) | No | Endpoints are `/aauth/{bootstrap,token,permission,audit,interaction,pending}`; approvals are auto-approve or `mock.r3_grants`, no SS delegation ([docs](https://www.hello.dev/docs/mockin/)) |
| aauth-person-server (Posta) | PS with missions | No | Consent is local (`/consent`, `AAUTH_PS_AUTO_APPROVE_*`); no SS registration or `aauth-supervisor.json` client ([repo](https://github.com/christian-posta/aauth-person-server)) |
| aauth-dev dotnet-samples | SDK, PS and resources | No | Targets draft-10 per its release note in the community Slack (no Supervision) |
| Sidecat AAuth (Elixir) | core, R3, Events, Bootstrap | No | Announced scope: core protocol and the R3, Events and Bootstrap companions |
| auth-go (aauth-dev, draft -11 branch) | Go module: agent, PS, AS, AP, resource | No | Its `personserver` decides locally; no SS registration or client (checked 2026-10-08 at `188231b`) |

Consequence: every end-to-end test here runs against `aauth_supervision_server.testing.SimulatedPS`,
a PS written from Supervision -00 for this purpose. It signs real RFC 9421 requests
under the `jwks_uri` scheme and mints real signed agent, resource and person tokens, but
it is this project's reading of the draft, not an independent one. A conformance claim
against a second implementation remains open. Since 2026-10-08 one end-to-end mission
also runs with every PS request signed by auth-go instead (see below), which makes the
transport independent but not the PS's Supervision logic.

What would close it: any PS that registers an SS and calls `connect_endpoint`,
`mission_endpoint`, `decision_endpoint` and `event_endpoint`. Mockin is the natural
first target, since it already fetches and hash-verifies R3 proposals: forwarding the
verified bytes to an SS is the change [AAuth #256](https://github.com/dickhardt/AAuth/issues/256) asks for.

## RFC 9421 vectors (added 2026-10-07)

The signature code is pinned to the published HTTP Message Signatures vectors in
`tests/test_rfc9421_vectors.py`, so the Ed25519 and ES256 paths are checked against
the standard's own keys and signatures, not only against fixtures written here:

| Vector | Algorithm | What it proves |
|---|---|---|
| RFC 9421 B.2.6 | ed25519 | The signature base is byte-for-byte correct (the published signature is reproduced), and `jwk.VerifyKey` verifies the published signature and rejects a tampered base. |
| RFC 9421 B.2.4 | ecdsa-p256-sha256 | The response signature base (with `;req`-free response components) matches the RFC line for line, and `jwk.VerifyKey` verifies the published ECDSA signature against the B.1.3 key. ECDSA is non-deterministic (RFC 9421 7.3.5), so the vector is verified, never reproduced. |
| RFC 9421 B.1.3 / B.1.4 | EC P-256 / Ed25519 | `jwk.key_from_jwk` builds this SS's JWK form from the RFC's own PEM keys and verifies with them. |

This is standards-level interop for the signature layer: a regression in
canonicalisation, EC point handling, or Ed25519 handling now fails against the RFC.

## Cross-implementation interop: open items

- **No second Supervision implementation exists.** As recorded above, none of the
  public AAuth implementations speak Supervision -00, so bidirectional
  sign/verify against an independent SS or PS cannot run yet.
- **Two independent AAuth signature libraries, in two languages, are cross-tested; a third
  is not compatible.** Both run on every gate.
  - `tests/test_interop_regent_httpsig.py`: requests signed by
    [regent-httpsig](https://github.com/regent-protocol/regent-httpsig) 0.7.1 (Python,
    listed in the AAuth README) under the `jwks_uri` scheme verify here, and requests this
    code signs verify with its `verify_server`, for a POST with a body and a bodyless poll.
  - `tests/test_interop_auth_go.py`: [auth-go](https://github.com/aauth-dev/aauth-go)
    (Go, on yaronf/httpsign; the draft -11 branch, pinned in `interop/auth-go/go.mod`)
    through its public API. A request its `ServerSigner` signs as a PS verifies here and a
    request this code signs verifies with its `VerifyServerRequest` (body coverage
    required), for a POST and a bodyless poll; a tampered body fails there. And a whole
    mission runs against the unmodified server with **every PS request signed by
    auth-go**: connect, mission proposal and approval, two decisions and an issuance event,
    ending in the split exfiltration denied, with each SS answer verified as signed.
    `interop/auth-go/main.go` is the thin command the test drives. Without a Go toolchain
    the test skips locally; CI sets `AAUTH_SS_REQUIRE_GO=1`, which turns a missing
    toolchain into a failure.
  - [aauth-signing](https://github.com/christian-posta/aauth-python-library) 0.2.0 does not
    interoperate in either direction: it encodes the `Signature` byte sequence as base64url
    without padding, which RFC 8941 (Section 3.3.5, base64 per RFC 4648 Section 4) does not
    allow, and its parser rejects standard base64. This SS accepts a missing `=` padding, as
    RFC 8941 Section 4.2.7 asks of parsers, and refuses the base64url alphabet, as it requires.
- **End-to-end against `aauth-person-server` has not run**, because it does not speak
  Supervision. The self-written `SimulatedPS` remains the end-to-end PS, with the
  caveat already stated: it is this project's reading of the draft, not an
  independent one.
