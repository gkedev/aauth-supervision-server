# Interoperability

## Supervision implementations

Supervision -00 is an editor's copy in the
[AAuth repository](https://github.com/dickhardt/AAuth), whose README lists it as
"Exploration, not yet submitted". As of 2026-10-15, none of the public person server
implementations below implements its client side:

| Implementation | Role | Supervision client | Source |
|---|---|---|---|
| Hellō Mockin | Mock person server (core, bootstrap, R3) | No: every consent and approval step auto-approves by default, with the R3 split set by `mock.r3_grants` | [Mockin documentation](https://www.hello.dev/docs/mockin/) |
| aauth-person-server | Person server with missions | No: consent is local (`/consent`, `AAUTH_PS_AUTO_APPROVE_*`) | [README](https://github.com/christian-posta/aauth-person-server) |
| dotnet-samples | .NET SDK, person server and resources (draft -11) | No | [README](https://github.com/aauth-dev/dotnet-samples) |
| Sidecat | Client and daemon with a local person server operator console | No | [Project](https://gitlab.com/sidecat-dev/sidecat), [v0.7.0 release](https://gitlab.com/sidecat-dev/sidecat/-/tags/v0.7.0) |
| aauth-go v0.2.0 | Go module: agent, person server, access server, agent provider, resource (draft -11) | No: its person server decides through a local `personserver.Decider` | [README at v0.2.0](https://github.com/aauth-dev/aauth-go/tree/v0.2.0) |

So every end-to-end test runs against `aauth_supervision_server.testing.SimulatedPS`, a
PS written from Supervision -00 for this purpose. It signs real RFC 9421 requests under
the `jwks_uri` scheme and mints real signed agent, resource and person tokens, but it is
this project's reading of the draft, not an independent one. Two end-to-end missions also
run with every PS request signed by aauth-go (below), which makes the request signatures
independent, but not the check of the SS's signed answers or the PS's Supervision logic.

A PS that registers an SS and calls its `connect_endpoint`, `mission_endpoint`,
`decision_endpoint` and `event_endpoint` would close this. Mockin already fetches and
hash-verifies R3 proposals; forwarding the verified bytes to an SS is the change
[AAuth #256](https://github.com/dickhardt/AAuth/issues/256) asks for.

## Signature layer

### RFC 9421 test vectors

The signature code is pinned to the published HTTP Message Signatures vectors in
`tests/test_rfc9421_vectors.py`, so the Ed25519 and ES256 paths are checked against the
standard's own keys and signatures, not only against fixtures written here:

| Vector | Algorithm | What it proves |
|---|---|---|
| RFC 9421 B.2.6 | ed25519 | The signature base is byte-for-byte correct (the published signature is reproduced), and `jwk.VerifyKey` verifies the published signature and rejects a tampered base. |
| RFC 9421 B.2.4 | ecdsa-p256-sha256 | The response signature base (with `;req`-free response components) matches the RFC line for line, and `jwk.VerifyKey` verifies the published ECDSA signature against the B.1.3 key. ECDSA is non-deterministic (RFC 9421 7.3.5), so the vector is verified, never reproduced. |
| RFC 9421 B.1.3 / B.1.4 | EC P-256 / Ed25519 | `jwk.key_from_jwk` builds this SS's JWK form from the RFC's own PEM keys and verifies with them. |

A regression in canonicalisation, EC point handling or Ed25519 handling fails against
the RFC.

### Independent libraries

Two independent AAuth signature libraries, in two languages, are cross-tested on every
gate; a third does not interoperate. They check request signatures: those this SS
verifies and those this code makes. The responses this SS signs are checked only by this
project's own code (`httpsig.verify_response`, which the simulated PS in `testing.py`
calls on each `200` answer once it is given the SS's key).

- **[regent-httpsig](https://github.com/regent-protocol/regent-httpsig) 0.7.1** (Python,
  listed in the AAuth README), in `tests/test_interop_regent_httpsig.py`: requests it
  signs under the `jwks_uri` scheme verify here, and requests this code signs verify with
  its `verify_server`, for a POST with a body and a bodyless poll.
- **[aauth-go](https://github.com/aauth-dev/aauth-go) v0.2.0** (Go, on yaronf/httpsign,
  pinned in `interop/aauth-go/go.mod`), in `tests/test_interop_aauth_go.py`, through its
  public API. A request its `ServerSigner` signs as a PS verifies here, and a request
  this code signs verifies with its `VerifyServerRequest` (body coverage required), for
  a POST and a bodyless poll; a tampered body fails there. Two whole missions also run
  against the unmodified server with **every PS request signed by aauth-go**, each SS
  answer verified as signed by this project's `verify_response`. The first (connect, mission proposal and approval, two
  decisions and an issuance event) ends in the split exfiltration denied, with the R3
  proposal forwarded (the opt-in AAuth #256 extension; without it that act is asked). The
  second, under Supervision -00 as written, denies a prohibited sequence whose tokens
  are taken last step first. `interop/aauth-go/main.go` is the thin command the tests
  drive. Without a Go toolchain the tests skip locally; CI sets `AAUTH_SS_REQUIRE_GO=1`,
  which turns a missing toolchain into a failure.
- **[aauth-signing](https://pypi.org/project/aauth-signing/0.2.0/) 0.2.0** does not
  interoperate in either direction. It encodes the `Signature` byte sequence as base64url
  without padding, which RFC 9651 (Section 3.3.5, base64 per RFC 4648 Section 4) does not
  allow, and its parser accepts only the base64url alphabet, so it rejects the `+`, `/`
  and `=` of standard base64 (`build_signature_header` and `parse_signature` in
  [`signature.py`](https://github.com/christian-posta/aauth-python-library/blob/main/aauth-signing/aauth_signing/signature.py)).
  This SS accepts a missing `=` padding, as RFC 9651 Section 4.2.7 asks of parsers, and
  refuses the base64url alphabet, as it requires.
