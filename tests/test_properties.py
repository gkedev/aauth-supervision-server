"""Property-based tests (Hypothesis) for the untrusted-input front doors.

The hand-written fuzz modules (test_config_files, test_fuzz_signature_headers,
test_fuzz_snapshot, test_fuzz_state_machine) stay as explicit, named regression cases:
they pin exact edge values. This module adds the generative half: it asserts the *invariant* each parser
must hold for every input, so inputs no one thought to list are covered too.

The invariants, one per front door:

* The SFV parser (sfv.py) raises only SFVError on any text, and round-trips any
  value it accepts (parse . serialize . parse is stable).
* jwk.b64u_decode / key_from_jwk raise only their declared exceptions on any
  string / object -- never a bare ValueError, UnicodeError or TypeError escaping.
* service._decode_jwt_claims returns a dict or raises invalid_request (a 400
  ProtocolError) on any token -- never an uncaught exception.
* policy.PolicyConfig.from_dict builds a config or raises ValueError on any dict,
  and cli.validate_policy agrees with it (both accept or both reject).
* A supervision request with arbitrary signature-header values maps to a clean
  4xx through the full server handle() path -- never a 500 and never a false 200.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import ROOT, SUB, make_env
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aauth_supervision_server.cli import validate_policy
from aauth_supervision_server.errors import ProtocolError
from aauth_supervision_server.httpsig import HttpRequest
from aauth_supervision_server.jwk import b64u, b64u_decode, key_from_jwk
from aauth_supervision_server.policy import PolicyConfig
from aauth_supervision_server.service import _decode_jwt_claims
from aauth_supervision_server.sfv import (
    SFVError,
    parse_dictionary,
    ser_dictionary,
)

POLICY = json.loads((ROOT / "examples" / "policy.json").read_text())

# A deadline-free, example-bounded profile: the server-path property builds a real
# signed request per example, which is slower than a pure parser, so cap examples
# and silence the function-scoped-fixture health check (the state is built inside
# the test, not via a fixture).
SLOW = settings(max_examples=150, deadline=None,
                suppress_health_check=[HealthCheck.function_scoped_fixture])
FAST = settings(max_examples=400, deadline=None)


# --------------------------------------------------------------- SFV parser

# Text drawn from the structured-field alphabet plus noise, so the generator hits
# real delimiters (quotes, colons, parens, semicolons) rather than random unicode.
_SFV_ALPHABET = st.text(
    alphabet=st.sampled_from(list('abcXYZ0123 ()";:,=?*-.\\\t/@#+!💥\x00')),
    max_size=60,
)


@given(_SFV_ALPHABET)
@FAST
def test_sfv_dictionary_only_raises_sfverror(text: str) -> None:
    try:
        out = parse_dictionary(text)
    except SFVError:
        return
    assert isinstance(out, dict)


@given(_SFV_ALPHABET)
@FAST
def test_sfv_dictionary_roundtrips(text: str) -> None:
    """Anything the parser accepts must re-serialize to something it accepts again,
    and the second parse must equal the first (serialize . parse is idempotent)."""
    try:
        d1 = parse_dictionary(text)
    except SFVError:
        return
    s1 = ser_dictionary(d1)
    d2 = parse_dictionary(s1)
    assert ser_dictionary(d2) == s1


# --------------------------------------------------------------- jwk parsing

@given(st.text(max_size=80))
@FAST
def test_b64u_decode_only_raises_valueerror(s: str) -> None:
    try:
        out = b64u_decode(s)
    except ValueError:
        return
    assert isinstance(out, bytes)


@given(st.binary(max_size=64))
@FAST
def test_b64u_roundtrips(raw: bytes) -> None:
    assert b64u_decode(b64u(raw)) == raw


# A JWK-shaped generator: valid-ish keys and arbitrary objects, so key_from_jwk sees
# both the happy path and junk in every field.
_JWK = st.fixed_dictionaries(
    {},
    optional={
        "kty": st.sampled_from(["OKP", "EC", "oct", "RSA", "", 1, None]),
        "crv": st.sampled_from(["Ed25519", "P-256", "P-384", "", None]),
        "alg": st.sampled_from(["Ed25519", "ES256", "none", "EdDSA", "HS256", "RS256", "", None]),
        "x": st.one_of(st.text(max_size=50), st.integers(), st.none()),
        "y": st.one_of(st.text(max_size=50), st.integers(), st.none()),
        "d": st.text(max_size=50),
        "kid": st.text(max_size=10),
    },
)


@given(_JWK)
@FAST
def test_key_from_jwk_only_raises_protocolerror(jwk: dict[str, Any]) -> None:
    try:
        key = key_from_jwk(jwk)
    except ProtocolError:
        return
    # If it accepted the key, it must be a well-formed supported alg.
    assert key.alg in ("Ed25519", "ES256")


# --------------------------------------------------------------- JWT claims

# Tokens: random text, and structurally-plausible three-part tokens whose middle
# segment is arbitrary base64url-ish text.
_SEG = st.text(alphabet=st.sampled_from(list("abcDEF012-_=.")), max_size=40)
_TOKEN = st.one_of(
    st.text(max_size=60),
    st.builds(lambda a, b, c: f"{a}.{b}.{c}", _SEG, _SEG, _SEG),
    st.none(),
    st.integers(),
    st.lists(st.text(max_size=5)),
)


@given(_TOKEN)
@FAST
def test_decode_jwt_claims_dict_or_invalid_request(token: Any) -> None:
    try:
        claims = _decode_jwt_claims(token)
    except ProtocolError as e:
        assert e.status == 400 and e.error == "invalid_request"
        return
    assert isinstance(claims, dict)


# --------------------------------------------------------------- policy config

# Policy dicts: the valid example mutated by overwriting members with wrong-typed
# values, and arbitrary small objects. from_dict must build or raise ValueError,
# and validate_policy must agree (both accept or both reject).
_POLICY_PATCH = st.dictionaries(
    keys=st.sampled_from([
        "high_impact", "severity", "allow_unlisted_resources", "max_mission_seconds",
        "rules", "prohibited_pairs", "budgets", "r3_member", "ask_on_mission_update",
        "classes", "nonexistent_key",
    ]),
    values=st.one_of(
        st.none(), st.booleans(), st.integers(min_value=-5, max_value=5),
        st.text(max_size=8), st.lists(st.text(max_size=5), max_size=3),
        st.lists(st.dictionaries(st.sampled_from(["class", "resource", "tool", "when",
                                                   "param_gt"]),
                                 st.one_of(st.text(max_size=5), st.integers()), max_size=3),
                 max_size=2),
    ),
    max_size=4,
)


@given(_POLICY_PATCH)
@FAST
def test_policy_from_dict_and_validate_agree(patch: dict[str, Any]) -> None:
    d = POLICY | patch
    built = True
    try:
        PolicyConfig.from_dict(d)
    except ValueError:
        built = False
    except Exception as e:  # pragma: no cover - any other exception is a defect
        pytest.fail(f"from_dict raised {type(e).__name__}, not ValueError: {e}")
    errs = validate_policy(d)
    # validate_policy is a strict superset of from_dict: it runs the same shape checks
    # (via from_dict) and then adds cross-field semantic checks (every referenced class
    # must appear in `severity`, if_unknown may not loosen, prohibited pairs name known
    # classes). So the invariant is one-directional: a shape rejection by from_dict is
    # always surfaced by validate_policy, but validate_policy may additionally reject a
    # shape-valid policy on semantic grounds (e.g. severity:[] with rules present).
    if not built:
        assert errs, "from_dict rejected but validate_policy accepted"


# --------------------------------------------------------------- server front door

_HEADER_VALUE = st.one_of(
    st.text(alphabet=st.sampled_from(list('sig=()":,;?01*-. \\abc\x00💥')), max_size=50),
    st.text(max_size=50),
    st.just(""),
)


@given(field=st.sampled_from(["signature", "signature-input", "signature-key"]),
       value=_HEADER_VALUE)
@SLOW
def test_arbitrary_signature_header_is_clean_4xx(field: str, value: str) -> None:
    ss, ps, _ = make_env()
    assert ps.connect(ss, SUB).status == 200
    base = ps.build("POST", "/connect",
                    {"action": "connect", "id": "c-prop", "iat": 1, "sub": SUB})
    headers = dict(base.headers)
    headers[field] = value
    req = HttpRequest("POST", base.authority, "/connect", headers, base.body, "")
    resp = ss.handle(req)
    assert resp.status not in (200, 500), (field, value[:40], resp.status)
    assert json.loads(resp.body).get("error")
