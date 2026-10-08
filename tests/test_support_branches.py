"""The remaining paths in the support modules, each pinned to its observable effect.

Command line, listener, keys, key discovery, Structured Fields, signature bases, the
snapshot loader and three policy edges. Two of them were defects, fixed alongside: a
mission `expires_at` that was malformed or had no UTC offset read as "no expiry"
(it now fails closed), and Structured Fields swallowed every exception while decoding
a byte sequence (it now catches only the decoding error).
"""
from __future__ import annotations

import http.client
import json
import logging
import socket
import threading
from pathlib import Path
from typing import Any

import pytest
from conftest import AGENT, ROOT, SUB, connected, make_env, policy_cfg

from aauth_supervision_server import cli
from aauth_supervision_server.egress import EgressPolicy, StaticFetcher
from aauth_supervision_server.errors import SignatureError, server_error
from aauth_supervision_server.http_server import ACCESS_LOG, serve
from aauth_supervision_server.httpsig import HttpRequest, HttpResponse, signature_base, verify_response
from aauth_supervision_server.jwk import SigningKey, VerifyKey, key_from_jwk
from aauth_supervision_server.policy import Act, Mission, Policy, _iso_to_epoch
from aauth_supervision_server.resolver import JwksUriResolver
from aauth_supervision_server.sfv import (
    InnerList,
    Item,
    SFVError,
    parse_dictionary,
    ser_bare,
    ser_dictionary,
)
from aauth_supervision_server.store import Store

EXAMPLES = ROOT / "examples"


def parse_item(text: str) -> Any:
    return parse_dictionary("a=" + text)["a"]


def example(name: str) -> dict[str, Any]:
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ command line


def test_a_config_file_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    f = tmp_path / "p.json"
    f.write_text("[1]", encoding="utf-8")
    with pytest.raises(SystemExit, match="not a JSON object$"):
        cli.main(["check-policy", str(f)])


def test_check_policy_prints_each_problem(tmp_path: Path, capsys: Any) -> None:
    d = example("policy.json") | {"composition_on_certain": "maybe"}
    d["severity"] = d["severity"] + [d["severity"][0]]
    f = tmp_path / "p.json"
    f.write_text(json.dumps(d), encoding="utf-8")
    assert cli.main(["check-policy", str(f)]) == 1
    assert capsys.readouterr().out.splitlines() == [
        "error: severity lists a class twice",
        "error: composition_on_certain must be deny or ask",
        "2 problem(s)"]


def test_every_class_a_policy_names_must_be_ranked() -> None:
    """Deterministic, so the coverage gate never depends on what Hypothesis drew."""
    d = example("policy.json")
    d["severity"] = [c for c in d["severity"] if c != "payment"]
    d["prohibited_sequences"] = [["read_sensitive", "teleport"]]
    problems = cli.validate_policy(d)
    assert "class 'payment' is used but missing from severity" in problems
    assert "prohibited sequence names unknown class 'teleport'" in problems


def test_build_server_refuses_a_policy_with_problems() -> None:
    pol = example("policy.json") | {"composition_on_certain": "maybe"}
    with pytest.raises(SystemExit, match="^policy rejected:\n  composition_on_certain"):
        cli.build_server(example("server.json"), pol, None, None)


@pytest.mark.parametrize("egress", [{"allow_private_hosts": "localhost"},
                                    {"allow_cross_origin_jwks": "yes"}])
def test_build_server_refuses_mistyped_egress(egress: dict[str, Any]) -> None:
    cfg = example("server.json") | {"egress": egress}
    with pytest.raises(ValueError, match="^server config: egress has the wrong types$"):
        cli.build_server(cfg, example("policy.json"), None, None)


def test_the_admin_token_can_come_from_the_environment(monkeypatch: Any) -> None:
    monkeypatch.setenv("AAUTH_SS_ADMIN_TOKEN", "from-env")
    ss = cli.build_server(example("server.json"), example("policy.json"), None, None)
    assert ss.cfg.admin_token == "from-env"


class FakeHttpd:
    def __init__(self) -> None:
        self.closed = False
        self.log_during: tuple[int, int] = (0, 0)

    def serve_forever(self) -> None:
        self.log_during = (len(ACCESS_LOG.handlers), ACCESS_LOG.level)
        raise KeyboardInterrupt

    def server_close(self) -> None:
        self.closed = True


def test_serve_runs_until_interrupted_and_cleans_up(monkeypatch: Any, capsys: Any,
                                                    tmp_path: Path) -> None:
    import aauth_supervision_server.http_server as hs

    fake = FakeHttpd()
    seen: dict[str, Any] = {}

    def fake_serve(ss: Any, host: str, port: int) -> FakeHttpd:
        seen.update(ss=ss, host=host, port=port)
        return fake

    monkeypatch.setattr(hs, "serve", fake_serve)
    before = (list(ACCESS_LOG.handlers), ACCESS_LOG.level)
    state = tmp_path / "state.json"
    assert cli.main(["serve", "--config", str(EXAMPLES / "server.json"), "--policy",
                     str(EXAMPLES / "policy.json"), "--state", str(state),
                     "--port", "9000"]) == 0
    out, err = capsys.readouterr()
    assert "warning: no --key, so decisions are unsigned" in err
    assert out.strip() == (f"{seen['ss'].cfg.issuer} listening on http://127.0.0.1:9000 "
                           "(loopback; put a TLS proxy for the issuer in front)")
    assert fake.log_during == (len(before[0]) + 1, logging.INFO)
    assert (list(ACCESS_LOG.handlers), ACCESS_LOG.level) == before
    assert fake.closed and state.exists()  # the store was saved on the way out


def test_serve_with_a_key_does_not_warn(monkeypatch: Any, capsys: Any, tmp_path: Path) -> None:
    import aauth_supervision_server.http_server as hs

    monkeypatch.setattr(hs, "serve", lambda ss, host, port: FakeHttpd())
    key = tmp_path / "k.json"
    assert cli.main(["keygen", "--kid", "ss-1", "--out", str(key)]) == 0
    capsys.readouterr()
    assert cli.main(["serve", "--config", str(EXAMPLES / "server.json"), "--policy",
                     str(EXAMPLES / "policy.json"), "--key", str(key)]) == 0
    assert capsys.readouterr().err == ""


# ------------------------------------------------------------------ listener


def test_serve_accepts_localhost_and_refuses_a_hostname() -> None:
    ss, _, _ = make_env()
    ready = threading.Event()
    httpd = serve(ss, "localhost", 0, ready=ready)
    try:
        assert ready.is_set()
    finally:
        httpd.server_close()
    with pytest.raises(ValueError, match="loopback"):
        serve(ss, "ss.example", 0)


@pytest.fixture
def live() -> Any:
    ss, ps, clock = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield ss, ps, httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_a_chunked_request_is_refused_and_the_connection_closed(live: Any) -> None:
    _, _, port = live
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(b"POST /decision HTTP/1.1\r\nHost: ss.example\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        reply = b""
        while chunk := s.recv(4096):
            reply += chunk
    head, _, body = reply.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 411 ")
    assert b"\r\nConnection: close" in head and body == b"Content-Length required\n"


def test_a_reply_without_a_body_sends_no_body(live: Any) -> None:
    ss, ps, port = live
    ps.connect(ss, SUB)
    req = ps.build("POST", "/event", {"event": "person_token.issued", "id": "e-1", "iat": 1,
                                      "sub": SUB, "agent": AGENT})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", req.path, body=req.body, headers=dict(req.headers) | {
        "host": req.authority})
    r = conn.getresponse()
    assert r.status == 201 and r.getheader("Content-Length") == "0" and r.read() == b""
    conn.close()


def test_handle_error_is_silent_only_for_dropped_connections(capsys: Any) -> None:
    ss, _, _ = make_env()
    httpd = serve(ss, "127.0.0.1", 0)
    try:
        for exc in (ConnectionResetError(), BrokenPipeError(), TimeoutError()):
            try:
                raise exc
            except OSError:
                httpd.handle_error(None, ("127.0.0.1", 1))
        assert capsys.readouterr().err == ""
        try:
            raise RuntimeError("unexpected")
        except RuntimeError:
            httpd.handle_error(None, ("127.0.0.1", 1))
        assert "RuntimeError: unexpected" in capsys.readouterr().err
    finally:
        httpd.server_close()


@pytest.mark.parametrize("exc", [ConnectionResetError, BrokenPipeError, TimeoutError])
def test_a_connection_dropped_mid_request_ends_the_connection(exc: type[OSError]) -> None:
    """Deterministic: the socket tests hit this path only when the OS timing allows."""
    from aauth_supervision_server.http_server import make_handler

    class Dropped:
        def readline(self, _limit: int = -1) -> bytes:
            raise exc

    ss, _, _ = make_env()
    handler = object.__new__(make_handler(ss))
    handler.rfile = Dropped()  # type: ignore[assignment]
    handler.client_address = ("127.0.0.1", 1)  # the stdlib logs a read timeout itself
    handler.close_connection = False
    handler.handle_one_request()
    assert handler.close_connection is True


# ------------------------------------------------------------------ keys


def test_an_es256_signature_of_the_wrong_length_does_not_verify() -> None:
    k = SigningKey.generate("k", "ES256")
    vk = key_from_jwk(k.public_jwk())
    sig = k.sign(b"m")
    assert vk.verify(sig, b"m")
    assert not vk.verify(sig[:63], b"m") and not vk.verify(sig + b"\0", b"m")


def test_a_key_of_an_unimplemented_alg_verifies_nothing() -> None:
    k = SigningKey.generate("k", "ES256")
    jwk = k.public_jwk() | {"alg": "ES384"}
    assert not VerifyKey("ES384", jwk).verify(k.sign(b"m"), b"m")


def test_a_jwk_must_be_an_object() -> None:
    with pytest.raises(SignatureError) as e:
        key_from_jwk(["kty", "OKP"])  # type: ignore[arg-type]
    assert (e.value.error, e.value.detail) == ("invalid_key", "JWK is not an object")


@pytest.mark.parametrize("n", [31, 33, 0])
def test_an_ed25519_x_must_be_32_bytes(n: int) -> None:
    from aauth_supervision_server.jwk import b64u

    jwk = SigningKey.generate("k").public_jwk() | {"x": b64u(b"\1" * n)}
    with pytest.raises(SignatureError) as e:
        key_from_jwk(jwk)
    assert (e.value.error, e.value.detail) == ("invalid_key", "bad Ed25519 x")


def test_algorithm_determination_refuses_each_inconsistent_jwk() -> None:
    ec_jwk = SigningKey.generate("k", "ES256").public_jwk()
    cases = [
        (ec_jwk | {"alg": "ES384"}, "unsupported_algorithm", "alg ES384 not implemented"),
        (ec_jwk | {"crv": "P-384"}, "invalid_key", "kty/crv disagree with alg ES256"),
        (ec_jwk | {"kty": "OKP"}, "invalid_key", "kty/crv disagree with alg ES256"),
        ({k: v for k, v in ec_jwk.items() if k != "y"}, "invalid_key", "malformed JWK: 'y'"),
        (ec_jwk | {"x": "a=b"}, "invalid_key",
         "malformed JWK: not base64url without padding"),
    ]
    for jwk, error, detail in cases:
        with pytest.raises(SignatureError) as e:
            key_from_jwk(jwk)
        assert (e.value.error, e.value.detail) == (error, detail)
    assert e.value.headers.get("Accept-Signature-Alg") is None
    with pytest.raises(SignatureError) as e:
        key_from_jwk(ec_jwk | {"alg": "ES384"})
    assert e.value.headers["Accept-Signature-Alg"] == '"Ed25519", "ES256"'


@pytest.mark.parametrize("alg", ["Ed25519", "ES256"])
def test_a_published_key_carrying_private_material_is_refused(alg: str) -> None:
    """A PS that leaks its private key in its JWKS is not a signer to trust."""
    with pytest.raises(SignatureError) as e:
        key_from_jwk(SigningKey.generate("k", alg).private_jwk())
    assert (e.value.error, e.value.detail) == ("invalid_key",
                                               "private key material in a public JWK")


def test_signing_keys_exist_only_for_implemented_algs() -> None:
    with pytest.raises(ValueError, match="^RS256$"):
        SigningKey.generate("k", "RS256")
    jwk = SigningKey.generate("k").private_jwk() | {"alg": "RS256"}
    with pytest.raises(ValueError, match="^RS256$"):
        SigningKey.from_private_jwk(jwk)


def test_es256_private_key_round_trip() -> None:
    k = SigningKey.generate("k", "ES256")
    k2 = SigningKey.from_private_jwk(k.private_jwk())
    assert k2.public_jwk() == k.public_jwk()
    assert key_from_jwk(k.public_jwk()).verify(k2.sign(b"m"), b"m")


# ------------------------------------------------------------------ key discovery


SIGNER = "https://ps.example"
META = f"{SIGNER}/.well-known/aauth-person.json"


def resolver(docs: dict[str, Any], **policy: Any) -> tuple[JwksUriResolver, StaticFetcher]:
    f = StaticFetcher(documents=docs)
    return JwksUriResolver(f, EgressPolicy(**policy)), f


def test_a_rotated_key_is_found_by_one_refetch() -> None:
    old, new = SigningKey.generate("k1"), SigningKey.generate("k2")
    docs = {META: {"issuer": SIGNER, "jwks_uri": f"{SIGNER}/jwks"},
            f"{SIGNER}/jwks": {"keys": [old.public_jwk()]}}
    r, f = resolver(docs)
    r.resolve(SIGNER, "aauth-person.json", "k1", now=1000.0)
    docs[f"{SIGNER}/jwks"] = {"keys": [new.public_jwk()]}
    assert r.resolve(SIGNER, "aauth-person.json", "k2", now=1031.0).jwk["x"] == \
        new.public_jwk()["x"]
    assert f.calls.count(f"{SIGNER}/jwks") == 2


@pytest.mark.parametrize("signer,dwk,detail", [
    ("http://ps.example", "aauth-person.json", "signer id is not an HTTPS URL"),
    (SIGNER, "a/b", "bad dwk"),
    (SIGNER, "", "bad dwk"),
])
def test_signer_ids_and_dwk_are_checked_before_any_fetch(signer: str, dwk: str,
                                                         detail: str) -> None:
    r, f = resolver({})
    with pytest.raises(SignatureError) as e:
        r.resolve(signer, dwk, "k", now=1.0)
    assert (e.value.error, e.value.detail) == ("invalid_key", detail) and f.calls == []


def test_plain_http_only_for_hosts_admitted_for_testing() -> None:
    k = SigningKey.generate("k")
    s = "http://127.0.0.1:8080"
    r, _ = resolver({f"{s}/.well-known/aauth-person.json": {"issuer": s, "jwks_uri": f"{s}/j"},
                     f"{s}/j": {"keys": [k.public_jwk()]}}, allow_http_hosts=frozenset(
                         {"127.0.0.1"}))
    assert r.resolve(s, "aauth-person.json", "k", now=1.0).jwk["x"] == k.public_jwk()["x"]


@pytest.mark.parametrize("docs,detail", [
    ({META: {"issuer": SIGNER, "jwks_uri": 5}}, "metadata has no jwks_uri"),
    ({META: {"issuer": SIGNER, "jwks_uri": f"{SIGNER}/jwks"}}, "JWKS fetch failed: no document "
                                                              f"at {SIGNER}/jwks"),
    ({META: {"issuer": SIGNER, "jwks_uri": f"{SIGNER}/jwks"}, f"{SIGNER}/jwks": [1]},
     "JWKS is not an object"),
])
def test_unusable_key_discovery_is_invalid_key(docs: dict[str, Any], detail: str) -> None:
    r, _ = resolver(docs)
    with pytest.raises(SignatureError) as e:
        r.resolve(SIGNER, "aauth-person.json", "k", now=1.0)
    assert (e.value.error, e.value.detail) == ("invalid_key", detail)


# ------------------------------------------------------------------ Structured Fields


def test_decimal_integer_part_is_at_most_twelve_digits() -> None:
    assert parse_item("123456789012.5").value == 123456789012.5
    assert parse_item("-123456789012.5").value == -123456789012.5
    with pytest.raises(SFVError, match="^decimal too long$"):
        parse_item("1234567890123.5")


def test_string_escapes() -> None:
    assert parse_item(r'"a\"b\\c"').value == 'a"b\\c'
    for bad in (r'"a\b"', '"a\\'):
        with pytest.raises(SFVError):
            parse_item(bad)


@pytest.mark.parametrize("raw", [":a:", ":YQ=Y:", ":ab-_:", ":YW=:"])
def test_byte_sequence_with_bad_padding_is_an_sfv_error(raw: str) -> None:
    with pytest.raises(SFVError, match="^bad base64$"):
        parse_item(raw)


@pytest.mark.parametrize("raw,value", [(":YWJj:", b"abc"), (":YWI:", b"ab"), (":YQ:", b"a"),
                                       (":YQ==:", b"a")])
def test_byte_sequence_without_padding_is_accepted(raw: str, value: bytes) -> None:
    # RFC 8941 4.2.7: "parsers SHOULD NOT fail when '=' padding is not present".
    assert parse_item(raw).value == value


@pytest.mark.parametrize("raw,detail", [
    ("-", "bad number at 2"),
    ('"a\x01"', "bad string char"),
    (":YWJj", "unterminated byte sequence"),
    ("?2", "bad boolean"),
])
def test_each_malformed_bare_item_has_its_own_error(raw: str, detail: str) -> None:
    """Deterministic, so the coverage gate never depends on what Hypothesis drew."""
    with pytest.raises(SFVError) as e:
        parse_item(raw)
    assert str(e.value) == detail


def test_a_true_dictionary_member_serializes_as_its_bare_key() -> None:
    assert ser_dictionary({"a": Item(True, {"p": 1}), "b": Item(False)}) == "a;p=1, b=?0"
    assert parse_dictionary("a;p=1, b=?0") == {"a": Item(True, {"p": 1}), "b": Item(False)}


def test_a_token_is_an_immutable_value() -> None:
    """Parsed `jwks_uri` tokens are compared and may be cached: a value object."""
    import dataclasses

    from aauth_supervision_server.sfv import Token

    t = parse_item("jwks_uri")
    assert t.value == Token("jwks_uri") and {Token("jwks_uri")} == {t.value}
    with pytest.raises(dataclasses.FrozenInstanceError):
        t.value.value = "other"  # type: ignore[misc]


def test_serializing_refuses_what_a_structured_field_cannot_carry() -> None:
    with pytest.raises(SFVError, match="^string not ASCII-printable$"):
        ser_bare("caf\u00e9")
    with pytest.raises(SFVError, match="^string not ASCII-printable$"):
        ser_bare("a\nb")
    with pytest.raises(SFVError, match="^cannot serialize <class 'list'>$"):
        ser_bare([1])  # type: ignore[arg-type]


# ------------------------------------------------------------------ signature bases


REQ = HttpRequest("POST", "ss.example", "/decision", {"content-type": "application/json"})


@pytest.mark.parametrize("items,detail", [
    ([Item(1)], "component identifier must be a string"),
    ([Item("@request-target")], "unsupported derived component @request-target"),
    ([Item("@method"), Item("@method")], "duplicate component \"@method\""),
])
def test_a_signature_base_refuses_bad_component_lists(items: list[Item], detail: str) -> None:
    with pytest.raises(SignatureError) as e:
        signature_base(InnerList(items), REQ)
    assert (e.value.error, e.value.detail) == ("invalid_input", detail)


def test_the_same_name_with_different_parameters_is_not_a_duplicate() -> None:
    resp = HttpResponse(200, {"content-type": "application/json"})
    base = signature_base(InnerList([Item("content-type"), Item("content-type", {"req": True})]),
                          REQ, resp)
    assert b'"content-type": application/json\n"content-type";req: application/json' in base


def test_a_response_with_malformed_signature_fields_is_refused() -> None:
    k = SigningKey.generate("k")
    resp = HttpResponse(200, {"signature-input": "sig=(", "signature": "sig=:YQ==:",
                              "signature-key": 'sig=jwks_uri;id="x"'})
    with pytest.raises(SignatureError) as e:
        verify_response(resp, REQ, key_from_jwk(k.public_jwk()), ["@status"])
    assert e.value.error == "invalid_signature"
    assert e.value.detail.startswith("malformed signature fields: ")


# ------------------------------------------------------------------ errors


def test_a_signature_error_without_detail_has_no_detail_member() -> None:
    body = json.loads(SignatureError("unknown_key").to_response().body)
    assert body == {"type": "urn:ietf:params:sig-error:unknown_key", "title": "unknown_key",
                    "status": 401, "error": "unknown_key"}


def test_server_error_is_a_500_problem() -> None:
    r = server_error("KeyError").to_response()
    assert r.status == 500 and json.loads(r.body) == {"error": "server_error",
                                                      "detail": "KeyError"}


# ------------------------------------------------------------------ snapshots


def test_a_snapshot_written_before_a_member_existed_loads_with_its_default(
        tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    ss, ps, c = make_env(clarify_missing_justification=True)
    ss.store = Store(str(path))
    s256 = connected((ss, ps, c))
    _, r, _ = ps.auth_token_request(ss, SUB, AGENT, s256, "https://mail.example",
                                    scope="mail.send")
    assert r.status == 202
    data = json.loads(path.read_text(encoding="utf-8"))
    for p in data["pending"].values():
        del p["deadline"]  # a snapshot written without deadlines
    path.write_text(json.dumps(data), encoding="utf-8")
    loaded = Store(str(path))
    assert [p.deadline for p in loaded.pending.values()] == [0.0]


# ------------------------------------------------------------------ policy edges


def test_a_mission_expiry_that_is_not_a_zoned_timestamp_fails_closed() -> None:
    assert _iso_to_epoch(None) is None
    assert _iso_to_epoch("2026-10-07T12:00:00Z") == 1791374400.0
    assert _iso_to_epoch("2026-10-07T14:00:00+02:00") == 1791374400.0
    for bad in ("tomorrow", "2026-10-07T12:00:00", 1791374400, ["2026"]):
        assert _iso_to_epoch(bad) == float("-inf")
    pol = Policy(policy_cfg())
    m = Mission("s", AGENT, SUB, SIGNER, {"expires_at": "2026-10-07T12:00:00"})
    d = pol.decide(Act("auth_token", SIGNER, SUB, AGENT, "s", resource="https://hr.example"),
                   m, [], [], now=0.0)
    assert (d.decision, d.reason) == ("deny", "The mission has expired.")


def test_a_denied_resource_is_denied_for_an_act_too() -> None:
    pol = Policy(policy_cfg(deny_resources=["https://*.evil.example"]))
    d = pol.decide(Act("auth_token", SIGNER, SUB, AGENT, "",
                       resource="https://api.evil.example"), None, [], [], now=0.0)
    assert (d.decision, d.reason, d.trace) == (
        "deny", "https://api.evil.example is not permitted by policy.", ["deny_resources"])


PAY = [{"resource": "*", "tool": "Pay", "param_gt": {"amount": 100}, "class": "payment"}]


@pytest.mark.parametrize("amount", [{"s256": "YQ"}, "a lot", None, [5], {"value": 5}])
def test_an_amount_the_supervisor_cannot_read_leaves_the_rule_undecided(amount: Any) -> None:
    rules = example("policy.json")["rules"]
    pol = Policy(policy_cfg(rules=PAY + rules))
    rule = pol.cfg.rules[0]
    act = Act("permission", SIGNER, SUB, AGENT, "", tool="Pay", parameters={"amount": amount})
    assert pol._data_match(rule, act) is None


def test_a_proposed_tool_in_neither_list_is_left_out() -> None:
    pol = Policy(policy_cfg(allowed_tools=["WebSearch"], ask_tools=["Bash"]))
    d = pol.decide_proposal({"description": "x", "resources": [],
                             "tools": [{"name": "WebSearch"}, {"name": "Teleport"}]}, now=0.0)
    assert d.decision == "allow"
    assert d.narrow["approved_tools"] == [{"name": "WebSearch"}]
