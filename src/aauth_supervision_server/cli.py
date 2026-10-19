"""`aauth-ss`: run and operate the Supervision Server.

    aauth-ss keygen --kid ss-2026-10 --out keys/ss-key.json
    aauth-ss check-policy examples/policy.json
    aauth-ss explain examples/policy.json --resource https://mail.example --scope mail.send
    aauth-ss serve --config examples/server.json --policy examples/policy.json --key keys/ss-key.json --state state/ss.json --port 8443
"""  # noqa: E501

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any, cast

from .egress import EgressPolicy, HttpsFetcher
from .jwk import SigningKey
from .policy import SERVER_ID, Act, Policy, PolicyConfig
from .resolver import JwksUriResolver
from .service import ServerConfig, SupervisionServer
from .store import StateInUse, Store

# Bounds on the egress settings: a key fetch runs on the request's thread.
MAX_EGRESS_TIMEOUT = 300.0
MAX_EGRESS_BYTES = 64 * 1024 * 1024


def _load(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise SystemExit(f"{path}: {e.strerror or e}") from e
    except ValueError as e:
        raise SystemExit(f"{path}: not valid JSON ({e})") from e
    except RecursionError as e:
        raise SystemExit(f"{path}: not valid JSON (nested too deep)") from e
    if not isinstance(data, dict):
        raise SystemExit(f"{path}: not a JSON object")
    return data


def validate_policy(d: dict[str, Any]) -> list[str]:
    """Static checks a policy file must pass before it is served. Returns problems."""
    problems: list[str] = []
    try:
        cfg = PolicyConfig.from_dict(d)
    except (TypeError, KeyError, ValueError) as e:
        return [f"malformed policy: {e}"]
    sev = set(cfg.severity)
    if len(sev) != len(cfg.severity):
        problems.append("severity lists a class twice")
    classes = {r.cls for r in cfg.rules} | {r.if_unknown for r in cfg.rules if r.if_unknown}
    for c in sorted(classes | cfg.high_impact | set(cfg.budgets) | {cfg.default_class}):
        if c not in sev:
            where = " (it is `default_class`)" if c == cfg.default_class else ""
            problems.append(f"class {c!r} is used but missing from severity{where}")
    for r in cfg.rules:
        if r.if_unknown and cfg.rank(r.if_unknown) < cfg.rank(r.cls):
            problems.append(f"rule {r.cls}: if_unknown {r.if_unknown!r} is less severe than the "
                            f"class it replaces; an unknown would loosen the decision")
    for a, b in cfg.prohibited_pairs:
        for c in (a, b):
            if c not in sev:
                problems.append(f"prohibited pair names unknown class {c!r}")
    for s in cfg.prohibited_sequences:  # length >= 2 is enforced by the loader
        for c in s:
            if c not in sev:
                problems.append(f"prohibited sequence names unknown class {c!r}")
    if cfg.composition_on_certain not in ("deny", "ask"):
        problems.append("composition_on_certain must be deny or ask")
    return problems


def cmd_keygen(a: argparse.Namespace) -> int:
    key = SigningKey.generate(a.kid, a.alg)
    out = Path(a.out)
    if os.path.lexists(out) and not a.force:
        print(f"{out} exists; pass --force to overwrite", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    # A new file, created owner-only on POSIX (the mode applies only to a file `open`
    # creates; Windows ignores it, and the key inherits the directory's ACL, so keep it in
    # a private directory). It then replaces whatever is at `out`, a file or a link,
    # without writing through it.
    tmp = out.with_name(f"{out.name}.{secrets.token_hex(4)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(key.private_jwk(), indent=2))
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink()
        raise
    print(json.dumps({"kid": key.kid, "public_jwk": key.public_jwk()}, indent=2))
    return 0


def cmd_check_policy(a: argparse.Namespace) -> int:
    problems = validate_policy(_load(a.policy))
    for p in problems:
        print(f"error: {p}")
    print("ok" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


def cmd_explain(a: argparse.Namespace) -> int:
    """Classify one act and print the decision trace, for policy authors."""
    d0 = _load(a.policy)
    problems = validate_policy(d0)
    if problems:
        raise SystemExit("policy rejected:\n  " + "\n  ".join(problems))
    policy = Policy(PolicyConfig.from_dict(d0))
    if a.resource and not SERVER_ID.fullmatch(a.resource):
        # The SS refuses such a resource at its endpoints (`_server_identifier`).
        raise ValueError(f"{a.resource!r} is not a server identifier (a lowercase https "
                         f"host, with no port or path), which the SS refuses")
    params: dict[str, Any] = {}
    for kv in a.param or []:
        k, _, v = kv.partition("=")
        params[k] = int(v) if v.isdigit() else v
    act = Act("permission" if a.tool else "auth_token", "https://ps.example", "sub", "agent",
              resource=a.resource or "", operations=list(a.operation or []), scope=a.scope or "",
              tool=a.tool or "", parameters=params if (params or a.provenance) else None,
              parameters_provenance=a.provenance or "",
              result={"contains": a.result} if a.result else None)
    d = policy.decide(act, None, [], [], now=0)
    print(json.dumps({"decision": d.decision, "reason": d.reason, "summary": d.summary,
                      "trace": d.trace}, indent=2))
    return 0


def build_server(config: dict[str, Any], policy: dict[str, Any], key_path: str | None,
                 state_path: str | None, claim: bool = False) -> SupervisionServer:
    problems = validate_policy(policy)
    if problems:
        raise SystemExit("policy rejected:\n  " + "\n  ".join(problems))
    eg = config.pop("egress", {}) or {}
    if not isinstance(eg, dict) or set(eg) - {"max_bytes", "timeout", "allow_private_hosts",
                                              "allow_cross_origin_jwks"}:
        raise ValueError("server config: egress has unknown members")
    hosts, timeout = eg.get("allow_private_hosts", []), eg.get("timeout", 5.0)
    size = eg.get("max_bytes", 256 * 1024)
    # A timeout or size every fetch fails under, or one a fetch cannot use (a timeout of
    # 1e308 overflows), would refuse every PS whose keys are not cached.
    if not (isinstance(hosts, list) and all(isinstance(h, str) for h in hosts)) \
            or not isinstance(eg.get("allow_cross_origin_jwks", False), bool) \
            or isinstance(timeout, bool) or not isinstance(timeout, int | float) \
            or not 0 < timeout <= MAX_EGRESS_TIMEOUT \
            or isinstance(size, bool) or not isinstance(size, int) \
            or not 0 < size <= MAX_EGRESS_BYTES:
        raise ValueError("server config: egress has a member of the wrong type or out of range")
    egress = EgressPolicy(
        max_bytes=size, timeout=float(timeout), allow_private_hosts=frozenset(hosts),
        allow_cross_origin_jwks=bool(eg.get("allow_cross_origin_jwks", False)))
    cfg = ServerConfig.from_dict(config)
    if os.environ.get("AAUTH_SS_ADMIN_TOKEN"):
        cfg.admin_token = os.environ["AAUTH_SS_ADMIN_TOKEN"]
    key = SigningKey.from_private_jwk(_load(key_path)) if key_path else None
    # A trusted PS's keys are never evicted by other signers' discoveries.
    resolver = JwksUriResolver(HttpsFetcher(egress), egress, keep=frozenset(cfg.trusted_ps))
    return SupervisionServer(cfg, Policy(PolicyConfig.from_dict(policy)), resolver, key,
                             Store(state_path, claim=claim))


def cmd_serve(a: argparse.Namespace) -> int:
    from .http_server import ACCESS_LOG, serve

    try:
        ss = build_server(_load(a.config), _load(a.policy), a.key, a.state, claim=True)
    except StateInUse as e:
        print(f"error: {e}: another SS serves from this state file", file=sys.stderr)
        return 1
    if ss.store.load_error:
        # Replay rebuilds missions and outstanding tokens, not connections, reach or
        # permission grants outside missions: the operator has to know it started empty.
        print(f"warning: the state file could not be read and was set aside, so the SS "
              f"starts empty and relies on PS replay: {ss.store.load_error}", file=sys.stderr)
    if ss.key is None:
        print("warning: no --key, so decisions are unsigned and the PS's record of them rests "
              "on its word alone (Supervision, Signed Decisions)", file=sys.stderr)
    if not ss.cfg.admin_token and (ss.cfg.open_registration or any(
            not t.auto_connect for t in ss.cfg.trusted_ps.values())):
        print("warning: no operator token (`admin_token`, or AAUTH_SS_ADMIN_TOKEN), so a "
              "connect that waits on the confirmation page can never be confirmed",
              file=sys.stderr)
    try:
        httpd = serve(ss, a.host, a.port)
    except OSError as e:  # a port in use, an address this host has no interface for
        ss.store.release()
        print(f"error: cannot listen on {a.host} port {a.port}: {e}", file=sys.stderr)
        return 1
    # The address bound (port 0 picks one), an IPv6 host in brackets as a URL has it.
    # Flushed now: under a service manager stdout is a pipe written in blocks.
    host, port = cast(tuple[str, int], httpd.server_address[:2])
    shown = f"[{host}]" if ":" in host else host
    print(f"{ss.cfg.issuer} listening on http://{shown}:{port} (loopback; put a TLS proxy "
          f"for the issuer in front)", flush=True)
    # The access log goes to stdout for as long as this process serves, and the handler is
    # removed afterwards, so repeated in-process calls do not stack handlers.
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    level = ACCESS_LOG.level
    ACCESS_LOG.addHandler(handler)
    ACCESS_LOG.setLevel(logging.INFO)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ACCESS_LOG.removeHandler(handler)
        ACCESS_LOG.setLevel(level)
        httpd.server_close()
        ss.store.save()
        ss.store.release()
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    from . import demo

    if a.show_policy:
        print(demo.policy_json())
        return 0
    return demo.run(extension=a.extension, trace=a.trace)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="aauth-ss", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate the SS signing key (private JWK file)")
    k.add_argument("--kid", required=True, help="the key's id in the SS's published JWKS")
    k.add_argument("--alg", default="Ed25519", choices=["Ed25519", "ES256"],
                   help="the signing algorithm (default Ed25519)")
    k.add_argument("--out", required=True,
                   help="the private JWK file to write (owner-only on POSIX)")
    k.add_argument("--force", action="store_true", help="replace an existing file")
    k.set_defaults(fn=cmd_keygen)
    c = sub.add_parser("check-policy", help="validate a policy file")
    c.add_argument("policy", help="the policy JSON file")
    c.set_defaults(fn=cmd_check_policy)
    e = sub.add_parser("explain", help="show how the policy decides one act")
    e.add_argument("policy", help="the policy JSON file")
    e.add_argument("--resource", help="the resource's server identifier")
    e.add_argument("--operation", action="append",
                   help="an operation the act names (repeatable)")
    e.add_argument("--scope", help="the scope asked for")
    e.add_argument("--tool", help="a tool name: the act is then a permission")
    e.add_argument("--param", action="append", help="name=value (repeatable)")
    e.add_argument("--result", action="append",
                   help="a label the result contains (repeatable)")
    e.add_argument("--provenance", choices=["resource", "agent"],
                   help="who states the parameters and result: the resource or the agent")
    e.set_defaults(fn=cmd_explain)
    s = sub.add_parser("serve", help="run the SS on loopback")
    s.add_argument("--config", required=True, help="the server config JSON file")
    s.add_argument("--policy", required=True, help="the policy JSON file")
    s.add_argument("--key", help="the SS's private JWK; without it answers are unsigned")
    s.add_argument("--state", help="the state snapshot file; without it state lives in memory only")
    s.add_argument("--host", default="127.0.0.1", help="a loopback address (default 127.0.0.1)")
    s.add_argument("--port", type=_port, default=8443, help="the port (default 8443)")
    s.set_defaults(fn=cmd_serve)
    m = sub.add_parser("demo", help="watch the SS decide a short mission (in-process, no network)")
    m.add_argument("--extension", action="store_true",
                   help="forward the R3 proposal (AAuth #256, not in Supervision -00)")
    m.add_argument("--trace", action="store_true", help="show what each decision rests on")
    m.add_argument("--show-policy", action="store_true", help="print the demo's policy and exit")
    m.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    try:
        return int(a.fn(a))
    except (ValueError, TypeError, KeyError, OSError) as e:
        # A malformed config, key or policy file, or a path the host refuses (a directory
        # given as the state file, a key file under a file): report it, never a traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


def _port(value: str) -> int:
    n = int(value)
    if not 0 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"{value} is not a port (0 to 65535)")
    return n


if __name__ == "__main__":
    raise SystemExit(main())
