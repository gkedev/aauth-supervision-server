"""`aauth-ss`: run and operate the Supervision Server.

    aauth-ss keygen --kid ss-2026-10 --out ss-key.json
    aauth-ss check-policy examples/policy.json
    aauth-ss explain examples/policy.json --resource https://mail.example \\
        --operation send_email --param to=a@evil.example --provenance resource
    aauth-ss serve --config examples/server.json --policy examples/policy.json \\
        --key ss-key.json --state state.json --port 8443
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from .egress import EgressPolicy, HttpsFetcher
from .jwk import SigningKey
from .policy import Act, Policy, PolicyConfig
from .resolver import JwksUriResolver
from .service import ServerConfig, SupervisionServer
from .store import Store


def _load(path: str) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise SystemExit(f"{path}: {e.strerror or e}") from e
    except ValueError as e:
        raise SystemExit(f"{path}: not valid JSON ({e})") from e
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
            problems.append(f"class {c!r} is used but missing from severity")
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
    if out.exists() and not a.force:
        print(f"{out} exists; pass --force to overwrite", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    # Create the file with owner-only permissions from the start (no window in which the
    # private key is readable under the default umask).
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(out, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(key.private_jwk(), indent=2))
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
                 state_path: str | None) -> SupervisionServer:
    problems = validate_policy(policy)
    if problems:
        raise SystemExit("policy rejected:\n  " + "\n  ".join(problems))
    eg = config.pop("egress", {}) or {}
    if not isinstance(eg, dict) or set(eg) - {"max_bytes", "timeout", "allow_private_hosts",
                                              "allow_cross_origin_jwks"}:
        raise ValueError("server config: egress has unknown members")
    if not isinstance(eg.get("allow_private_hosts", []), list) or not isinstance(
            eg.get("allow_cross_origin_jwks", False), bool):
        raise ValueError("server config: egress has the wrong types")
    egress = EgressPolicy(
        max_bytes=int(eg.get("max_bytes", 256 * 1024)), timeout=float(eg.get("timeout", 5.0)),
        allow_private_hosts=frozenset(eg.get("allow_private_hosts", [])),
        allow_cross_origin_jwks=bool(eg.get("allow_cross_origin_jwks", False)))
    cfg = ServerConfig.from_dict(config)
    if os.environ.get("AAUTH_SS_ADMIN_TOKEN"):
        cfg.admin_token = os.environ["AAUTH_SS_ADMIN_TOKEN"]
    key = SigningKey.from_private_jwk(_load(key_path)) if key_path else None
    return SupervisionServer(cfg, Policy(PolicyConfig.from_dict(policy)),
                             JwksUriResolver(HttpsFetcher(egress), egress), key,
                             Store(state_path))


def cmd_serve(a: argparse.Namespace) -> int:
    from .http_server import ACCESS_LOG, serve

    ss = build_server(_load(a.config), _load(a.policy), a.key, a.state)
    if ss.key is None:
        print("warning: no --key, so decisions are unsigned and the PS's record of them rests "
              "on its word alone (Supervision, jwks_uri)", file=sys.stderr)
    httpd = serve(ss, a.host, a.port)
    print(f"{ss.cfg.issuer} listening on http://{a.host}:{a.port} (loopback; put a TLS proxy "
          f"for the issuer in front)")
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
    k.add_argument("--kid", required=True)
    k.add_argument("--alg", default="Ed25519", choices=["Ed25519", "ES256"])
    k.add_argument("--out", required=True)
    k.add_argument("--force", action="store_true")
    k.set_defaults(fn=cmd_keygen)
    c = sub.add_parser("check-policy", help="validate a policy file")
    c.add_argument("policy")
    c.set_defaults(fn=cmd_check_policy)
    e = sub.add_parser("explain", help="show how the policy decides one act")
    e.add_argument("policy")
    e.add_argument("--resource")
    e.add_argument("--operation", action="append")
    e.add_argument("--scope")
    e.add_argument("--tool")
    e.add_argument("--param", action="append", help="name=value")
    e.add_argument("--result", action="append", help="a label the result contains")
    e.add_argument("--provenance", choices=["resource", "agent"])
    e.set_defaults(fn=cmd_explain)
    s = sub.add_parser("serve", help="run the SS on loopback")
    s.add_argument("--config", required=True)
    s.add_argument("--policy", required=True)
    s.add_argument("--key")
    s.add_argument("--state")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8443)
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
    except (ValueError, TypeError, KeyError) as e:
        # A malformed config, key or policy file: report it, never a traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
