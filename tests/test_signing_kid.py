r"""The SS's own key id is a value its Signature-Key can carry.

Every signed answer names the SS's key in `Signature-Key: sig=jwks_uri;id=...;kid=...`,
whose parameters are Structured Field Strings (RFC 9651 3.3.3: printable ASCII, with `"`
and `\` escaped). A `kid` with a quote or a backslash is escaped; one outside printable
ASCII cannot be carried at all, so `keygen` and key loading refuse it rather than leave
every signed answer unverifiable (the PS then treats it as `server_error`, Supervision
L342).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from conftest import SUB, make_env

from aauth_supervision_server import cli
from aauth_supervision_server.jwk import SigningKey


@pytest.mark.parametrize("kid", ['ss"2026', "ss\\2026", "ss 2026", "~"])
def test_a_kid_with_characters_to_escape_still_verifies(kid: str) -> None:
    ss, ps, _ = make_env()
    ss.key = SigningKey.generate(kid)
    ps.ss_jwk = ss.key.public_jwk()
    assert ps.connect(ss, SUB).status == 200          # the PS verified the signed answer


@pytest.mark.parametrize("kid", ["ss-2026-é", "ss-ł", "", "ss\x7f", "a\tb"])
def test_a_kid_signature_key_cannot_carry_is_refused(kid: str, tmp_path: Path,
                                                    capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(ValueError, match="kid"):
        SigningKey.generate(kid)
    out = tmp_path / "k.json"
    assert cli.main(["keygen", "--kid", kid, "--out", str(out)]) == 2
    assert "kid" in capsys.readouterr().err and not out.exists()
    jwk = SigningKey.generate("ok").private_jwk() | {"kid": kid}
    with pytest.raises(ValueError, match="kid"):
        SigningKey.from_private_jwk(jwk)
