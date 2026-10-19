"""`documentation_uri` is published as configured, so it must be a URL a reader can follow:
https (Protocol L1994), with no whitespace or control character, no user information, and
a port in range.
"""
from __future__ import annotations

import pytest

from aauth_supervision_server.service import ServerConfig


@pytest.mark.parametrize("uri", ["https://docs example/x", "https://u:p@docs.example/",
                                 "https://docs.example:99999/", "https://docs.example/\nX: 1",
                                 "https://docs.example/\u00a0", "https://docs.ex\u00e4mple/"])
def test_a_documentation_uri_that_is_no_url_is_refused(uri: str) -> None:
    with pytest.raises(ValueError, match="documentation_uri"):
        ServerConfig.from_dict({"issuer": "https://ss.example", "documentation_uri": uri})


@pytest.mark.parametrize("uri", ["https://docs.example/a?b=c#d", "https://docs.example:8443/",
                                 "https://[::1]/docs"])
def test_a_documentation_uri_that_is_a_url_is_kept(uri: str) -> None:
    cfg = ServerConfig.from_dict({"issuer": "https://ss.example", "documentation_uri": uri})
    assert cfg.documentation_uri == uri
