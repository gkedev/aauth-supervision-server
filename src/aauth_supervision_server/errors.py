"""Signature-key errors and AAuth protocol errors, rendered as HTTP responses."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def json(self) -> object:
        return json.loads(self.body) if self.body else None


def json_response(status: int, obj: object, headers: dict[str, str] | None = None) -> Response:
    body = json.dumps(obj, separators=(",", ":"), sort_keys=False).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    return Response(status, h, body)


class ProtocolError(Exception):
    """An AAuth error with an `error` code (core, Error Response Format)."""

    def __init__(self, status: int, error: str, detail: str = "",
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(f"{status} {error}: {detail}")
        self.status = status
        self.error = error
        self.detail = detail
        self.headers = headers or {}

    def to_response(self) -> Response:
        obj: dict[str, object] = {"error": self.error}
        if self.detail:
            obj["detail"] = self.detail
        body = json.dumps(obj, separators=(",", ":")).encode()
        h = {"Content-Type": "application/problem+json"}
        h.update(self.headers)
        return Response(self.status, h, body)


class SignatureError(ProtocolError):
    """Signature failure: 401 with Signature-Error (core, Verification (Server))."""

    def __init__(self, code: str, detail: str = "", extra: dict[str, str] | None = None) -> None:
        headers = {"Signature-Error": f"error={code}"}
        headers.update(extra or {})
        super().__init__(401, code, detail, headers)

    def to_response(self) -> Response:
        obj = {
            "type": f"urn:ietf:params:sig-error:{self.error}",
            "title": self.error,
            "status": 401,
            "error": self.error,
        }
        if self.detail:
            obj["detail"] = self.detail
        h = {"Content-Type": "application/problem+json"}
        h.update(self.headers)
        return Response(401, h, json.dumps(obj, separators=(",", ":")).encode())


def invalid_request(detail: str) -> ProtocolError:
    return ProtocolError(400, "invalid_request", detail)


def unsupported_iss(detail: str = "") -> ProtocolError:
    return ProtocolError(403, "unsupported_iss", detail)


def unknown_sub(detail: str = "") -> ProtocolError:
    return ProtocolError(404, "unknown_sub", detail)


def unknown_mission(detail: str = "") -> ProtocolError:
    return ProtocolError(404, "unknown_mission", detail)


def unknown_pending(detail: str = "") -> ProtocolError:
    return ProtocolError(404, "unknown_pending", detail)


def rate_limited(retry_after: int) -> ProtocolError:
    return ProtocolError(429, "rate_limited", "", {"Retry-After": str(retry_after)})


def server_error(detail: str = "") -> ProtocolError:
    return ProtocolError(500, "server_error", detail)
