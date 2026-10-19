"""Minimal RFC 9651 Structured Field Values for the headers AAuth uses.

Covers Dictionary, Inner List, Item and Parameters with the bare item
types Integer, Decimal, String, Token, Byte Sequence and Boolean. Enough for
Signature-Input, Signature, Signature-Key, Signature-Error, Accept-Signature
and Content-Digest. Parsing is strict: any syntax error raises SFVError.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field


class SFVError(ValueError):
    """Malformed structured field."""


@dataclass(frozen=True)
class Token:
    value: str


# Type aliases, only ever used in annotations (never evaluated: `from __future__ import
# annotations`), so replacing one with `None` is an equivalent mutant.
BareItem = int | float | str | bytes | bool | Token  # pragma: no mutate


@dataclass
class Item:
    value: BareItem
    params: dict[str, BareItem] = field(default_factory=dict)


@dataclass
class InnerList:
    items: list[Item]
    params: dict[str, BareItem] = field(default_factory=dict)


Member = Item | InnerList  # pragma: no mutate (type alias, see BareItem)

_KEY_START = re.compile(r"[a-z*]")
_KEY_CHAR = re.compile(r"[a-z0-9_\-.*]")
_TOKEN_START = re.compile(r"[A-Za-z*]")
_TOKEN_CHAR = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z:/]")


class _Parser:
    def __init__(self, text: str) -> None:
        self.s = text
        self.i = 0

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.i += 1

    def key(self) -> str:
        if not _KEY_START.match(self.peek() or "\0"):
            raise SFVError(f"bad key at {self.i}")
        start = self.i
        while not self.eof() and _KEY_CHAR.match(self.peek()):
            self.i += 1
        return self.s[start:self.i]

    def bare(self) -> BareItem:
        c = self.peek()
        if c == "-" or c.isdigit():
            return self.number()
        if c == '"':
            return self.string()
        if c == ":":
            return self.bytes_()
        if c == "?":
            return self.boolean()
        if c and _TOKEN_START.match(c):
            return self.token()
        raise SFVError(f"bad item at {self.i}")

    def number(self) -> int | float:
        m = re.compile(r"-?\d{1,15}(\.\d{1,3})?").match(self.s, self.i)
        if not m:
            raise SFVError(f"bad number at {self.i}")
        self.i = m.end()
        txt = m.group(0)
        if "." in txt:
            if len(txt.split(".")[0].lstrip("-")) > 12:
                raise SFVError("decimal too long")
            return float(txt)
        return int(txt)

    def string(self) -> str:
        self.i += 1
        out = []
        while True:
            if self.eof():
                raise SFVError("unterminated string")
            c = self.s[self.i]
            self.i += 1
            if c == "\\":
                if self.eof() or self.s[self.i] not in ('"', "\\"):
                    raise SFVError("bad escape")
                out.append(self.s[self.i])
                self.i += 1
            elif c == '"':
                return "".join(out)
            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise SFVError("bad string char")
            else:
                out.append(c)

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while not self.eof() and _TOKEN_CHAR.match(self.peek()):
            self.i += 1
        return Token(self.s[start:self.i])

    def bytes_(self) -> bytes:
        self.i += 1
        end = self.s.find(":", self.i)
        if end < 0:
            raise SFVError("unterminated byte sequence")
        raw = self.s[self.i:end]
        self.i = end + 1
        if not re.fullmatch(r"[A-Za-z0-9+/=]*", raw):
            raise SFVError("bad base64")
        if "=" not in raw:  # RFC 9651 4.2.7: parsers SHOULD NOT fail when padding is absent
            raw += "=" * (-len(raw) % 4)
        try:
            return base64.b64decode(raw, validate=True)
        except ValueError as e:  # binascii.Error: bad padding, e.g. ":a:"
            raise SFVError("bad base64") from e

    def boolean(self) -> bool:
        self.i += 1
        c = self.peek()
        if c not in ("0", "1"):
            raise SFVError("bad boolean")
        self.i += 1
        return c == "1"

    def params(self) -> dict[str, BareItem]:
        out: dict[str, BareItem] = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            k = self.key()
            v: BareItem = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare()
            out[k] = v
        return out

    def item(self) -> Item:
        v = self.bare()
        return Item(v, self.params())

    def inner_list(self) -> InnerList:
        self.i += 1
        items: list[Item] = []
        while True:
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.params())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise SFVError("bad inner list")

    def member(self) -> Member:
        return self.inner_list() if self.peek() == "(" else self.item()


def parse_dictionary(text: str, unique: bool = False) -> dict[str, Member]:
    """RFC 9651 4.2.2. A key given twice keeps its last value, as the RFC says; with
    `unique`, it fails instead (for a field whose readers may take the first)."""
    p = _Parser(text.strip(" "))
    out: dict[str, Member] = {}
    if p.eof():
        return out
    while True:
        k = p.key()
        if unique and k in out:
            raise SFVError(f"key {k!r} given twice")
        if p.peek() == "=":
            p.i += 1
            out[k] = p.member()
        else:
            out[k] = Item(True, p.params())
        p.skip_ows()
        if p.eof():
            return out
        if p.peek() != ",":
            raise SFVError(f"expected ',' at {p.i}")
        p.i += 1
        p.skip_ows()
        if p.eof():
            raise SFVError("trailing comma")


# --------------------------------------------------------------------- serialize


def ser_bare(v: BareItem) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, Token):
        return v.value
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # RFC 9651 4.1.5: at most three fractional digits, and at least one.
        s = f"{v:.3f}".rstrip("0")
        return s + "0" if s.endswith(".") else s
    if isinstance(v, bytes):
        return ":" + base64.b64encode(v).decode("ascii") + ":"
    if isinstance(v, str):
        if any(ord(c) < 0x20 or ord(c) > 0x7E for c in v):
            raise SFVError("string not ASCII-printable")
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFVError(f"cannot serialize {type(v)}")


def ser_params(params: dict[str, BareItem]) -> str:
    out = []
    for k, v in params.items():
        out.append(f";{k}" if v is True else f";{k}={ser_bare(v)}")
    return "".join(out)


def ser_item(it: Item) -> str:
    return ser_bare(it.value) + ser_params(it.params)


def ser_inner_list(il: InnerList) -> str:
    return "(" + " ".join(ser_item(i) for i in il.items) + ")" + ser_params(il.params)


def ser_member(m: Member) -> str:
    return ser_inner_list(m) if isinstance(m, InnerList) else ser_item(m)


def ser_dictionary(d: dict[str, Member]) -> str:
    parts = []
    for k, m in d.items():
        if isinstance(m, Item) and m.value is True:
            parts.append(k + ser_params(m.params))
        else:
            parts.append(f"{k}={ser_member(m)}")
    return ", ".join(parts)
