"""Strict JSON reader (tier V1, wire level).

A hand-written RFC 8259 parser, not ``json.loads`` with hooks. It refuses, before any
document model exists: input over the size limit, bytes that are not UTF-8, a byte-order
mark, duplicate object members (compared after unescaping), the constants ``NaN`` and
``Infinity``, lone surrogate escapes, numbers outside the stated range, nesting beyond the
stated depth, and trailing data. Refusal is the verdict: nothing is repaired or normalized.

Values come back as dict, list, str, int, float, bool and None. Integer and float stay
distinct (``1`` is an int, ``1.0`` and ``1e2`` are floats), because the pinned canonical
profile keeps them distinct.
"""

from __future__ import annotations

from typing import Any

MAX_BYTES = 8 * 1024 * 1024
MAX_DEPTH = 64
MAX_INT = 2**53 - 1
MAX_NUMBER_LEXEME = 64

WIRE_CODES = (
    "wire_too_large",
    "wire_not_utf8",
    "wire_bom",
    "wire_syntax",
    "wire_duplicate_member",
    "wire_nonfinite_constant",
    "wire_lone_surrogate",
    "wire_number_out_of_range",
    "wire_depth",
    "wire_trailing_data",
)

_WS = " \t\n\r"
_DIGITS = "0123456789"
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


class WireError(ValueError):
    """A wire-level refusal with a stable ``wire_*`` code and a character offset."""

    def __init__(self, code: str, offset: int, message: str) -> None:
        super().__init__(f"{code} at offset {offset}: {message}")
        self.code = code
        self.offset = offset
        self.message = message


def decode(data: bytes, *, max_bytes: int = MAX_BYTES) -> str:
    """Bytes to text under the wire rules (size, byte-order mark, strict UTF-8)."""
    if len(data) > max_bytes:
        raise WireError("wire_too_large", 0, f"input is {len(data)} bytes; limit is {max_bytes}")
    if data.startswith(b"\xef\xbb\xbf"):
        raise WireError("wire_bom", 0, "byte-order mark")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WireError("wire_not_utf8", exc.start, "bytes are not valid UTF-8") from exc


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.n = len(text)

    def fail(self, code: str, message: str, at: int | None = None) -> WireError:
        return WireError(code, self.pos if at is None else at, message)

    def skip(self) -> None:
        text, n, i = self.text, self.n, self.pos
        while i < n and text[i] in _WS:
            i += 1
        self.pos = i

    def value(self, depth: int) -> Any:
        self.skip()
        if self.pos >= self.n:
            raise self.fail("wire_syntax", "unexpected end of input")
        ch = self.text[self.pos]
        if ch == "{":
            return self.obj(depth + 1)
        if ch == "[":
            return self.arr(depth + 1)
        if ch == '"':
            return self.string()
        if ch == "-" or ch in _DIGITS:
            if self.text.startswith("-Infinity", self.pos):
                raise self.fail("wire_nonfinite_constant", "-Infinity is not JSON")
            return self.number()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.pos):
                self.pos += len(word)
                return val
        for word in ("NaN", "Infinity"):
            if self.text.startswith(word, self.pos):
                raise self.fail("wire_nonfinite_constant", f"{word} is not JSON")
        raise self.fail("wire_syntax", f"unexpected character {ch!r}")

    def obj(self, depth: int) -> dict[str, Any]:
        if depth > MAX_DEPTH:
            raise self.fail("wire_depth", f"nesting deeper than {MAX_DEPTH}")
        self.pos += 1
        out: dict[str, Any] = {}
        self.skip()
        if self.pos < self.n and self.text[self.pos] == "}":
            self.pos += 1
            return out
        while True:
            self.skip()
            if self.pos >= self.n or self.text[self.pos] != '"':
                raise self.fail("wire_syntax", "object member name must be a string")
            start = self.pos
            name = self.string()
            if name in out:
                raise self.fail("wire_duplicate_member", f"duplicate member {name!r}", start)
            self.skip()
            if self.pos >= self.n or self.text[self.pos] != ":":
                raise self.fail("wire_syntax", "expected ':' after member name")
            self.pos += 1
            out[name] = self.value(depth)
            self.skip()
            if self.pos >= self.n:
                raise self.fail("wire_syntax", "unterminated object")
            ch = self.text[self.pos]
            self.pos += 1
            if ch == "}":
                return out
            if ch != ",":
                raise self.fail("wire_syntax", "expected ',' or '}' in object", self.pos - 1)

    def arr(self, depth: int) -> list[Any]:
        if depth > MAX_DEPTH:
            raise self.fail("wire_depth", f"nesting deeper than {MAX_DEPTH}")
        self.pos += 1
        out: list[Any] = []
        self.skip()
        if self.pos < self.n and self.text[self.pos] == "]":
            self.pos += 1
            return out
        while True:
            out.append(self.value(depth))
            self.skip()
            if self.pos >= self.n:
                raise self.fail("wire_syntax", "unterminated array")
            ch = self.text[self.pos]
            self.pos += 1
            if ch == "]":
                return out
            if ch != ",":
                raise self.fail("wire_syntax", "expected ',' or ']' in array", self.pos - 1)

    def hex4(self) -> int:
        chunk = self.text[self.pos : self.pos + 4]
        if len(chunk) != 4 or any(c not in "0123456789abcdefABCDEF" for c in chunk):
            raise self.fail("wire_syntax", "bad \\u escape")
        self.pos += 4
        return int(chunk, 16)

    def string(self) -> str:
        self.pos += 1  # opening quote
        parts: list[str] = []
        text, n = self.text, self.n
        while True:
            if self.pos >= n:
                raise self.fail("wire_syntax", "unterminated string")
            ch = text[self.pos]
            if ch == '"':
                self.pos += 1
                return "".join(parts)
            if ch < " ":
                raise self.fail("wire_syntax", "raw control character in string")
            if ch != "\\":
                parts.append(ch)
                self.pos += 1
                continue
            self.pos += 1
            if self.pos >= n:
                raise self.fail("wire_syntax", "unterminated escape")
            esc = text[self.pos]
            self.pos += 1
            if esc in _ESCAPES:
                parts.append(_ESCAPES[esc])
                continue
            if esc != "u":
                raise self.fail("wire_syntax", f"bad escape \\{esc}", self.pos - 2)
            at = self.pos - 2
            code = self.hex4()
            if 0xD800 <= code <= 0xDBFF:
                if text.startswith("\\u", self.pos):
                    self.pos += 2
                    low = self.hex4()
                    if 0xDC00 <= low <= 0xDFFF:
                        parts.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                        continue
                raise self.fail("wire_lone_surrogate", "high surrogate without a low surrogate", at)
            if 0xDC00 <= code <= 0xDFFF:
                raise self.fail("wire_lone_surrogate", "low surrogate without a high surrogate", at)
            parts.append(chr(code))

    def number(self) -> int | float:
        text, n, start = self.text, self.n, self.pos
        i = start
        if i < n and text[i] == "-":
            i += 1
        if i >= n or text[i] not in _DIGITS:
            raise self.fail("wire_syntax", "malformed number", start)
        if text[i] == "0":
            i += 1
            if i < n and text[i] in _DIGITS:
                raise self.fail("wire_syntax", "leading zero in number", start)
        else:
            while i < n and text[i] in _DIGITS:
                i += 1
        is_float = False
        if i < n and text[i] == ".":
            is_float = True
            i += 1
            if i >= n or text[i] not in _DIGITS:
                raise self.fail("wire_syntax", "digits required after '.'", start)
            while i < n and text[i] in _DIGITS:
                i += 1
        if i < n and text[i] in "eE":
            is_float = True
            i += 1
            if i < n and text[i] in "+-":
                i += 1
            if i >= n or text[i] not in _DIGITS:
                raise self.fail("wire_syntax", "digits required in exponent", start)
            while i < n and text[i] in _DIGITS:
                i += 1
        lexeme = text[start:i]
        if len(lexeme) > MAX_NUMBER_LEXEME:
            raise self.fail("wire_number_out_of_range", "number lexeme too long", start)
        self.pos = i
        if not is_float:
            value = int(lexeme)
            if abs(value) > MAX_INT:
                raise self.fail("wire_number_out_of_range", f"integer beyond +-{MAX_INT}", start)
            return value
        fvalue = float(lexeme)
        if fvalue in (float("inf"), float("-inf")):
            raise self.fail("wire_number_out_of_range", "float overflows to infinity", start)
        return fvalue


def parse_text(text: str) -> Any:
    """Parse already decoded text under the wire rules."""
    parser = _Parser(text)
    value = parser.value(0)
    parser.skip()
    if parser.pos != parser.n:
        raise parser.fail("wire_trailing_data", "data after the JSON value")
    return value


def parse(data: bytes, *, max_bytes: int = MAX_BYTES) -> Any:
    """Parse bytes under the wire rules; raise ``WireError`` with a stable code on refusal."""
    return parse_text(decode(data, max_bytes=max_bytes))
