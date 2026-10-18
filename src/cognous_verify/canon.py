"""Canonical form: the pinned profile, implemented independently.

Profile id ``json-sort-keys-compact-utf8-no-nan-python-semantics-v0.1-proposed`` (the name
in the control plane's decision-input vectors; the design note abbreviates it without the
``-proposed`` suffix). Same profile, no migration to RFC 8785 (JCS): this form does not
claim JCS or cross-language equivalence.

Definition implemented here:

* objects: members sorted by key in Unicode code point order, written ``{"k":v,...}``;
* no whitespace outside strings;
* strings in UTF-8, not ASCII-escaped: only ``"``, ``\\`` and the control characters
  U+0000 to U+001F are escaped (``\\b \\f \\n \\r \\t`` by name, the rest as ``\\u00xx``
  with lowercase hex); no Unicode normalization;
* integers as decimal digits, floats as Python ``repr`` (so ``1`` and ``1.0`` differ, and
  ``-0.0`` differs from ``0.0``), booleans ``true``/``false``, null ``null``;
* NaN, Infinity, tuples, sets, bytes and non-string keys are refused.

A commitment is ``sha256:`` plus the lowercase hex SHA-256 of these bytes.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

PROFILE_ID = "json-sort-keys-compact-utf8-no-nan-python-semantics-v0.1-proposed"
MAX_DEPTH = 64

_NAMED = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


class CanonError(ValueError):
    """The value is not representable in the pinned profile."""


def _string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in _NAMED:
            out.append(_NAMED[ch])
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _emit(value: Any, out: list[str], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonError(f"nesting deeper than {MAX_DEPTH}")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif type(value) is int:
        out.append(str(value))
    elif type(value) is float:
        if not math.isfinite(value):
            raise CanonError("non-finite number")
        out.append(repr(value))
    elif type(value) is str:
        out.append(_string(value))
    elif type(value) is list:
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _emit(item, out, depth + 1)
        out.append("]")
    elif type(value) is dict:
        out.append("{")
        for key in value:
            if type(key) is not str:
                raise CanonError("object keys must be strings")
        for i, key in enumerate(sorted(value)):
            if i:
                out.append(",")
            out.append(_string(key))
            out.append(":")
            _emit(value[key], out, depth + 1)
        out.append("}")
    else:
        raise CanonError(f"{type(value).__name__} is not a JSON value")


def canonical_text(value: Any) -> str:
    out: list[str] = []
    _emit(value, out, 0)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    """Canonical bytes of a JSON value under the pinned profile."""
    try:
        return canonical_text(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonError("string holds a lone surrogate") from exc


def commitment(value: Any) -> str:
    """``sha256:`` plus the hex digest of the canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    """``sha256:`` digest of raw bytes (used for input files, not for commitments)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()
