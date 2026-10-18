"""Tier V1 structure: a small JSON Schema subset interpreter, written here.

The contract schemas under ``data/`` are data (vendored, hashed in ``data/PROVENANCE.json``);
the interpreter is this file. Supported keywords are exactly those the two contract schemas
use: ``type``, ``enum``, ``const``, ``required``, ``properties``, ``additionalProperties``
(false or a schema), ``items``, ``oneOf``, ``anyOf``, ``$ref`` into ``#/$defs``, ``pattern``,
``minLength``, ``maxLength`` and ``propertyNames.pattern``. An unsupported keyword is an
error, not a pass.

Stable structural codes: ``schema_violation``, ``unknown_enum_value``, ``undeclared_member``,
``invalid_extension_key``.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

from .results import Finding

SUPPORTED = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "enum",
    "const",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "oneOf",
    "anyOf",
    "pattern",
    "minLength",
    "maxLength",
    "propertyNames",
}


class SchemaError(ValueError):
    """The schema uses something this interpreter does not implement."""


def _is_type(value: Any, name: str) -> bool:
    if name == "object":
        return type(value) is dict
    if name == "array":
        return type(value) is list
    if name == "string":
        return type(value) is str
    if name == "null":
        return value is None
    if name == "boolean":
        return type(value) is bool
    if name == "integer":
        return type(value) is int
    if name == "number":
        return type(value) in (int, float)
    raise SchemaError(f"unsupported type {name!r}")


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if ref is None:
        return schema
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise SchemaError(f"unsupported $ref {ref!r}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part]
    if not isinstance(node, dict):
        raise SchemaError(f"$ref {ref!r} does not name a schema")
    return node


def _same(value: Any, option: Any) -> bool:
    return bool(value == option and type(value) is type(option))


def _matches(pattern: str, value: str) -> bool:
    """JSON Schema pattern search, with a closing ``$`` read as the end of the string.

    In Python ``$`` also matches just before a trailing newline, so ``^x$`` would accept
    ``"x\\n"``. A pattern ending in an unescaped ``$`` is searched with ``\\Z`` instead; a
    pattern without it keeps the search semantics the schema keyword has.
    """
    if pattern.endswith("$") and not pattern.endswith("\\$"):
        pattern = pattern[:-1] + "\\Z"
    return re.search(pattern, value, re.ASCII) is not None


def _not_unicode(text: str) -> bool:
    """True when ``text`` holds an unpaired surrogate (it cannot be encoded as UTF-8)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


class _EnoughFindings(Exception):
    """Internal: the structural pass stops once the findings kept are plenty (any one refutes)."""


STRUCTURE_FINDINGS_LIMIT = 1000


def _check(
    value: Any, schema: dict[str, Any], root: dict[str, Any], path: str, out: list[Finding]
) -> None:
    if len(out) >= STRUCTURE_FINDINGS_LIMIT:
        raise _EnoughFindings
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise SchemaError(f"unsupported schema keyword(s) {sorted(unknown)} at {path}")
    if isinstance(value, str) and _not_unicode(value):
        # Refused as one typed violation before any enum, pattern or length rule reads the text
        # (ODES #93: the reference validators scan the whole document first).
        out.append(
            Finding("schema_violation", path, "text is not valid Unicode (unpaired surrogate)")
        )
        return
    schema = _resolve(schema, root)
    if "const" in schema and not _same(value, schema["const"]):
        out.append(Finding("schema_violation", path, f"expected constant {schema['const']!r}"))
        return
    if "enum" in schema and not any(_same(value, o) for o in schema["enum"]):
        out.append(Finding("unknown_enum_value", path, f"value {value!r} not in the declared set"))
        return
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_is_type(value, n) for n in names):
            out.append(Finding("schema_violation", path, f"expected type {'|'.join(names)}"))
            return
    if "oneOf" in schema:
        _alternatives(value, schema, "oneOf", root, path, out)
        return
    if "anyOf" in schema:
        before = len(out)
        _alternatives(value, schema, "anyOf", root, path, out)
        if len(out) > before:
            return
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(Finding("schema_violation", path, "string shorter than minimum length"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(Finding("schema_violation", path, "string longer than maximum length"))
        if "pattern" in schema and not _matches(schema["pattern"], value):
            out.append(
                Finding("schema_violation", path, f"string does not match {schema['pattern']}")
            )
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            _check(item, schema["items"], root, f"{path}[{i}]", out)
    if isinstance(value, dict):
        _object(value, schema, root, path, out)


def _alternatives(
    value: Any,
    schema: dict[str, Any],
    keyword: str,
    root: dict[str, Any],
    path: str,
    out: list[Finding],
) -> None:
    options: list[dict[str, Any]] = schema[keyword]
    trials: list[list[Finding]] = []
    for option in options:
        trial: list[Finding] = []
        _check(value, option, root, path, trial)
        trials.append(trial)
    matches = sum(1 for t in trials if not t)
    if (keyword == "oneOf" and matches == 1) or (keyword == "anyOf" and matches >= 1):
        return
    if keyword == "oneOf" and value is not None:
        for trial in trials:
            if trial:
                out.extend(trial)
                return
    out.append(Finding("schema_violation", path, f"does not match {keyword} alternatives"))


def _object(
    value: dict[str, Any],
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str,
    out: list[Finding],
) -> None:
    props: dict[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in value:
            out.append(Finding("schema_violation", f"{path}.{name}", "required member missing"))
    extra = schema.get("additionalProperties", True)
    for name, member in value.items():
        if _not_unicode(name):
            out.append(
                Finding(
                    "schema_violation",
                    f"{path}.{name.encode('unicode_escape').decode('ascii')}",
                    "member name is not valid Unicode (unpaired surrogate)",
                )
            )
            continue
        if name in props:
            _check(member, props[name], root, f"{path}.{name}", out)
        elif extra is False:
            out.append(
                Finding(
                    "undeclared_member",
                    f"{path}.{name}",
                    "member is neither declared nor inside the extensions namespace",
                )
            )
        elif isinstance(extra, dict):
            _check(member, extra, root, f"{path}.{name}", out)
    names = schema.get("propertyNames")
    if names is not None:
        pattern = names.get("pattern", "")
        reserved = pattern.startswith("^x-")
        for name in value:
            if not _not_unicode(name) and not _matches(pattern, name):
                out.append(
                    Finding(
                        "invalid_extension_key" if reserved else "schema_violation",
                        f"{path}.{name}",
                        "extension member names must match the reserved x- form"
                        if reserved
                        else "member name does not match its declared form",
                    )
                )


def validate_structure(doc: Any, schema: dict[str, Any]) -> list[Finding]:
    """All structural findings for ``doc`` against ``schema`` (empty means conformant)."""
    out: list[Finding] = []
    # once enough findings exist the rest would only cost memory: any one finding refutes
    with contextlib.suppress(_EnoughFindings):
        _check(doc, schema, schema, "$", out)
    return out
