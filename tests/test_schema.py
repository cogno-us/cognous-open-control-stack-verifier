from __future__ import annotations

from typing import Any

import pytest

from cognous_verify import schema


def codes(doc: Any, sch: dict[str, Any]) -> list[str]:
    return [f.code for f in schema.validate_structure(doc, sch)]


def test_keywords_the_contracts_use() -> None:
    sch: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["a"],
        "properties": {
            "a": {"type": "string", "minLength": 2, "maxLength": 3, "pattern": "^x"},
            "b": {"enum": ["p", "q"]},
            "c": {"const": 1},
            "d": {"type": "array", "items": {"type": "integer"}},
            "e": {"type": ["string", "null"]},
            "f": {"type": "number"},
            "g": {"type": "boolean"},
            "ext": {"type": "object", "propertyNames": {"pattern": "^x-"}},
            "n": {"type": "object", "propertyNames": {"pattern": "^[a-z]+$"}},
        },
    }
    assert codes({"a": "xy"}, sch) == []
    assert codes({}, sch) == ["schema_violation"]
    assert codes({"a": "x"}, sch) == ["schema_violation"]
    assert codes({"a": "xyzw"}, sch) == ["schema_violation"]
    assert codes({"a": "yy"}, sch) == ["schema_violation"]
    assert codes({"a": "xy", "b": "z"}, sch) == ["unknown_enum_value"]
    assert codes({"a": "xy", "c": 2}, sch) == ["schema_violation"]
    assert codes({"a": "xy", "d": [1, True]}, sch) == ["schema_violation"]
    assert codes({"a": "xy", "e": None, "f": 1.5, "g": False}, sch) == []
    assert codes({"a": "xy", "e": 3}, sch) == ["schema_violation"]
    assert codes({"a": "xy", "zz": 1}, sch) == ["undeclared_member"]
    assert codes({"a": "xy", "ext": {"x-ok": 1, "bad": 2}}, sch) == ["invalid_extension_key"]
    assert codes({"a": "xy", "n": {"UP": 1}}, sch) == ["schema_violation"]
    assert codes({"a": "xy", "g": 0}, sch) == ["schema_violation"]


def test_enum_is_type_strict() -> None:
    assert codes(1, {"enum": [True]}) == ["unknown_enum_value"]
    assert codes(1.0, {"enum": [1]}) == ["unknown_enum_value"]


def test_additional_properties_schema_and_refs() -> None:
    sch: dict[str, Any] = {
        "type": "object",
        "additionalProperties": {"$ref": "#/$defs/s"},
        "$defs": {"s": {"type": "string"}},
    }
    assert codes({"k": "v"}, sch) == []
    assert codes({"k": 1}, sch) == ["schema_violation"]


def test_one_of_and_any_of() -> None:
    one: dict[str, Any] = {"oneOf": [{"type": "null"}, {"type": "string"}]}
    assert codes(None, one) == [] and codes("s", one) == []
    assert codes(3, one) == ["schema_violation"]
    nested: dict[str, Any] = {"oneOf": [{"type": "string", "enum": ["a"]}, {"type": "null"}]}
    assert codes("b", nested) == ["unknown_enum_value"]
    anyof: dict[str, Any] = {"anyOf": [{"type": "null"}, {"type": "object", "required": ["k"]}]}
    assert codes({"k": 1}, anyof) == [] and codes(None, anyof) == []
    assert codes({}, anyof) == ["schema_violation"]
    both: dict[str, Any] = {
        "anyOf": [{"type": "object", "required": ["k"]}],
        "type": "object",
        "additionalProperties": False,
        "properties": {"k": {"type": "integer"}},
    }
    assert codes({"k": 1, "z": 2}, both) == ["undeclared_member"]


def test_unsupported_keyword_or_type_or_ref_is_an_error_not_a_pass() -> None:
    with pytest.raises(schema.SchemaError):
        schema.validate_structure(1, {"minimum": 0})
    with pytest.raises(schema.SchemaError):
        schema.validate_structure(1, {"type": "decimal"})
    with pytest.raises(schema.SchemaError):
        schema.validate_structure(1, {"$ref": "http://elsewhere/x"})
    with pytest.raises(schema.SchemaError):
        schema.validate_structure(1, {"$ref": "#/$defs/x", "$defs": {"x": 1}})
