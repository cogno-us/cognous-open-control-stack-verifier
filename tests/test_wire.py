from __future__ import annotations

import json

import pytest

from cognous_verify import wire


def refused(raw: bytes | str) -> str:
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    with pytest.raises(wire.WireError) as info:
        wire.parse(data)
    return info.value.code


def test_accepts_plain_document() -> None:
    assert wire.parse(b' {"a":[1,1.0,2e2,true,false,null,"x"],"b":{}} ') == {
        "a": [1, 1.0, 200.0, True, False, None, "x"],
        "b": {},
    }


def test_int_and_float_stay_distinct() -> None:
    value = wire.parse(b"[1,1.0,1e2,-0,-0.0]")
    assert [type(v) for v in value] == [int, float, float, int, float]
    assert str(value[4]) == "-0.0"


def test_duplicate_member_refused_even_when_escaped() -> None:
    assert refused('{"result":"hold","result":"authorized"}') == "wire_duplicate_member"
    assert refused('{"a":1,"\\u0061":2}') == "wire_duplicate_member"
    assert refused('{"o":{"a":1,"a":1}}') == "wire_duplicate_member"


@pytest.mark.parametrize("const", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_constants_refused(const: str) -> None:
    assert refused('{"x":' + const + "}") == "wire_nonfinite_constant"


def test_bytes_level_refusals() -> None:
    assert refused(b"\xef\xbb\xbf{}") == "wire_bom"
    assert refused(b'{"a":"\xff"}') == "wire_not_utf8"
    assert refused(b'{"a":"\xed\xa0\x80"}') == "wire_not_utf8"  # surrogate encoded as UTF-8
    with pytest.raises(wire.WireError) as info:
        wire.parse(b"x" * 11, max_bytes=10)
    assert info.value.code == "wire_too_large"


def test_lone_surrogate_escapes_refused_pairs_accepted() -> None:
    assert refused('"\\ud800"') == "wire_lone_surrogate"
    assert refused('"\\udc00"') == "wire_lone_surrogate"
    assert refused('"\\ud800\\u0041"') == "wire_lone_surrogate"
    assert wire.parse(b'"\\ud83d\\ude00"') == "\U0001f600"


def test_depth_limit() -> None:
    ok = "[" * wire.MAX_DEPTH + "]" * wire.MAX_DEPTH
    assert wire.parse(ok.encode()) is not None
    too_deep = "[" * (wire.MAX_DEPTH + 1) + "]" * (wire.MAX_DEPTH + 1)
    assert refused(too_deep) == "wire_depth"
    assert (
        refused('{"a":' * (wire.MAX_DEPTH + 1) + "1" + "}" * (wire.MAX_DEPTH + 1)) == "wire_depth"
    )


def test_trailing_data_and_empty() -> None:
    assert refused("{} {}") == "wire_trailing_data"
    assert refused("1 x") == "wire_trailing_data"
    assert refused("") == "wire_syntax"
    assert refused("   ") == "wire_syntax"


@pytest.mark.parametrize(
    "raw",
    [
        "{",
        "[1,]",
        "{,}",
        '{"a" 1}',
        '{"a":1,}',
        "{1:2}",
        "[1 2]",
        "tru",
        "01",
        "+1",
        ".5",
        "1.",
        "1e",
        "1e+",
        "-",
        "--1",
        '"abc',
        '"\\x"',
        '"\\u12"',
        '"\\u12zz"',
        '"a\nb"',
        "'a'",
        "{'a':1}",
        '{"a":1 "b":2}',
        '{"a":1',
        "[1",
        '"\\',
    ],
)
def test_syntax_errors(raw: str) -> None:
    assert refused(raw) == "wire_syntax"


def test_number_range() -> None:
    assert refused("1e999") == "wire_number_out_of_range"
    assert refused("-1e999") == "wire_number_out_of_range"
    assert refused(str(wire.MAX_INT + 1)) == "wire_number_out_of_range"
    assert wire.parse(str(wire.MAX_INT).encode()) == wire.MAX_INT
    assert refused("1" + "0" * 80) == "wire_number_out_of_range"


def test_matches_stdlib_on_valid_documents() -> None:
    docs = [
        '{"a":"\\u00e9\\n\\t\\"","b":[1,2.5,-3e-2],"c":{"d":null}}',
        "[]",
        '"x"',
        "12",
        "-0.5",
        '{"k":"\U0001f600"}',
    ]
    for doc in docs:
        assert wire.parse(doc.encode()) == json.loads(doc)


def test_python_parser_accepts_what_this_one_refuses() -> None:
    # The cases the design note names: the standard parser keeps the last duplicate and accepts NaN.
    assert json.loads('{"result":"hold","result":"authorized"}') == {"result": "authorized"}
    assert json.loads('{"x":NaN}')["x"] != json.loads('{"x":NaN}')["x"]
    assert refused('{"result":"hold","result":"authorized"}') == "wire_duplicate_member"
    assert refused('{"x":NaN}') == "wire_nonfinite_constant"
